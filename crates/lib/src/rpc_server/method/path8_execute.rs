use crate::{
    path8::verify_path8_approval,
    rpc_server::middleware_utils::default_sig_verify,
    transaction::{
        RespondAfter, TransactionUtil, VersionedTransactionOps, VersionedTransactionResolved,
    },
    usage_limit::UsageTracker,
    KoraError,
};
use serde::{Deserialize, Serialize};
use solana_client::nonblocking::rpc_client::RpcClient;
use solana_keychain::SolanaSigner;
use std::sync::Arc;
use utoipa::ToSchema;

#[cfg(not(test))]
use crate::state::{get_config, select_request_signer_with_signer_key};

#[cfg(test)]
use crate::state::select_request_signer_with_signer_key;
#[cfg(test)]
use crate::tests::config_mock::mock_state::get_config;

#[derive(Debug, Deserialize, ToSchema)]
pub struct Path8ExecuteRequest {
    /// Base64-encoded Solana transaction signed by the user/delegated authority.
    pub transaction: String,
    /// One-shot approval JWT minted by Path8 for the transaction's canonical content hash.
    pub approval_token: String,
    /// Optional signer signer_key to ensure consistency across related RPC calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signer_key: Option<String>,
    /// Whether to verify signatures during simulation (defaults to false).
    #[serde(default = "default_sig_verify")]
    pub sig_verify: bool,
    /// Optional user ID for usage tracking (required when pricing is free and usage tracking is enabled).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct Path8ExecuteResponse {
    pub signed_transaction: String,
    /// Public key of the relayer signer used for co-signing/paymaster.
    pub signer_pubkey: String,
    /// Transaction signature.
    pub signature: String,
}

pub async fn path8_execute(
    rpc_client: &Arc<RpcClient>,
    request: Path8ExecuteRequest,
) -> Result<Path8ExecuteResponse, KoraError> {
    let transaction = TransactionUtil::decode_b64_transaction(&request.transaction)?;

    let config = &get_config()?;

    let signer = select_request_signer_with_signer_key(request.signer_key.as_deref())?;
    let fee_payer = signer.pubkey();

    let sig_verify = request.sig_verify || config.kora.force_sig_verify;
    let mut resolved_transaction = VersionedTransactionResolved::from_transaction(
        &transaction,
        config,
        rpc_client,
        sig_verify,
    )
    .await?;

    // Verify + bind the approval; defer burning the single-use JTI until after
    // the retryable usage-limit check (see `verify_path8_approval`).
    let approval_guard = verify_path8_approval(
        config,
        "path8_execute",
        Some(request.approval_token.as_str()),
        &resolved_transaction,
    )
    .await?;

    UsageTracker::check_transaction_usage_limit(
        config,
        &mut resolved_transaction,
        request.user_id.as_deref(),
        &fee_payer,
        rpc_client,
    )
    .await?;

    // Burn the JTI immediately before the irreversible network send.
    approval_guard.consume(config).await?;

    let (signature, signed_transaction) = resolved_transaction
        .sign_and_send_transaction(config, &signer, rpc_client, RespondAfter::Confirmed)
        .await?;

    Ok(Path8ExecuteResponse {
        signed_transaction,
        signer_pubkey: signer.pubkey().to_string(),
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{
        common::{setup_or_get_test_signer, setup_or_get_test_usage_limiter, RpcMockBuilder},
        config_mock::ConfigMockBuilder,
    };

    #[tokio::test]
    async fn test_path8_execute_decode_error() {
        let _m = ConfigMockBuilder::new().build_and_setup();
        let _ = setup_or_get_test_signer();
        let _ = setup_or_get_test_usage_limiter().await;
        let rpc_client = Arc::new(RpcMockBuilder::new().build());

        let request = Path8ExecuteRequest {
            transaction: "invalid_base64!@#$".to_string(),
            approval_token: "token".to_string(),
            signer_key: None,
            sig_verify: true,
            user_id: None,
        };

        let result = path8_execute(&rpc_client, request).await;
        assert!(result.is_err(), "Should fail with decode error");
    }
}
