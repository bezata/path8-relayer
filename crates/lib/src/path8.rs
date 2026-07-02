use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use solana_message::{compiled_instruction::CompiledInstruction, VersionedMessage};
use solana_sdk::{instruction::AccountMeta, pubkey::Pubkey};
use subtle::ConstantTimeEq;

use crate::{
    config::{Config, Path8Config},
    error::KoraError,
    transaction::VersionedTransactionResolved,
};

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Deserialize)]
struct ApprovalClaims {
    sub: String,
    sid: String,
    iid: String,
    ch: String,
    exp: i64,
    jti: String,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    typ: Option<String>,
}

pub async fn enforce_path8_approval(
    config: &Config,
    method: &str,
    approval_token: Option<&str>,
    transaction: &VersionedTransactionResolved,
) -> Result<(), KoraError> {
    if !config.path8.requires_method(method) {
        return Ok(());
    }
    let token = approval_token.ok_or_else(|| {
        KoraError::Unauthorized(format!("Path8 approval token required for {method}"))
    })?;
    let claims = verify_approval_token(&config.path8, token)?;
    let recomputed = compute_canonical_instruction_hash(transaction)?;
    if claims.ch != recomputed {
        return Err(KoraError::Unauthorized(
            "Path8 approval token content hash mismatch".to_string(),
        ));
    }
    consume_jti(&config.path8, &claims.jti, claims.exp).await?;
    Ok(())
}

fn verify_approval_token(config: &Path8Config, token: &str) -> Result<ApprovalClaims, KoraError> {
    let mut parts = token.split('.');
    let header_b64 = parts
        .next()
        .ok_or_else(|| KoraError::Unauthorized("approval token missing header".to_string()))?;
    let payload_b64 = parts
        .next()
        .ok_or_else(|| KoraError::Unauthorized("approval token missing payload".to_string()))?;
    let sig_b64 = parts
        .next()
        .ok_or_else(|| KoraError::Unauthorized("approval token missing signature".to_string()))?;
    if parts.next().is_some() {
        return Err(KoraError::Unauthorized("approval token has too many segments".to_string()));
    }

    let header_bytes = URL_SAFE_NO_PAD.decode(header_b64).map_err(|_| {
        KoraError::Unauthorized("approval token header is not base64url".to_string())
    })?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes).map_err(|_| {
        KoraError::Unauthorized("approval token header is invalid JSON".to_string())
    })?;
    if header.alg != "HS256" {
        return Err(KoraError::Unauthorized("approval token alg must be HS256".to_string()));
    }
    if let Some(typ) = &header.typ {
        if typ != "JWT" {
            return Err(KoraError::Unauthorized("approval token typ must be JWT".to_string()));
        }
    }

    let secret = std::env::var(&config.hmac_secret_env).map_err(|_| {
        KoraError::Unauthorized(format!(
            "Path8 approval secret env {} is not set",
            config.hmac_secret_env
        ))
    })?;
    let signing_input = format!("{header_b64}.{payload_b64}");
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
        .map_err(|_| KoraError::Unauthorized("Path8 approval secret is invalid".to_string()))?;
    mac.update(signing_input.as_bytes());
    let expected_sig = mac.finalize().into_bytes();
    let actual_sig = URL_SAFE_NO_PAD.decode(sig_b64).map_err(|_| {
        KoraError::Unauthorized("approval token signature is not base64url".to_string())
    })?;
    if expected_sig.as_slice().ct_eq(actual_sig.as_slice()).unwrap_u8() != 1 {
        return Err(KoraError::Unauthorized("approval token signature mismatch".to_string()));
    }

    let payload_bytes = URL_SAFE_NO_PAD.decode(payload_b64).map_err(|_| {
        KoraError::Unauthorized("approval token payload is not base64url".to_string())
    })?;
    let claims: ApprovalClaims = serde_json::from_slice(&payload_bytes).map_err(|_| {
        KoraError::Unauthorized("approval token payload is invalid JSON".to_string())
    })?;
    if claims.sub.is_empty()
        || claims.sid.is_empty()
        || claims.iid.is_empty()
        || claims.ch.len() != 64
        || claims.jti.is_empty()
    {
        return Err(KoraError::Unauthorized("approval token missing required claim".to_string()));
    }
    let now = chrono::Utc::now().timestamp();
    if claims.exp <= now {
        return Err(KoraError::Unauthorized("approval token expired".to_string()));
    }
    Ok(claims)
}

async fn consume_jti(config: &Path8Config, jti: &str, exp: i64) -> Result<(), KoraError> {
    let redis_url = config.redis_url.as_ref().ok_or_else(|| {
        KoraError::Unauthorized(
            "Path8 JTI Redis URL is required when enforcement is enabled".to_string(),
        )
    })?;
    let ttl = exp - chrono::Utc::now().timestamp();
    if ttl <= 0 {
        return Err(KoraError::Unauthorized("approval token expired".to_string()));
    }
    let client = redis::Client::open(redis_url.as_str())
        .map_err(|e| KoraError::Unauthorized(format!("Path8 JTI Redis client error: {e}")))?;
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .map_err(|e| KoraError::Unauthorized(format!("Path8 JTI Redis connection error: {e}")))?;
    let key = format!("{}:{}", config.jti_key_prefix, jti);
    let set: Option<String> = redis::cmd("SET")
        .arg(key)
        .arg("1")
        .arg("EX")
        .arg(ttl)
        .arg("NX")
        .query_async(&mut connection)
        .await
        .map_err(|e| KoraError::Unauthorized(format!("Path8 JTI Redis SETNX error: {e}")))?;
    if set.as_deref() != Some("OK") {
        return Err(KoraError::Unauthorized("approval token JTI already consumed".to_string()));
    }
    Ok(())
}

fn compute_canonical_instruction_hash(
    transaction: &VersionedTransactionResolved,
) -> Result<String, KoraError> {
    let instructions = canonical_outer_instructions(transaction)?;
    let mut h = Sha256::new();
    h.update((instructions.len() as u64).to_le_bytes());
    for ix in instructions {
        h.update(ix.program_id.to_bytes());
        h.update((ix.accounts.len() as u64).to_le_bytes());
        for account in ix.accounts {
            h.update(account.pubkey.to_bytes());
            h.update([account.is_signer as u8, account.is_writable as u8]);
        }
        h.update((ix.data.len() as u64).to_le_bytes());
        h.update(ix.data);
    }
    Ok(hex::encode(h.finalize()))
}

struct CanonicalInstruction {
    program_id: Pubkey,
    accounts: Vec<AccountMeta>,
    data: Vec<u8>,
}

fn canonical_outer_instructions(
    transaction: &VersionedTransactionResolved,
) -> Result<Vec<CanonicalInstruction>, KoraError> {
    let account_keys = &transaction.all_account_keys;
    let static_len = transaction.transaction.message.static_account_keys().len();
    let writable_loaded_count = writable_loaded_address_count(&transaction.transaction.message);
    transaction
        .transaction
        .message
        .instructions()
        .iter()
        .map(|ix| {
            canonical_instruction(
                ix,
                account_keys,
                static_len,
                writable_loaded_count,
                &transaction.transaction.message,
            )
        })
        .collect()
}

fn canonical_instruction(
    ix: &CompiledInstruction,
    account_keys: &[Pubkey],
    static_len: usize,
    writable_loaded_count: usize,
    message: &VersionedMessage,
) -> Result<CanonicalInstruction, KoraError> {
    let program_id = account_keys.get(ix.program_id_index as usize).copied().ok_or_else(|| {
        KoraError::InvalidTransaction("instruction program id index out of bounds".to_string())
    })?;
    let accounts = ix
        .accounts
        .iter()
        .map(|idx| {
            let index = *idx as usize;
            let pubkey = account_keys.get(index).copied().ok_or_else(|| {
                KoraError::InvalidTransaction("instruction account index out of bounds".to_string())
            })?;
            Ok(AccountMeta {
                pubkey,
                is_signer: is_signer(message, index),
                is_writable: is_writable(message, index, static_len, writable_loaded_count),
            })
        })
        .collect::<Result<Vec<_>, KoraError>>()?;
    Ok(CanonicalInstruction { program_id, accounts, data: ix.data.clone() })
}

fn writable_loaded_address_count(message: &VersionedMessage) -> usize {
    match message {
        VersionedMessage::Legacy(_) => 0,
        VersionedMessage::V0(v0) => {
            v0.address_table_lookups.iter().map(|l| l.writable_indexes.len()).sum()
        }
    }
}

fn is_signer(message: &VersionedMessage, index: usize) -> bool {
    index < message.header().num_required_signatures as usize
}

fn is_writable(
    message: &VersionedMessage,
    index: usize,
    static_len: usize,
    writable_loaded_count: usize,
) -> bool {
    let header = message.header();
    let required = header.num_required_signatures as usize;
    if index < static_len {
        if index < required {
            return index < required.saturating_sub(header.num_readonly_signed_accounts as usize);
        }
        return index < static_len.saturating_sub(header.num_readonly_unsigned_accounts as usize);
    }
    let loaded_index = index - static_len;
    loaded_index < writable_loaded_count
}

#[cfg(test)]
mod tests {
    use super::*;
    use solana_message::{Message, VersionedMessage};
    use solana_sdk::{instruction::Instruction, pubkey::Pubkey};

    fn hs256_token(secret: &str, payload: serde_json::Value) -> String {
        let header = serde_json::json!({"alg":"HS256","typ":"JWT"});
        let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).unwrap());
        let input = format!("{header}.{payload}");
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(input.as_bytes());
        let sig = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        format!("{input}.{sig}")
    }

    #[test]
    fn verifies_hs256_claims() {
        std::env::set_var("PATH8_TEST_SECRET", "secret");
        let exp = chrono::Utc::now().timestamp() + 60;
        let token = hs256_token(
            "secret",
            serde_json::json!({
                "sub":"u",
                "sid":"s",
                "iid":"i",
                "ch":"ab".repeat(32),
                "exp": exp,
                "jti":"j"
            }),
        );
        let config = Path8Config {
            enabled: true,
            hmac_secret_env: "PATH8_TEST_SECRET".to_string(),
            ..Default::default()
        };
        let claims = verify_approval_token(&config, &token).unwrap();
        assert_eq!(claims.ch, "ab".repeat(32));
        assert_eq!(claims.jti, "j");
    }

    #[test]
    fn rejects_bad_signature() {
        std::env::set_var("PATH8_TEST_SECRET", "secret");
        let exp = chrono::Utc::now().timestamp() + 60;
        let token = hs256_token(
            "wrong",
            serde_json::json!({
                "sub":"u",
                "sid":"s",
                "iid":"i",
                "ch":"ab".repeat(32),
                "exp": exp,
                "jti":"j"
            }),
        );
        let config = Path8Config {
            enabled: true,
            hmac_secret_env: "PATH8_TEST_SECRET".to_string(),
            ..Default::default()
        };
        assert!(matches!(verify_approval_token(&config, &token), Err(KoraError::Unauthorized(_))));
    }

    #[test]
    fn canonical_hash_ignores_blockhash() {
        let payer = Pubkey::new_unique();
        let program = Pubkey::new_unique();
        let account = Pubkey::new_unique();
        let ix = Instruction::new_with_bytes(
            program,
            &[1, 2, 3],
            vec![AccountMeta::new_readonly(account, false)],
        );
        let msg1 = VersionedMessage::Legacy(Message::new(&[ix.clone()], Some(&payer)));
        let msg2 = VersionedMessage::Legacy(Message::new(&[ix], Some(&payer)));
        let tx1 = crate::transaction::TransactionUtil::new_unsigned_versioned_transaction(msg1);
        let tx2 = crate::transaction::TransactionUtil::new_unsigned_versioned_transaction(msg2);
        let resolved1 = VersionedTransactionResolved::from_kora_built_transaction(&tx1).unwrap();
        let resolved2 = VersionedTransactionResolved::from_kora_built_transaction(&tx2).unwrap();
        assert_eq!(
            compute_canonical_instruction_hash(&resolved1).unwrap(),
            compute_canonical_instruction_hash(&resolved2).unwrap()
        );
    }
}
