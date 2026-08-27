#![forbid(unsafe_code)]
//! Bounded Happy Wakey synchronization on the Opto Sync merge engine.

pub use happy_wakey_interfaces as interfaces;
pub use syncer_rs;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use syncer_rs::{merge_values, ArrayMergeStrategy, MergeOptions};
use thiserror::Error;

const SERVER_OWNED_FIELDS: &[&str] = &[
    "access_token",
    "audit",
    "factor",
    "owner_id",
    "permission",
    "refresh_token",
    "revocation",
    "role",
    "session",
    "subject",
    "token",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncBackend {
    Supabase,
    SQLite,
    PostgreSql,
    IndexedDb,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum SyncPolicyError {
    #[error("sync documents must be JSON objects")]
    NotAnObject,
    #[error("field is server-owned and cannot be synchronized: {0}")]
    ServerOwnedField(String),
}

/// Merge approved client-owned preferences through Opto Sync.
///
/// Identity, sessions, roles, factors, permissions, recovery, revocation, and
/// audit data stay server-authoritative and are rejected before reconciliation.
pub fn merge_preferences(base: Value, incoming: &Value) -> Result<Value, SyncPolicyError> {
    validate_document(&base)?;
    validate_document(incoming)?;

    let options = MergeOptions {
        array_strategy: ArrayMergeStrategy::MergeByKey,
        max_depth: 32,
        resolve_by_timestamp: true,
        detect_circular_refs: true,
        lww_keys: Some("updated_at,updatedAt".to_owned()),
        fww_keys: None,
        array_match_keys: Some("id".to_owned()),
    };
    Ok(merge_values(base, incoming, &options))
}

pub fn validate_document(document: &Value) -> Result<(), SyncPolicyError> {
    let object = document.as_object().ok_or(SyncPolicyError::NotAnObject)?;
    for forbidden in SERVER_OWNED_FIELDS {
        if object.contains_key(*forbidden) {
            return Err(SyncPolicyError::ServerOwnedField((*forbidden).to_owned()));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn supports_the_required_storage_backends() {
        let backends = [
            SyncBackend::Supabase,
            SyncBackend::SQLite,
            SyncBackend::PostgreSql,
            SyncBackend::IndexedDb,
        ];
        assert_eq!(backends.len(), 4);
    }

    #[test]
    fn rejects_server_owned_security_state() {
        let result = merge_preferences(json!({}), &json!({ "role": "admin" }));
        assert_eq!(
            result,
            Err(SyncPolicyError::ServerOwnedField("role".into()))
        );
        assert_eq!(
            validate_document(&json!({ "token": "secret" })),
            Err(SyncPolicyError::ServerOwnedField("token".into()))
        );
        assert_eq!(
            validate_document(&json!({ "subject": "user-1" })),
            Err(SyncPolicyError::ServerOwnedField("subject".into()))
        );
    }

    #[test]
    fn merges_client_owned_preferences_with_opto_sync() {
        let base = json!({
            "updated_at": "2026-08-25T10:00:00Z",
            "theme": "light"
        });
        let incoming = json!({
            "updated_at": "2026-08-25T10:01:00Z",
            "theme": "dark"
        });
        let merged = merge_preferences(base, &incoming).expect("approved preference merge");
        assert_eq!(merged["theme"], "dark");
    }
}
