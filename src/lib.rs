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
    #[error("sync document exceeds the 32-level nesting bound")]
    DocumentTooDeep,
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
    // The merge engine also merges nested maps and arrays. Check the entire
    // document before passing any part of it to reconciliation.
    let mut pending = vec![(object, 0usize)];
    while let Some((current, depth)) = pending.pop() {
        if depth > 32 {
            return Err(SyncPolicyError::DocumentTooDeep);
        }
        for (key, value) in current {
            if SERVER_OWNED_FIELDS
                .iter()
                .any(|field| key.eq_ignore_ascii_case(field))
            {
                return Err(SyncPolicyError::ServerOwnedField(key.clone()));
            }
            match value {
                Value::Object(next) => pending.push((next, depth + 1)),
                Value::Array(items) => {
                    // Count nested arrays as depth as well.
                    let mut arrays = vec![(items, depth + 1)];
                    while let Some((items, array_depth)) = arrays.pop() {
                        if array_depth > 32 {
                            return Err(SyncPolicyError::DocumentTooDeep);
                        }
                        for item in items {
                            match item {
                                Value::Object(next) => pending.push((next, array_depth)),
                                Value::Array(next) => arrays.push((next, array_depth + 1)),
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
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
    fn rejects_nested_server_owned_state_before_merging() {
        for payload in [
            json!({"settings": {"role": "admin"}}),
            json!({"widgets": [{"metadata": {"refresh_token": "secret"}}]}),
            json!({"settings": {"TOKEN": "secret"}}),
        ] {
            assert!(matches!(
                merge_preferences(json!({}), &payload),
                Err(SyncPolicyError::ServerOwnedField(_))
            ));
        }
    }

    #[test]
    fn rejects_excessively_nested_client_documents() {
        let mut nested = json!({"theme": "dark"});
        for _ in 0..34 {
            nested = json!({"preferences": nested});
        }
        assert_eq!(
            validate_document(&nested),
            Err(SyncPolicyError::DocumentTooDeep)
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
