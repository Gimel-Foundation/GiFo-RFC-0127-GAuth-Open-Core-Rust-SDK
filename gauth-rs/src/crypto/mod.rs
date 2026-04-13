// Copyright (c) 2025-2026 Gimel Foundation gGmbH i.G.
// SPDX-License-Identifier: MPL-2.0
use sha2::{Digest, Sha256};

pub fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let entries: Vec<String> = keys
                .iter()
                .map(|k| format!("{}:{}", canonical_json_string(k), canonical_json(&map[*k])))
                .collect();
            format!("{{{}}}", entries.join(","))
        }
        serde_json::Value::Array(arr) => {
            let items: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", items.join(","))
        }
        serde_json::Value::String(s) => canonical_json_string(s),
        serde_json::Value::Number(n) => n.to_string(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Null => "null".to_string(),
    }
}

fn canonical_json_string(s: &str) -> String {
    let mut result = String::with_capacity(s.len() + 2);
    result.push('"');
    for c in s.chars() {
        match c {
            '"' => result.push_str("\\\""),
            '\\' => result.push_str("\\\\"),
            '\n' => result.push_str("\\n"),
            '\r' => result.push_str("\\r"),
            '\t' => result.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                result.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => result.push(c),
        }
    }
    result.push('"');
    result
}

pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

pub fn compute_scope_checksum(scope: &crate::types::Scope) -> crate::error::Result<String> {
    let value = serde_json::to_value(scope)?;
    let canonical = canonical_json(&value);
    Ok(format!("sha256:{}", sha256_hex(canonical.as_bytes())))
}

pub fn compute_permissions_hash(
    core_verbs: &crate::types::CoreVerbs,
) -> crate::error::Result<String> {
    let value = serde_json::to_value(core_verbs)?;
    let canonical = canonical_json(&value);
    Ok(format!("sha256:{}", sha256_hex(canonical.as_bytes())))
}

pub fn compute_platform_permissions_hash(
    platform_permissions: &crate::types::PlatformPermissions,
) -> crate::error::Result<String> {
    let value = serde_json::to_value(platform_permissions)?;
    let canonical = canonical_json(&value);
    Ok(format!("sha256:{}", sha256_hex(canonical.as_bytes())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_json_sorts_keys() {
        let value: serde_json::Value = serde_json::json!({
            "z": 1,
            "a": 2,
            "m": 3
        });
        let result = canonical_json(&value);
        assert_eq!(result, r#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn test_canonical_json_nested() {
        let value: serde_json::Value = serde_json::json!({
            "b": {"d": 1, "c": 2},
            "a": [3, 2, 1]
        });
        let result = canonical_json(&value);
        assert_eq!(result, r#"{"a":[3,2,1],"b":{"c":2,"d":1}}"#);
    }

    #[test]
    fn test_sha256_hex() {
        let hash = sha256_hex(b"hello");
        assert_eq!(
            hash,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_scope_checksum_deterministic() {
        let scope = crate::types::Scope {
            governance_profile: crate::types::GovernanceProfile::Standard,
            phase: crate::types::Phase::Build,
            core_verbs: std::collections::HashMap::new(),
            active_modules: None,
            allowed_paths: None,
            denied_paths: None,
            allowed_sectors: None,
            allowed_regions: None,
            allowed_transactions: None,
            transaction_matrix: None,
            allowed_decisions: None,
            platform_permissions: None,
        };
        let c1 = compute_scope_checksum(&scope).unwrap();
        let c2 = compute_scope_checksum(&scope).unwrap();
        assert_eq!(c1, c2);
        assert!(c1.starts_with("sha256:"));
    }
}
