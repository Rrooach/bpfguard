// SPDX-License-Identifier: GPL-2.0-only

//! Closed control protocol used when Allox owns the workload lifecycle and
//! this process owns only system-effect collection. START and FINISH rely on a
//! trusted private input channel; protocol v1 does not request-MAC them.
//!
//! The one-shot capability arrives on the private stdin pipe. It is never
//! persisted. HMAC response-authenticates the READY and FINALIZED transcript
//! so an accidentally reachable or confused helper cannot be accepted as the
//! recorder for another run.

use anyhow::{bail, Context, Result};
use bpf_observer_system_effects::PolicyProfile;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;
use std::io::BufRead;

pub const PROTOCOL: &str = "allox.system-effects-supervisor";
pub const PROTOCOL_VERSION: u32 = 1;
pub const MAX_PROTOCOL_MESSAGE_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub run_id: String,
    pub run_epoch: u64,
    pub cgroup_path: String,
    pub cgroup_id: u64,
    pub profile: PolicyProfile,
    pub expected_recorder_sha256: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartMessage {
    pub protocol: String,
    pub version: u32,
    #[serde(rename = "type")]
    pub message_type: String,
    pub binding: Binding,
    pub evidence_directory: String,
    pub auth_challenge: String,
    pub auth_capability: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Quiescence {
    pub status: String,
    pub basis: String,
    pub cgroup_id: u64,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Completed,
    Stopped,
    LaunchFailed,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishMessage {
    pub protocol: String,
    pub version: u32,
    #[serde(rename = "type")]
    pub message_type: String,
    pub binding: Binding,
    pub auth_challenge: String,
    pub outcome: Outcome,
    pub quiescence: Quiescence,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ReadyMessage<'a> {
    pub protocol: &'static str,
    pub version: u32,
    #[serde(rename = "type")]
    pub message_type: &'static str,
    pub binding: &'a Binding,
    pub auth_challenge: &'a str,
    pub proof: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedReadyMessage<'a> {
    protocol: &'static str,
    version: u32,
    #[serde(rename = "type")]
    message_type: &'static str,
    binding: &'a Binding,
    auth_challenge: &'a str,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedResult {
    pub evidence_status: String,
    pub verification_status: String,
    pub manifest_path: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FinalizedMessage<'a> {
    pub protocol: &'static str,
    pub version: u32,
    #[serde(rename = "type")]
    pub message_type: &'static str,
    pub binding: &'a Binding,
    pub auth_challenge: &'a str,
    pub outcome: Outcome,
    pub quiescence: &'a Quiescence,
    pub result: &'a FinalizedResult,
    pub proof: String,
}

#[derive(Debug, Serialize)]
#[serde(deny_unknown_fields)]
struct UnsignedFinalizedMessage<'a> {
    protocol: &'static str,
    version: u32,
    #[serde(rename = "type")]
    message_type: &'static str,
    binding: &'a Binding,
    auth_challenge: &'a str,
    outcome: Outcome,
    quiescence: &'a Quiescence,
    result: &'a FinalizedResult,
}

impl StartMessage {
    pub fn validate(&self) -> Result<()> {
        validate_envelope(&self.protocol, self.version, &self.message_type, "START")?;
        validate_binding(&self.binding)?;
        validate_lower_hex(&self.auth_challenge, 32, "auth_challenge")?;
        validate_lower_hex(&self.auth_capability, 32, "auth_capability")?;
        if self.evidence_directory.is_empty()
            || self.evidence_directory.contains('\0')
            || !self.evidence_directory.starts_with('/')
        {
            bail!("evidence_directory must be a nonempty absolute path without NUL");
        }
        Ok(())
    }

    pub fn ready(&self) -> Result<ReadyMessage<'_>> {
        self.validate()?;
        let unsigned = UnsignedReadyMessage {
            protocol: PROTOCOL,
            version: PROTOCOL_VERSION,
            message_type: "READY",
            binding: &self.binding,
            auth_challenge: &self.auth_challenge,
        };
        Ok(ReadyMessage {
            protocol: PROTOCOL,
            version: PROTOCOL_VERSION,
            message_type: "READY",
            binding: &self.binding,
            auth_challenge: &self.auth_challenge,
            proof: protocol_proof(&self.auth_capability, "READY", &unsigned)?,
        })
    }
}

impl FinishMessage {
    pub fn validate_against(&self, start: &StartMessage) -> Result<()> {
        validate_envelope(&self.protocol, self.version, &self.message_type, "FINISH")?;
        if self.binding != start.binding || self.auth_challenge != start.auth_challenge {
            bail!("FINISH is not bound to the accepted START message");
        }
        if self.quiescence.status != "QUIESCENT_WITHIN_CGROUP"
            || self.quiescence.basis != "CGROUP_V2_EMPTY_FROZEN_VERIFIED"
            || self.quiescence.cgroup_id != start.binding.cgroup_id
        {
            bail!("FINISH does not carry the required exact-cgroup quiescence claim");
        }
        Ok(())
    }

    pub fn finalized<'a>(
        &'a self,
        start: &'a StartMessage,
        result: &'a FinalizedResult,
    ) -> Result<FinalizedMessage<'a>> {
        self.validate_against(start)?;
        validate_finalized_result(result)?;
        let unsigned = UnsignedFinalizedMessage {
            protocol: PROTOCOL,
            version: PROTOCOL_VERSION,
            message_type: "FINALIZED",
            binding: &self.binding,
            auth_challenge: &self.auth_challenge,
            outcome: self.outcome,
            quiescence: &self.quiescence,
            result,
        };
        Ok(FinalizedMessage {
            protocol: PROTOCOL,
            version: PROTOCOL_VERSION,
            message_type: "FINALIZED",
            binding: &self.binding,
            auth_challenge: &self.auth_challenge,
            outcome: self.outcome,
            quiescence: &self.quiescence,
            result,
            proof: protocol_proof(&start.auth_capability, "FINALIZED", &unsigned)?,
        })
    }
}

pub fn read_json_line<T: DeserializeOwned>(reader: &mut impl BufRead) -> Result<T> {
    let mut encoded = Vec::new();
    let mut limited = std::io::Read::take(reader, (MAX_PROTOCOL_MESSAGE_BYTES + 1) as u64);
    let bytes = limited
        .read_until(b'\n', &mut encoded)
        .context("read effects-supervisor protocol message")?;
    if bytes == 0 {
        bail!("effects-supervisor control channel reached EOF");
    }
    if encoded.len() > MAX_PROTOCOL_MESSAGE_BYTES || encoded.last() != Some(&b'\n') {
        bail!("effects-supervisor message exceeds the 64 KiB bound or lacks a newline");
    }
    serde_json::from_slice(&encoded).context("decode effects-supervisor protocol message")
}

pub fn protocol_proof<T: Serialize>(
    capability_hex: &str,
    label: &str,
    value: &T,
) -> Result<String> {
    let key = decode_lower_hex(capability_hex, 32, "auth_capability")?;
    if !label.is_ascii() || label.is_empty() || label.contains('\0') {
        bail!("protocol proof label must be nonempty ASCII without NUL");
    }
    let value = serde_json::to_value(value).context("serialize protocol proof message")?;
    let canonical = python_canonical_json(&value)?;
    let mut transcript = Vec::with_capacity(label.len() + 1 + canonical.len());
    transcript.extend_from_slice(label.as_bytes());
    transcript.push(0);
    transcript.extend_from_slice(&canonical);
    Ok(hex_lower(&hmac_sha256(&key, &transcript)))
}

fn validate_envelope(
    protocol: &str,
    version: u32,
    message_type: &str,
    expected: &str,
) -> Result<()> {
    if protocol != PROTOCOL || version != PROTOCOL_VERSION || message_type != expected {
        bail!("invalid effects-supervisor {expected} envelope");
    }
    Ok(())
}

fn validate_binding(binding: &Binding) -> Result<()> {
    if binding.run_id.is_empty()
        || binding.run_id.len() > 128
        || !binding
            .run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || binding.run_epoch == 0
        || binding.cgroup_id == 0
    {
        bail!("effects-supervisor binding has an invalid run identity");
    }
    if binding.cgroup_path.is_empty()
        || binding.cgroup_path.contains('\0')
        || !binding.cgroup_path.starts_with('/')
    {
        bail!("effects-supervisor binding has an invalid cgroup path");
    }
    validate_lower_hex(
        &binding.expected_recorder_sha256,
        32,
        "expected_recorder_sha256",
    )
}

fn validate_finalized_result(result: &FinalizedResult) -> Result<()> {
    if result.evidence_status != "COMPLETE" || result.verification_status != "VERIFIED" {
        bail!("FINALIZED result is not complete and verified");
    }
    if result.manifest_path.is_empty()
        || result.manifest_path.contains('\0')
        || result.manifest_path.starts_with('/')
        || result
            .manifest_path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        bail!("FINALIZED manifest_path must be a canonical relative path");
    }
    validate_lower_hex(&result.manifest_sha256, 32, "manifest_sha256")
}

fn validate_lower_hex(value: &str, bytes: usize, name: &str) -> Result<()> {
    decode_lower_hex(value, bytes, name).map(|_| ())
}

fn decode_lower_hex(value: &str, bytes: usize, name: &str) -> Result<Vec<u8>> {
    if value.len() != bytes * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{name} must be exactly {bytes} bytes of lowercase hexadecimal");
    }
    let mut output = Vec::with_capacity(bytes);
    for pair in value.as_bytes().chunks_exact(2) {
        output.push((hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]));
    }
    Ok(output)
}

fn hex_nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => unreachable!("decode_lower_hex validated every nibble"),
    }
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    const BLOCK_BYTES: usize = 64;
    let mut padded = [0u8; BLOCK_BYTES];
    if key.len() > BLOCK_BYTES {
        padded[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        padded[..key.len()].copy_from_slice(key);
    }
    let mut inner_pad = [0x36u8; BLOCK_BYTES];
    let mut outer_pad = [0x5cu8; BLOCK_BYTES];
    for index in 0..BLOCK_BYTES {
        inner_pad[index] ^= padded[index];
        outer_pad[index] ^= padded[index];
    }
    let mut inner = Sha256::new();
    inner.update(inner_pad);
    inner.update(message);
    let inner = inner.finalize();
    let mut outer = Sha256::new();
    outer.update(outer_pad);
    outer.update(inner);
    outer.finalize().into()
}

fn python_canonical_json(value: &Value) -> Result<Vec<u8>> {
    let mut output = String::new();
    append_python_json(value, &mut output)?;
    Ok(output.into_bytes())
}

fn append_python_json(value: &Value, output: &mut String) -> Result<()> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(true) => output.push_str("true"),
        Value::Bool(false) => output.push_str("false"),
        Value::Number(number) => {
            if !number.is_i64() && !number.is_u64() {
                bail!("floating-point values are not allowed in the supervisor transcript");
            }
            output.push_str(&number.to_string());
        }
        Value::String(value) => append_python_string(value, output),
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                append_python_json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(values) => {
            output.push('{');
            let mut entries = values.iter().collect::<Vec<_>>();
            entries.sort_by(|left, right| left.0.cmp(right.0));
            for (index, (key, value)) in entries.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                append_python_string(key, output);
                output.push(':');
                append_python_json(value, output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

fn append_python_string(value: &str, output: &mut String) {
    output.push('"');
    for character in value.chars() {
        match character {
            '"' => output.push_str("\\\""),
            '\\' => output.push_str("\\\\"),
            '\u{08}' => output.push_str("\\b"),
            '\u{0c}' => output.push_str("\\f"),
            '\n' => output.push_str("\\n"),
            '\r' => output.push_str("\\r"),
            '\t' => output.push_str("\\t"),
            character if character <= '\u{1f}' => {
                write!(output, "\\u{:04x}", character as u32).expect("write to String")
            }
            character if character <= '\u{7e}' => output.push(character),
            character if character as u32 <= 0xffff => {
                write!(output, "\\u{:04x}", character as u32).expect("write to String")
            }
            character => {
                let scalar = character as u32 - 0x1_0000;
                let high = 0xd800 + (scalar >> 10);
                let low = 0xdc00 + (scalar & 0x3ff);
                write!(output, "\\u{high:04x}\\u{low:04x}").expect("write to String")
            }
        }
    }
    output.push('"');
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(output, "{byte:02x}").expect("write to String");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn start_json() -> String {
        format!(
            concat!(
                "{{\"protocol\":\"allox.system-effects-supervisor\",",
                "\"version\":1,\"type\":\"START\",",
                "\"binding\":{{\"run_id\":\"run1\",\"run_epoch\":7,",
                "\"cgroup_path\":\"/sys/fs/cgroup/allox/rün\",\"cgroup_id\":123,",
                "\"profile\":\"balanced\",\"expected_recorder_sha256\":\"{}\"}},",
                "\"evidence_directory\":\"/var/lib/allox/audit/run1/effects\",",
                "\"auth_challenge\":\"{}\",\"auth_capability\":\"{}\"}}\n"
            ),
            "ab".repeat(32),
            "cd".repeat(32),
            "00".repeat(32),
        )
    }

    #[test]
    fn ready_proof_matches_python_reference_including_ensure_ascii() {
        let start: StartMessage = read_json_line(&mut Cursor::new(start_json())).unwrap();
        let ready = start.ready().unwrap();
        assert_eq!(
            ready.proof,
            "481995e8e798c527c4c5946e10b8cd13304ff185f5e2bdd8ceec8a37b1107601"
        );
    }

    #[test]
    fn parser_rejects_unknown_fields_and_overlong_lines() {
        let unknown = start_json().replace(
            "\"auth_capability\"",
            "\"unexpected\":true,\"auth_capability\"",
        );
        assert!(read_json_line::<StartMessage>(&mut Cursor::new(unknown)).is_err());
        let overlong = format!("{{\"x\":\"{}\"}}\n", "a".repeat(MAX_PROTOCOL_MESSAGE_BYTES));
        assert!(read_json_line::<Value>(&mut Cursor::new(overlong)).is_err());
    }

    #[test]
    fn finish_must_echo_binding_and_exact_quiescence() {
        let start: StartMessage = read_json_line(&mut Cursor::new(start_json())).unwrap();
        let mut finish: FinishMessage = serde_json::from_value(serde_json::json!({
            "protocol": PROTOCOL,
            "version": 1,
            "type": "FINISH",
            "binding": start.binding,
            "auth_challenge": start.auth_challenge,
            "outcome": "completed",
            "quiescence": {
                "status": "QUIESCENT_WITHIN_CGROUP",
                "basis": "CGROUP_V2_EMPTY_FROZEN_VERIFIED",
                "cgroup_id": 123
            }
        }))
        .unwrap();
        assert!(finish.validate_against(&start).is_ok());
        finish.quiescence.cgroup_id = 124;
        assert!(finish.validate_against(&start).is_err());
    }

    #[test]
    fn finalized_proof_matches_python_reference() {
        let start: StartMessage = read_json_line(&mut Cursor::new(start_json())).unwrap();
        let finish: FinishMessage = serde_json::from_value(serde_json::json!({
            "protocol": PROTOCOL,
            "version": 1,
            "type": "FINISH",
            "binding": start.binding,
            "auth_challenge": start.auth_challenge,
            "outcome": "completed",
            "quiescence": {
                "status": "QUIESCENT_WITHIN_CGROUP",
                "basis": "CGROUP_V2_EMPTY_FROZEN_VERIFIED",
                "cgroup_id": 123
            }
        }))
        .unwrap();
        let result = FinalizedResult {
            evidence_status: "COMPLETE".to_owned(),
            verification_status: "VERIFIED".to_owned(),
            manifest_path: "system-effects.manifest.json".to_owned(),
            manifest_sha256: "ef".repeat(32),
        };
        let finalized = finish.finalized(&start, &result).unwrap();
        assert_eq!(
            finalized.proof,
            "b1313138d8e6900e3d133523f6eb4a936a719c5edf5bc1720a89c2588f25b8ad"
        );
    }

    #[test]
    fn finalized_result_is_closed_and_path_confined() {
        let good = FinalizedResult {
            evidence_status: "COMPLETE".to_owned(),
            verification_status: "VERIFIED".to_owned(),
            manifest_path: "system-effects.manifest.json".to_owned(),
            manifest_sha256: "ef".repeat(32),
        };
        assert!(validate_finalized_result(&good).is_ok());
        let bad = FinalizedResult {
            manifest_path: "../manifest.json".to_owned(),
            ..good
        };
        assert!(validate_finalized_result(&bad).is_err());
    }
}
