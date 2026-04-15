use std::io::{BufRead, Write};

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// Tool schema sent to MCP clients on `tools/list`.
///
/// The `#[serde(rename_all = "camelCase")]` attribute is required by the MCP
/// 2024-11-05 specification: clients expect `inputSchema` (camelCase), not the
/// Rust-idiomatic `input_schema` (snake_case).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolSchema {
    pub name: String,
    pub description: String,
    pub input_schema: Value,
}

/// Read one JSON-RPC message from a buffered reader that uses the LSP/MCP
/// Content-Length framing protocol.
pub fn read_message<R: BufRead>(reader: &mut R) -> Result<Option<Value>> {
    let mut content_length = None::<usize>;
    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line)?;
        if bytes == 0 {
            return Ok(None);
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        if key.eq_ignore_ascii_case("content-length") {
            content_length = Some(value.trim().parse::<usize>()?);
        }
    }

    let length = content_length.ok_or_else(|| anyhow!("missing content-length header"))?;
    let mut buffer = vec![0_u8; length];
    reader
        .read_exact(&mut buffer)
        .context("failed to read MCP payload")?;
    let payload = String::from_utf8(buffer).context("payload is not valid utf-8")?;
    Ok(Some(serde_json::from_str(&payload)?))
}

/// Write one JSON-RPC message using the LSP/MCP Content-Length framing protocol.
pub fn write_message<W: Write>(writer: &mut W, payload: &Value) -> Result<()> {
    let serialized = serde_json::to_string(payload)?;
    write!(
        writer,
        "Content-Length: {}\r\n\r\n{}",
        serialized.len(),
        serialized
    )?;
    writer.flush()?;
    Ok(())
}

/// Wrap a result value in a JSON-RPC 2.0 success response.
pub fn success(id: Value, result: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": result,
    })
}

/// Wrap an error in a JSON-RPC 2.0 error response (for protocol-level errors).
pub fn error(id: Option<Value>, code: i64, message: &str) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": {
            "code": code,
            "message": message,
        }
    })
}

/// Build a successful tool-call result content array.
///
/// `isError: false` is included explicitly per MCP 2024-11-05 spec so that
/// clients can distinguish success from tool-level failure without guessing.
pub fn text_result(text: impl Into<String>) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": text.into()
            }
        ],
        "isError": false
    })
}

/// Build a tool-level error result.
///
/// Per MCP 2024-11-05, tool execution errors must be returned as a *successful*
/// JSON-RPC response (i.e. inside `result`, not `error`) with `isError: true`
/// in the content array.  This lets MCP hosts surface the error text to the
/// model without treating it as a protocol failure.
pub fn error_result(text: impl Into<String>) -> Value {
    json!({
        "content": [
            {
                "type": "text",
                "text": text.into()
            }
        ],
        "isError": true
    })
}
