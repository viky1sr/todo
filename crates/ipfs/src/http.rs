//! HTTP helpers shared by the live backends.

use crate::error::IpfsError;

pub(crate) fn transport(e: reqwest::Error) -> IpfsError {
    // `without_url` keeps query strings (CIDs are harmless, but tokens might not be) out
    // of error messages.
    IpfsError::Transport(e.without_url().to_string())
}

pub(crate) fn normalize_base_url(url: &str) -> Result<String, IpfsError> {
    let parsed = reqwest::Url::parse(url)
        .map_err(|e| IpfsError::Transport(format!("invalid base URL: {e}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.query().is_some() {
        return Err(IpfsError::Transport(
            "base URL must be http(s) without a query".into(),
        ));
    }
    Ok(url.trim_end_matches('/').to_string())
}

/// Read a response body, failing as soon as it exceeds `limit` bytes.
pub(crate) async fn read_limited(
    mut resp: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, IpfsError> {
    if let Some(len) = resp.content_length()
        && len > limit as u64
    {
        return Err(IpfsError::BlockTooLarge {
            size: usize::try_from(len).unwrap_or(usize::MAX),
            limit,
        });
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(transport)? {
        if body.len() + chunk.len() > limit {
            return Err(IpfsError::BlockTooLarge {
                size: body.len() + chunk.len(),
                limit,
            });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Bound for JSON/error responses.
pub(crate) const MAX_RPC_RESPONSE: usize = 64 * 1024;

pub(crate) async fn error_message(resp: reqwest::Response) -> String {
    let body = read_limited(resp, MAX_RPC_RESPONSE)
        .await
        .unwrap_or_default();
    serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("Message").and_then(|m| m.as_str()).map(str::to_owned))
        .unwrap_or_else(|| String::from_utf8_lossy(&body).chars().take(512).collect())
}
