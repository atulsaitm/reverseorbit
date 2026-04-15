#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ErrorKind {
    BadRequest,
    NotFound,
    Timeout,
    Internal,
}

impl ErrorKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::BadRequest => "bad_request",
            Self::NotFound => "not_found",
            Self::Timeout => "timeout",
            Self::Internal => "internal",
        }
    }
}

pub(crate) fn classify_error_kind(message: &str) -> ErrorKind {
    let lower = message.to_ascii_lowercase();
    if lower.contains("missing `")
        || lower.contains("unknown graph view")
        || lower.contains("unknown tool")
        || lower.contains("action target missing")
        || lower.contains("function name missing")
    {
        return ErrorKind::BadRequest;
    }
    if lower.contains("timed out") {
        return ErrorKind::Timeout;
    }
    if lower.contains("not found") || lower.contains("snapshot artifact missing") {
        return ErrorKind::NotFound;
    }
    ErrorKind::Internal
}

#[cfg(test)]
mod tests {
    use super::{ErrorKind, classify_error_kind};

    #[test]
    fn classifies_timeout_errors() {
        assert_eq!(
            classify_error_kind("timed out after 90s while collecting xref probe"),
            ErrorKind::Timeout
        );
    }

    #[test]
    fn classifies_not_found_errors() {
        assert_eq!(
            classify_error_kind("artifact not found in index"),
            ErrorKind::NotFound
        );
    }
}
