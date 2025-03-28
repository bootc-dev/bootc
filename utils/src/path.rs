use std::ffi::OsStr;
use std::fmt::Display;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Helper to format a path.
#[derive(Debug)]
pub struct PathQuotedDisplay<'a> {
    path: &'a Path,
}

impl<'a> Display for PathQuotedDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(s) = self.path.to_str() {
            if s.chars()
                .all(|c| matches!(c, '/' | '.') || c.is_alphanumeric())
            {
                return f.write_str(s);
            }
        }
        if let Ok(r) = shlex::bytes::try_quote(self.path.as_os_str().as_bytes()) {
            if let Ok(s) = std::str::from_utf8(&r) {
                return f.write_str(s);
            } else {
                let r = OsStr::from_bytes(&r);
                return write!(f, "{r:?}");
            }
        }
        // Should not happen really
        return Err(std::fmt::Error);
    }
}

impl<'a> PathQuotedDisplay<'a> {
    /// Given a path, quote it in a way that it would be parsed by a default
    /// POSIX shell. If the path is UTF-8 with no spaces or shell meta-characters,
    /// it will be exactly the same as the input.
    pub fn new<P: AsRef<Path>>(path: &'a P) -> PathQuotedDisplay<'a> {
        PathQuotedDisplay {
            path: path.as_ref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unquoted() {
        for v in ["", "foo", "/foo/bar", "/foo/bar/../baz", "/foo9/bar10"] {
            assert_eq!(v, format!("{}", PathQuotedDisplay::new(&v)));
        }
    }

    #[test]
    fn test_quoted() {
        let cases = [
            (" ", "' '"),
            ("/some/path with spaces/", "'/some/path with spaces/'"),
            ("/foo/!/bar&", "'/foo/!/bar&'"),
            (r#"/path/"withquotes'"#, r#""/path/\"withquotes'""#),
        ];
        for (v, quoted) in cases {
            assert_eq!(quoted, format!("{}", PathQuotedDisplay::new(&v)));
        }
    }
}
