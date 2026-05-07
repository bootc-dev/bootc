use std::fmt::Display;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Helper to format a path.
#[derive(Debug)]
pub struct PathQuotedDisplay<'a> {
    path: &'a Path,
}

/// A pretty conservative check for "shell safe" characters. These
/// are basically ones which are very common in filenames or command line
/// arguments, which are the primary use case for this. There are definitely
/// characters such as '+' which are typically safe, but it's fine if
/// we're overly conservative.
///
/// For bash for example: <https://www.gnu.org/software/bash/manual/html_node/Definitions.html#index-metacharacter>
fn is_shellsafe(c: char) -> bool {
    matches!(c, '/' | '.' | '-' | '_' | ',' | '=' | ':') || c.is_alphanumeric()
}

impl<'a> Display for PathQuotedDisplay<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(s) = self.path.to_str() {
            if s.chars().all(is_shellsafe) {
                return f.write_str(s);
            }
        }
        if let Ok(r) = shlex::bytes::try_quote(self.path.as_os_str().as_bytes()) {
            let s = String::from_utf8_lossy(&r);
            return f.write_str(&s);
        }
        // Should not happen really
        Err(std::fmt::Error)
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
    use std::ffi::OsStr;

    use super::*;

    #[test]
    fn test_unquoted() {
        for v in [
            "",
            "foo",
            "/foo/bar",
            "/foo/bar/../baz",
            "/foo9/bar10",
            "--foo",
            "--virtiofs=/foo,/bar",
            "/foo:/bar",
            "--label=type=unconfined_t",
        ] {
            assert_eq!(v, format!("{}", PathQuotedDisplay::new(&v)));
        }
    }

    #[test]
    fn test_bash_metachars() {
        // https://www.gnu.org/software/bash/manual/html_node/Definitions.html#index-metacharacter
        let bash_metachars = "|&;()<>";
        for c in bash_metachars.chars() {
            assert!(!is_shellsafe(c));
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
            let q = PathQuotedDisplay::new(&v).to_string();
            assert_eq!(quoted, q.as_str());
            // Also sanity check there's exactly one token
            let token = shlex::split(&q).unwrap();
            assert_eq!(1, token.len());
            assert_eq!(v, token[0]);
        }
    }

    #[test]
    fn test_nonutf8() {
        let p = Path::new(OsStr::from_bytes(b"/foo/somenonutf8\xEE/bar"));
        assert!(p.to_str().is_none());
        let q = PathQuotedDisplay::new(&p).to_string();
        assert_eq!(q, r#"'/foo/somenonutf8�/bar'"#);
    }
}
