//! Kernel command line parsing utilities.
//!
//! This module provides functionality for parsing and working with kernel command line
//! arguments, supporting both key-only switches and key-value pairs with proper quote handling.

use std::borrow::Cow;

use anyhow::Result;

/// This is used by dracut.
pub const INITRD_ARG_PREFIX: &str = "rd.";
/// The kernel argument for configuring the rootfs flags.
pub const ROOTFLAGS: &str = "rootflags";

/// A parsed kernel command line.
///
/// Wraps the raw command line bytes and provides methods for parsing and iterating
/// over individual parameters. Uses copy-on-write semantics to avoid unnecessary
/// allocations when working with borrowed data.
#[derive(Debug)]
pub struct Cmdline<'a>(Cow<'a, [u8]>);

impl<'a, T: AsRef<[u8]> + ?Sized> From<&'a T> for Cmdline<'a> {
    /// Creates a new `Cmdline` from any type that can be referenced as bytes.
    ///
    /// Uses borrowed data when possible to avoid unnecessary allocations.
    fn from(input: &'a T) -> Self {
        Self(Cow::Borrowed(input.as_ref()))
    }
}

impl<'a> Cmdline<'a> {
    /// Reads the kernel command line from `/proc/cmdline`.
    ///
    /// Returns an error if the file cannot be read or if there are I/O issues.
    pub fn from_proc() -> Result<Self> {
        Ok(Self(Cow::Owned(std::fs::read("/proc/cmdline")?)))
    }

    /// Returns an iterator over all parameters in the command line.
    ///
    /// Properly handles quoted values containing whitespace and splits on
    /// unquoted whitespace characters. Parameters are parsed as either
    /// key-only switches or key=value pairs.
    pub fn iter(&'a self) -> impl Iterator<Item = Parameter<'a>> + 'a {
        let mut in_quotes = false;

        self.0
            .split(move |c| {
                if *c == b'"' {
                    in_quotes = !in_quotes;
                }
                !in_quotes && c.is_ascii_whitespace()
            })
            .map(Parameter::from)
    }

    /// Locate a kernel argument with the given key name.
    ///
    /// Returns the first parameter matching the given key, or `None` if not found.
    /// Key comparison treats dashes and underscores as equivalent.
    pub fn find(&'a self, key: impl AsRef<[u8]>) -> Option<Parameter<'a>> {
        let key = ParameterKey(key.as_ref());
        self.iter().find(|p| p.key == key)
    }

    /// Locate a kernel argument with the given key name that must be UTF-8.
    ///
    /// Otherwise the same as [`Self::find`].
    pub fn find_str(&'a self, key: &str) -> Option<ParameterStr<'a>> {
        let key = ParameterKeyStr(key);
        self.iter()
            .filter_map(|p| p.to_str())
            .find(move |p| p.key == key)
    }

    /// Find all kernel arguments starting with the given prefix which must be UTF-8.
    /// Non-UTF8 values are ignored.
    ///
    /// This is a variant of [`Self::find`].
    pub fn find_all_starting_with_str(
        &'a self,
        prefix: &'a str,
    ) -> impl Iterator<Item = ParameterStr<'a>> + 'a {
        self.iter()
            .filter_map(|p| p.to_str())
            .filter(move |p| p.key.0.starts_with(prefix))
    }

    /// Locate the value of the kernel argument with the given key name.
    ///
    /// Returns the first value matching the given key, or `None` if not found.
    /// Key comparison treats dashes and underscores as equivalent.
    pub fn value_of(&'a self, key: impl AsRef<[u8]>) -> Option<&'a [u8]> {
        self.find(key).and_then(|p| p.value)
    }

    /// Locate the UTF-8 value of the kernel argument with the given key name.
    ///
    /// Returns the first value matching the given key, or `None` if not found.
    /// Key comparison treats dashes and underscores as equivalent.
    pub fn value_of_utf8(&'a self, key: &str) -> Result<Option<&'a str>, std::str::Utf8Error> {
        self.value_of(key).map(std::str::from_utf8).transpose()
    }

    /// Find the value of the kernel argument with the provided name, which must be present.
    ///
    /// Otherwise the same as [`Self::value_of`].
    #[cfg(test)]
    pub fn require_value_of(&'a self, key: impl AsRef<[u8]>) -> Result<&'a [u8]> {
        let key = key.as_ref();
        self.value_of(key).ok_or_else(|| {
            let key = String::from_utf8_lossy(key);
            anyhow::anyhow!("Failed to find kernel argument '{key}'")
        })
    }

    /// Find the value of the kernel argument with the provided name, which must be present.
    ///
    /// Otherwise the same as [`Self::value_of`].
    #[cfg(test)]
    pub fn require_value_of_utf8(&'a self, key: &str) -> Result<&'a str> {
        self.value_of_utf8(key)?
            .ok_or_else(|| anyhow::anyhow!("Failed to find kernel argument '{key}'"))
    }
}

/// A single kernel command line parameter key
///
/// Handles quoted values and treats dashes and underscores in keys as equivalent.
#[derive(Debug, Eq)]
pub struct ParameterKey<'a>(&'a [u8]);

impl<'a> std::ops::Deref for ParameterKey<'a> {
    type Target = [u8];

    fn deref(&self) -> &'a Self::Target {
        self.0
    }
}

impl<'a> From<&'a [u8]> for ParameterKey<'a> {
    fn from(value: &'a [u8]) -> Self {
        Self(value)
    }
}

/// A single kernel command line parameter key that is known to be UTF-8.
///
/// Otherwise the same as [`ParameterKey`].
#[derive(Debug, Eq)]
pub struct ParameterKeyStr<'a>(&'a str);

impl<'a> From<&'a str> for ParameterKeyStr<'a> {
    fn from(value: &'a str) -> Self {
        Self(value)
    }
}

/// A single kernel command line parameter.
#[derive(Debug, Eq)]
pub struct Parameter<'a> {
    /// The full original value
    pub parameter: &'a [u8],
    /// The parameter key as raw bytes
    pub key: ParameterKey<'a>,
    /// The parameter value as raw bytes, if present
    pub value: Option<&'a [u8]>,
}

/// A single kernel command line parameter.
#[derive(Debug, PartialEq, Eq)]
pub struct ParameterStr<'a> {
    /// The original value
    pub parameter: &'a str,
    /// The parameter key
    pub key: ParameterKeyStr<'a>,
    /// The parameter value, if present
    pub value: Option<&'a str>,
}

impl<'a> Parameter<'a> {
    /// Convert this parameter to a UTF-8 string parameter, if possible.
    ///
    /// Returns `None` if the parameter contains invalid UTF-8.
    pub fn to_str(&self) -> Option<ParameterStr<'a>> {
        let Ok(parameter) = std::str::from_utf8(self.parameter) else {
            return None;
        };
        Some(ParameterStr::from(parameter))
    }
}

impl<'a> AsRef<str> for ParameterStr<'a> {
    fn as_ref(&self) -> &str {
        self.parameter
    }
}

impl<'a, T: AsRef<[u8]> + ?Sized> From<&'a T> for Parameter<'a> {
    /// Parses a parameter from raw bytes.
    ///
    /// Splits on the first `=` character to separate key and value.
    /// Strips only the outermost pair of double quotes from values.
    /// If no `=` is found, treats the entire input as a key-only parameter.
    fn from(input: &'a T) -> Self {
        let input = input.as_ref();
        let equals = input.iter().position(|b| *b == b'=');

        match equals {
            None => Self {
                parameter: input,
                key: ParameterKey(input),
                value: None,
            },
            Some(i) => {
                let (key, mut value) = input.split_at(i);
                let key = ParameterKey(key);

                // skip `=`, we know it's the first byte because we
                // found it above
                value = &value[1..];

                // *Only* the first and last double quotes are stripped
                value = value
                    .strip_prefix(b"\"")
                    .unwrap_or(value)
                    .strip_suffix(b"\"")
                    .unwrap_or(value);

                Self {
                    parameter: input,
                    key,
                    value: Some(value),
                }
            }
        }
    }
}

impl PartialEq for ParameterKey<'_> {
    /// Compares two parameter keys for equality.
    ///
    /// Keys are compared with dashes and underscores treated as equivalent.
    /// This comparison is case-sensitive.
    fn eq(&self, other: &Self) -> bool {
        let dedashed = |&c: &u8| {
            if c == b'-' {
                b'_'
            } else {
                c
            }
        };

        // We can't just zip() because leading substrings will match
        //
        // For example, "foo" == "foobar" since the zipped iterator
        // only compares the first three chars.
        let our_iter = self.0.iter().map(dedashed);
        let other_iter = other.0.iter().map(dedashed);
        our_iter.eq(other_iter)
    }
}

impl<'a> From<&'a str> for ParameterStr<'a> {
    fn from(parameter: &'a str) -> Self {
        let (key, value) = if let Some((key, value)) = parameter.split_once('=') {
            let value = value
                .strip_prefix('"')
                .unwrap_or(value)
                .strip_suffix('"')
                .unwrap_or(value);
            (key, Some(value))
        } else {
            (parameter, None)
        };
        let key = ParameterKeyStr(key);
        ParameterStr {
            parameter,
            key,
            value,
        }
    }
}

impl<'a> PartialEq for Parameter<'a> {
    fn eq(&self, other: &Self) -> bool {
        // Note we don't compare parameter because we want hyphen-dash insensitivity for the key
        self.key == other.key && self.value == other.value
    }
}

impl<'a> PartialEq for ParameterKeyStr<'a> {
    fn eq(&self, other: &Self) -> bool {
        ParameterKey(self.0.as_bytes()) == ParameterKey(other.0.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parameter_simple() {
        let switch = Parameter::from("foo");
        assert_eq!(switch.key.0, b"foo");
        assert_eq!(switch.value, None);

        let kv = Parameter::from("bar=baz");
        assert_eq!(kv.key.0, b"bar");
        assert_eq!(kv.value, Some(b"baz".as_slice()));
    }

    #[test]
    fn test_parameter_quoted() {
        let p = Parameter::from("foo=\"quoted value\"");
        assert_eq!(p.value, Some(b"quoted value".as_slice()));
    }

    #[test]
    fn test_parameter_pathological() {
        // valid things that certified insane people would do

        // quotes don't get removed from keys
        let p = Parameter::from("\"\"\"");
        assert_eq!(p.key.0, b"\"\"\"");

        // quotes only get stripped from the absolute ends of values
        let p = Parameter::from("foo=\"internal \" quotes \" are ok\"");
        assert_eq!(p.value, Some(b"internal \" quotes \" are ok".as_slice()));

        // non-UTF8 things are in fact valid
        let non_utf8_byte = b"\xff";
        #[allow(invalid_from_utf8)]
        let failed_conversion = std::str::from_utf8(non_utf8_byte);
        assert!(failed_conversion.is_err());
        let mut p = b"foo=".to_vec();
        p.push(non_utf8_byte[0]);
        let p = Parameter::from(&p);
        assert_eq!(p.value, Some(non_utf8_byte.as_slice()));
    }

    #[test]
    fn test_parameter_equality() {
        // substrings are not equal
        let foo = Parameter::from("foo");
        let bar = Parameter::from("foobar");
        assert_ne!(foo, bar);
        assert_ne!(bar, foo);

        // dashes and underscores are treated equally
        let dashes = Parameter::from("a-delimited-param");
        let underscores = Parameter::from("a_delimited_param");
        assert_eq!(dashes, underscores);

        // same key, same values is equal
        let dashes = Parameter::from("a-delimited-param=same_values");
        let underscores = Parameter::from("a_delimited_param=same_values");
        assert_eq!(dashes, underscores);

        // same key, different values is not equal
        let dashes = Parameter::from("a-delimited-param=different_values");
        let underscores = Parameter::from("a_delimited_param=DiFfErEnT_valUEZ");
        assert_ne!(dashes, underscores);

        // mixed variants are never equal
        let switch = Parameter::from("same_key");
        let keyvalue = Parameter::from("same_key=but_with_a_value");
        assert_ne!(switch, keyvalue);
    }

    #[test]
    fn test_kargs_simple() {
        // example taken lovingly from:
        // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/params.c?id=89748acdf226fd1a8775ff6fa2703f8412b286c8#n160
        let kargs = Cmdline::from(b"foo=bar,bar2 baz=fuz wiz".as_slice());
        let mut iter = kargs.iter();

        assert_eq!(iter.next(), Some(Parameter::from(b"foo=bar,bar2")));
        assert_eq!(iter.next(), Some(Parameter::from(b"baz=fuz")));
        assert_eq!(iter.next(), Some(Parameter::from(b"wiz")));
        assert_eq!(iter.next(), None);

        // Test the find API
        assert_eq!(kargs.find("foo").unwrap().value.unwrap(), b"bar,bar2");
        assert!(kargs.find("nothing").is_none());
    }

    #[test]
    fn test_kargs_from_proc() {
        let kargs = Cmdline::from_proc().unwrap();

        // Not really a good way to test this other than assume
        // there's at least one argument in /proc/cmdline wherever the
        // tests are running
        assert!(kargs.iter().count() > 0);
    }

    #[test]
    fn test_kargs_find_dash_hyphen() {
        let kargs = Cmdline::from(b"a-b=1 a_b=2".as_slice());
        // find should find the first one, which is a-b=1
        let p = kargs.find("a_b").unwrap();
        assert_eq!(p.key.0, b"a-b");
        assert_eq!(p.value.unwrap(), b"1");
        let p = kargs.find("a-b").unwrap();
        assert_eq!(p.key.0, b"a-b");
        assert_eq!(p.value.unwrap(), b"1");

        let kargs = Cmdline::from(b"a_b=2 a-b=1".as_slice());
        // find should find the first one, which is a_b=2
        let p = kargs.find("a_b").unwrap();
        assert_eq!(p.key.0, b"a_b");
        assert_eq!(p.value.unwrap(), b"2");
        let p = kargs.find("a-b").unwrap();
        assert_eq!(p.key.0, b"a_b");
        assert_eq!(p.value.unwrap(), b"2");
    }

    #[test]
    fn test_value_of() {
        let kargs = Cmdline::from(b"foo=bar baz=qux switch".as_slice());

        // Test existing key with value
        assert_eq!(kargs.value_of("foo"), Some(b"bar".as_slice()));
        assert_eq!(kargs.value_of("baz"), Some(b"qux".as_slice()));

        // Test key without value
        assert_eq!(kargs.value_of("switch"), None);

        // Test non-existent key
        assert_eq!(kargs.value_of("missing"), None);

        // Test dash/underscore equivalence
        let kargs = Cmdline::from(b"dash-key=value1 under_key=value2".as_slice());
        assert_eq!(kargs.value_of("dash_key"), Some(b"value1".as_slice()));
        assert_eq!(kargs.value_of("under-key"), Some(b"value2".as_slice()));
    }

    #[test]
    fn test_value_of_utf8() {
        let kargs = Cmdline::from(b"foo=bar baz=qux switch".as_slice());

        // Test existing key with UTF-8 value
        assert_eq!(kargs.value_of_utf8("foo").unwrap(), Some("bar"));
        assert_eq!(kargs.value_of_utf8("baz").unwrap(), Some("qux"));

        // Test key without value
        assert_eq!(kargs.value_of_utf8("switch").unwrap(), None);

        // Test non-existent key
        assert_eq!(kargs.value_of_utf8("missing").unwrap(), None);

        // Test dash/underscore equivalence
        let kargs = Cmdline::from(b"dash-key=value1 under_key=value2".as_slice());
        assert_eq!(kargs.value_of_utf8("dash_key").unwrap(), Some("value1"));
        assert_eq!(kargs.value_of_utf8("under-key").unwrap(), Some("value2"));

        // Test invalid UTF-8
        let mut invalid_utf8 = b"invalid=".to_vec();
        invalid_utf8.push(0xff);
        let kargs = Cmdline::from(&invalid_utf8);
        assert!(kargs.value_of_utf8("invalid").is_err());
    }

    #[test]
    fn test_require_value_of() {
        let kargs = Cmdline::from(b"foo=bar baz=qux switch".as_slice());

        // Test existing key with value
        assert_eq!(kargs.require_value_of("foo").unwrap(), b"bar");
        assert_eq!(kargs.require_value_of("baz").unwrap(), b"qux");

        // Test key without value should fail
        let err = kargs.require_value_of("switch").unwrap_err();
        assert!(err
            .to_string()
            .contains("Failed to find kernel argument 'switch'"));

        // Test non-existent key should fail
        let err = kargs.require_value_of("missing").unwrap_err();
        assert!(err
            .to_string()
            .contains("Failed to find kernel argument 'missing'"));

        // Test dash/underscore equivalence
        let kargs = Cmdline::from(b"dash-key=value1 under_key=value2".as_slice());
        assert_eq!(kargs.require_value_of("dash_key").unwrap(), b"value1");
        assert_eq!(kargs.require_value_of("under-key").unwrap(), b"value2");
    }

    #[test]
    fn test_require_value_of_utf8() {
        let kargs = Cmdline::from(b"foo=bar baz=qux switch".as_slice());

        // Test existing key with UTF-8 value
        assert_eq!(kargs.require_value_of_utf8("foo").unwrap(), "bar");
        assert_eq!(kargs.require_value_of_utf8("baz").unwrap(), "qux");

        // Test key without value should fail
        let err = kargs.require_value_of_utf8("switch").unwrap_err();
        assert!(err
            .to_string()
            .contains("Failed to find kernel argument 'switch'"));

        // Test non-existent key should fail
        let err = kargs.require_value_of_utf8("missing").unwrap_err();
        assert!(err
            .to_string()
            .contains("Failed to find kernel argument 'missing'"));

        // Test dash/underscore equivalence
        let kargs = Cmdline::from(b"dash-key=value1 under_key=value2".as_slice());
        assert_eq!(kargs.require_value_of_utf8("dash_key").unwrap(), "value1");
        assert_eq!(kargs.require_value_of_utf8("under-key").unwrap(), "value2");

        // Test invalid UTF-8 should fail
        let mut invalid_utf8 = b"invalid=".to_vec();
        invalid_utf8.push(0xff);
        let kargs = Cmdline::from(&invalid_utf8);
        assert!(kargs.require_value_of_utf8("invalid").is_err());
    }

    #[test]
    fn test_find_str() {
        let kargs = Cmdline::from(b"foo=bar baz=qux switch rd.break".as_slice());
        let p = kargs.find_str("foo").unwrap();
        assert_eq!(p, ParameterStr::from("foo=bar"));
        assert_eq!(p.as_ref(), "foo=bar");
        let p = kargs.find_str("rd.break").unwrap();
        assert_eq!(p, ParameterStr::from("rd.break"));
        assert!(kargs.find_str("missing").is_none());
    }

    #[test]
    fn test_find_all_str() {
        let kargs =
            Cmdline::from(b"foo=bar rd.foo=a rd.bar=b rd.baz rd.qux=c notrd.val=d".as_slice());
        let mut rd_args: Vec<_> = kargs.find_all_starting_with_str("rd.").collect();
        rd_args.sort_by(|a, b| a.key.0.cmp(b.key.0));
        assert_eq!(rd_args.len(), 4);
        assert_eq!(rd_args[0], ParameterStr::from("rd.bar=b"));
        assert_eq!(rd_args[1], ParameterStr::from("rd.baz"));
        assert_eq!(rd_args[2], ParameterStr::from("rd.foo=a"));
        assert_eq!(rd_args[3], ParameterStr::from("rd.qux=c"));
    }

    #[test]
    fn test_param_to_str() {
        let p = Parameter::from("foo=bar");
        let p_str = p.to_str().unwrap();
        assert_eq!(p_str, ParameterStr::from("foo=bar"));
        let non_utf8_byte = b"\xff";
        let mut p_u8 = b"foo=".to_vec();
        p_u8.push(non_utf8_byte[0]);
        let p = Parameter::from(&p_u8);
        assert!(p.to_str().is_none());
    }

    #[test]
    fn test_param_key_str_eq() {
        let k1 = ParameterKeyStr("a-b");
        let k2 = ParameterKeyStr("a_b");
        assert_eq!(k1, k2);
        let k1 = ParameterKeyStr("a-b");
        let k2 = ParameterKeyStr("a-c");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_kargs_non_utf8() {
        let non_utf8_val = b"an_invalid_key=\xff";
        let mut kargs_bytes = b"foo=bar ".to_vec();
        kargs_bytes.extend_from_slice(non_utf8_val);
        kargs_bytes.extend_from_slice(b" baz=qux");
        let kargs = Cmdline::from(kargs_bytes.as_slice());

        // We should be able to find the valid kargs
        assert_eq!(kargs.find_str("foo").unwrap().value, Some("bar"));
        assert_eq!(kargs.find_str("baz").unwrap().value, Some("qux"));

        // But we should not find the invalid one via find_str
        assert!(kargs.find("an_invalid_key").unwrap().to_str().is_none());

        // And even using the raw find, trying to convert it to_str will fail.
        let raw_param = kargs.find("an_invalid_key").unwrap();
        assert_eq!(raw_param.value.unwrap(), b"\xff");
    }
}
