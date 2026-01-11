//! UTF-8-based kernel command line parsing utilities.
//!
//! This module provides functionality for parsing and working with kernel command line
//! arguments, supporting both key-only switches and key-value pairs with proper quote handling.

use std::ops::Deref;

use crate::{Action, bytes};

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A parsed UTF-8 kernel command line.
///
/// Wraps the raw command line bytes and provides methods for parsing and iterating
/// over individual parameters. Uses copy-on-write semantics to avoid unnecessary
/// allocations when working with borrowed data.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cmdline<'a>(bytes::Cmdline<'a>);

/// An owned `Cmdline`.  Alias for `Cmdline<'static>`.
pub type CmdlineOwned = Cmdline<'static>;

impl<'a, T: AsRef<str> + ?Sized> From<&'a T> for Cmdline<'a> {
    /// Creates a new `Cmdline` from any type that can be referenced as `str`.
    ///
    /// Uses borrowed data when possible to avoid unnecessary allocations.
    fn from(input: &'a T) -> Self {
        Self(bytes::Cmdline::from(input.as_ref().as_bytes()))
    }
}

impl From<String> for CmdlineOwned {
    /// Creates a new `Cmdline` from a `String`.
    ///
    /// Takes ownership of input and maintains it for internal owned data.
    fn from(input: String) -> Self {
        Self(bytes::Cmdline::from(input.into_bytes()))
    }
}

/// An iterator over UTF-8 kernel command line parameters.
///
/// This is created by the `iter` method on `CmdlineUTF8`.
#[derive(Debug)]
pub struct CmdlineIter<'a>(bytes::CmdlineIter<'a>);

impl<'a> Iterator for CmdlineIter<'a> {
    type Item = Parameter<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(Parameter::from_bytes)
    }
}

/// An iterator over UTF-8 kernel command line parameters as string slices.
///
/// This is created by the `iter_str` method on `Cmdline`.
#[derive(Debug)]
pub struct CmdlineIterStr<'a>(bytes::CmdlineIterBytes<'a>);

impl<'a> Iterator for CmdlineIterStr<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        // Get the next byte slice from the underlying iterator
        let bytes = self.0.next()?;

        // Convert to UTF-8 string slice
        // SAFETY: We know this is valid UTF-8 since the Cmdline was constructed from valid UTF-8
        Some(str::from_utf8(bytes).expect("Parameter bytes come from valid UTF-8 cmdline"))
    }
}

impl<'a> Cmdline<'a> {
    /// Creates a new empty owned `Cmdline`.
    ///
    /// This is equivalent to `Cmdline::default()` but makes ownership explicit.
    pub fn new() -> CmdlineOwned {
        Cmdline::default()
    }

    /// Reads the kernel command line from `/proc/cmdline`.
    ///
    /// Returns an error if:
    ///   - The file cannot be read
    ///   - There are I/O issues
    ///   - The cmdline from proc is not valid UTF-8
    pub fn from_proc() -> Result<Self> {
        let cmdline = std::fs::read("/proc/cmdline")?;

        // SAFETY: validate the value from proc is valid UTF-8.  We
        // don't need to save this, but checking now will ensure we
        // can safely convert from the underlying bytes back to UTF-8
        // later.
        str::from_utf8(&cmdline)?;

        Ok(Self(bytes::Cmdline::from(cmdline)))
    }

    /// Returns an iterator over all parameters in the command line.
    ///
    /// Properly handles quoted values containing whitespace and splits on
    /// unquoted whitespace characters. Parameters are parsed as either
    /// key-only switches or key=value pairs.
    pub fn iter(&'a self) -> CmdlineIter<'a> {
        CmdlineIter(self.0.iter())
    }

    /// Returns an iterator over all parameters in the command line as string slices.
    ///
    /// This is similar to `iter()` but yields `&str` directly instead of `Parameter`,
    /// which can be more convenient when you just need the string representation.
    pub fn iter_str(&self) -> CmdlineIterStr<'_> {
        CmdlineIterStr(self.0.iter_bytes())
    }

    /// Locate a kernel argument with the given key name.
    ///
    /// Returns the first parameter matching the given key, or `None` if not found.
    /// Key comparison treats dashes and underscores as equivalent.
    pub fn find<T: AsRef<str> + ?Sized>(&'a self, key: &T) -> Option<Parameter<'a>> {
        let key = ParameterKey::from(key.as_ref());
        self.iter().find(|p| p.key() == key)
    }

    /// Find all kernel arguments starting with the given UTF-8 prefix.
    ///
    /// This is a variant of [`Self::find`].
    pub fn find_all_starting_with<T: AsRef<str> + ?Sized>(
        &'a self,
        prefix: &'a T,
    ) -> impl Iterator<Item = Parameter<'a>> + 'a {
        self.iter()
            .filter(move |p| p.key().starts_with(prefix.as_ref()))
    }

    /// Locate the value of the kernel argument with the given key name.
    ///
    /// Returns the first value matching the given key, or `None` if not found.
    /// Key comparison treats dashes and underscores as equivalent.
    pub fn value_of<T: AsRef<str> + ?Sized>(&'a self, key: &T) -> Option<&'a str> {
        self.0.value_of(key.as_ref().as_bytes()).map(|v| {
            // SAFETY: We know this is valid UTF-8 since we only
            // construct the underlying `bytes` from valid UTF-8
            str::from_utf8(v).expect("We only construct the underlying bytes from valid UTF-8")
        })
    }

    /// Find the value of the kernel argument with the provided name, which must be present.
    ///
    /// Otherwise the same as [`Self::value_of`].
    pub fn require_value_of<T: AsRef<str> + ?Sized>(&'a self, key: &T) -> Result<&'a str> {
        let key = key.as_ref();
        self.value_of(key)
            .ok_or_else(|| anyhow::anyhow!("Failed to find kernel argument '{key}'"))
    }

    /// Add a parameter to the command line if it doesn't already exist
    ///
    /// Returns `Action::Added` if the parameter did not already exist
    /// and was added.
    ///
    /// Returns `Action::Existed` if the exact parameter (same key and value)
    /// already exists. No modification was made.
    ///
    /// Unlike `add_or_modify`, this method will not modify existing
    /// parameters. If a parameter with the same key exists but has a
    /// different value, the new parameter is still added, allowing
    /// duplicate keys (e.g., multiple `console=` parameters).
    pub fn add(&mut self, param: &Parameter) -> Action {
        self.0.add(&param.0)
    }

    /// Add or modify a parameter to the command line
    ///
    /// Returns `Action::Added` if the parameter did not exist before
    /// and was added.
    ///
    /// Returns `Action::Modified` if the parameter existed before,
    /// but contained a different value.  The value was updated to the
    /// newly-requested value.
    ///
    /// Returns `Action::Existed` if the parameter existed before, and
    /// contained the same value as the newly-requested value.  No
    /// modification was made.
    pub fn add_or_modify(&mut self, param: &Parameter) -> Action {
        self.0.add_or_modify(&param.0)
    }

    /// Remove parameter(s) with the given key from the command line
    ///
    /// Returns `true` if parameter(s) were removed.
    pub fn remove(&mut self, key: &ParameterKey) -> bool {
        self.0.remove(&key.0)
    }

    /// Remove all parameters that exactly match the given parameter
    /// from the command line
    ///
    /// Returns `true` if parameter(s) were removed.
    pub fn remove_exact(&mut self, param: &Parameter) -> bool {
        self.0.remove_exact(&param.0)
    }

    #[cfg(test)]
    pub(crate) fn is_owned(&self) -> bool {
        self.0.is_owned()
    }

    #[cfg(test)]
    pub(crate) fn is_borrowed(&self) -> bool {
        self.0.is_borrowed()
    }
}

impl Deref for Cmdline<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        // SAFETY: We know this is valid UTF-8 since we only
        // construct the underlying `bytes` from valid UTF-8
        str::from_utf8(&self.0).expect("We only construct the underlying bytes from valid UTF-8")
    }
}

impl<'a, T> AsRef<T> for Cmdline<'a>
where
    T: ?Sized,
    <Cmdline<'a> as Deref>::Target: AsRef<T>,
{
    fn as_ref(&self) -> &T {
        self.deref().as_ref()
    }
}

impl<'a> std::fmt::Display for Cmdline<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str(self)
    }
}

impl<'a> IntoIterator for &'a Cmdline<'a> {
    type Item = Parameter<'a>;
    type IntoIter = CmdlineIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, 'other> Extend<Parameter<'other>> for Cmdline<'a> {
    // Note this is O(N*M), but in practice this doesn't matter
    // because kernel cmdlines are typically quite small (limited
    // to at most 4k depending on arch).  Using a hash-based
    // structure to reduce this to O(N)+C would likely raise the C
    // portion so much as to erase any benefit from removing the
    // combinatorial complexity.  Plus CPUs are good at
    // caching/pipelining through contiguous memory.
    fn extend<T: IntoIterator<Item = Parameter<'other>>>(&mut self, iter: T) {
        for param in iter {
            self.add(&param);
        }
    }
}

/// A single kernel command line parameter key
///
/// Handles quoted values and treats dashes and underscores in keys as equivalent.
#[derive(Clone, Debug, Eq)]
pub struct ParameterKey<'a>(bytes::ParameterKey<'a>);

impl Deref for ParameterKey<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        // SAFETY: We know this is valid UTF-8 since we only
        // construct the underlying `bytes` from valid UTF-8
        str::from_utf8(&self.0).expect("We only construct the underlying bytes from valid UTF-8")
    }
}

impl<'a, T> AsRef<T> for ParameterKey<'a>
where
    T: ?Sized,
    <ParameterKey<'a> as Deref>::Target: AsRef<T>,
{
    fn as_ref(&self) -> &T {
        self.deref().as_ref()
    }
}

impl<'a> ParameterKey<'a> {
    /// Construct a utf8::ParameterKey from a bytes::ParameterKey
    ///
    /// This is non-public and should only be used when the underlying
    /// bytes are known to be valid UTF-8.
    fn from_bytes(input: bytes::ParameterKey<'a>) -> Self {
        Self(input)
    }
}

impl<'a, T: AsRef<str> + ?Sized> From<&'a T> for ParameterKey<'a> {
    fn from(input: &'a T) -> Self {
        Self(bytes::ParameterKey(input.as_ref().as_bytes()))
    }
}

impl<'a> std::fmt::Display for ParameterKey<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str(self)
    }
}

impl PartialEq for ParameterKey<'_> {
    /// Compares two parameter keys for equality.
    ///
    /// Keys are compared with dashes and underscores treated as equivalent.
    /// This comparison is case-sensitive.
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

/// A single kernel command line parameter.
#[derive(Clone, Debug, Eq)]
pub struct Parameter<'a>(bytes::Parameter<'a>);

impl<'a> Parameter<'a> {
    /// Attempt to parse a single command line parameter from a UTF-8
    /// string.
    ///
    /// Returns `Some(Parameter)`, or `None` if a Parameter could not
    /// be constructed from the input.  This occurs when the input is
    /// either empty or contains only whitespace.
    pub fn parse<T: AsRef<str> + ?Sized>(input: &'a T) -> Option<Self> {
        bytes::Parameter::parse(input.as_ref().as_bytes()).map(Self)
    }

    /// Construct a utf8::Parameter from a bytes::Parameter
    ///
    /// This is non-public and should only be used when the underlying
    /// bytes are known to be valid UTF-8.
    fn from_bytes(bytes: bytes::Parameter<'a>) -> Self {
        Self(bytes)
    }

    /// Returns the key part of the parameter
    pub fn key(&'a self) -> ParameterKey<'a> {
        ParameterKey::from_bytes(self.0.key())
    }

    /// Returns the optional value part of the parameter
    pub fn value(&'a self) -> Option<&'a str> {
        self.0.value().map(|p| {
            // SAFETY: We know this is valid UTF-8 since we only
            // construct the underlying `bytes` from valid UTF-8
            str::from_utf8(p).expect("We only construct the underlying bytes from valid UTF-8")
        })
    }
}

impl<'a> TryFrom<bytes::Parameter<'a>> for Parameter<'a> {
    type Error = anyhow::Error;

    fn try_from(bytes: bytes::Parameter<'a>) -> Result<Self, Self::Error> {
        if str::from_utf8(bytes.key().deref()).is_err() {
            anyhow::bail!("Parameter key is not valid UTF-8");
        }

        if let Some(value) = bytes.value() {
            if str::from_utf8(value).is_err() {
                anyhow::bail!("Parameter value is not valid UTF-8");
            }
        }

        Ok(Self(bytes))
    }
}

impl<'a> std::fmt::Display for Parameter<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
        f.write_str(self)
    }
}

impl Deref for Parameter<'_> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        // SAFETY: We know this is valid UTF-8 since we only
        // construct the underlying `bytes` from valid UTF-8
        str::from_utf8(&self.0).expect("We only construct the underlying bytes from valid UTF-8")
    }
}

impl<'a, T> AsRef<T> for Parameter<'a>
where
    T: ?Sized,
    <Parameter<'a> as Deref>::Target: AsRef<T>,
{
    fn as_ref(&self) -> &T {
        self.deref().as_ref()
    }
}

impl<'a> PartialEq for Parameter<'a> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // convenience method for tests
    fn param(s: &str) -> Parameter<'_> {
        Parameter::parse(s).unwrap()
    }

    #[test]
    fn test_parameter_parse() {
        let p = Parameter::parse("foo").unwrap();
        assert_eq!(p.key(), "foo".into());
        assert_eq!(p.value(), None);

        // should parse only the first parameter and discard the rest of the input
        let p = Parameter::parse("foo=bar baz").unwrap();
        assert_eq!(p.key(), "foo".into());
        assert_eq!(p.value(), Some("bar"));

        // should return None on empty or whitespace inputs
        assert!(Parameter::parse("").is_none());
        assert!(Parameter::parse("   ").is_none());
    }

    #[test]
    fn test_parameter_simple() {
        let switch = param("foo");
        assert_eq!(switch.key(), "foo".into());
        assert_eq!(switch.value(), None);

        let kv = param("bar=baz");
        assert_eq!(kv.key(), "bar".into());
        assert_eq!(kv.value(), Some("baz"));
    }

    #[test]
    fn test_parameter_quoted() {
        let p = param("foo=\"quoted value\"");
        assert_eq!(p.value(), Some("quoted value"));

        let p = param("foo=\"unclosed quotes");
        assert_eq!(p.value(), Some("unclosed quotes"));

        let p = param("foo=trailing_quotes\"");
        assert_eq!(p.value(), Some("trailing_quotes"));

        let outside_quoted = param("\"foo=quoted value\"");
        let value_quoted = param("foo=\"quoted value\"");
        assert_eq!(outside_quoted, value_quoted);
    }

    #[test]
    fn test_parameter_display() {
        // Basically this should always return the original data
        // without modification.

        // unquoted stays unquoted
        assert_eq!(param("foo").to_string(), "foo");

        // quoted stays quoted
        assert_eq!(param("\"foo\"").to_string(), "\"foo\"");
    }

    #[test]
    fn test_parameter_extra_whitespace() {
        let p = param("  foo=bar  ");
        assert_eq!(p.key(), "foo".into());
        assert_eq!(p.value(), Some("bar"));
    }

    #[test]
    fn test_parameter_internal_key_whitespace() {
        // parse should only consume the first parameter
        let p = Parameter::parse("foo bar=baz").unwrap();
        assert_eq!(p.key(), "foo".into());
        assert_eq!(p.value(), None);
    }

    #[test]
    fn test_parameter_pathological() {
        // valid things that certified insane people would do

        // you can quote just the key part in a key-value param, but
        // the end quote is actually part of the key as far as the
        // kernel is concerned...
        let p = param("\"foo\"=bar");
        assert_eq!(p.key(), ParameterKey::from("foo\""));
        assert_eq!(p.value(), Some("bar"));
        // and it is definitely not equal to an unquoted foo ...
        assert_ne!(p, param("foo=bar"));

        // ... but if you close the quote immediately after the
        // equals sign, it does get removed.
        let p = param("\"foo=\"bar");
        assert_eq!(p.key(), ParameterKey::from("foo"));
        assert_eq!(p.value(), Some("bar"));
        // ... so of course this makes sense ...
        assert_eq!(p, param("foo=bar"));

        // quotes only get stripped from the absolute ends of values
        let p = param("foo=\"internal\"quotes\"are\"ok\"");
        assert_eq!(p.value(), Some("internal\"quotes\"are\"ok"));
    }

    #[test]
    fn test_parameter_equality() {
        // substrings are not equal
        let foo = param("foo");
        let bar = param("foobar");
        assert_ne!(foo, bar);
        assert_ne!(bar, foo);

        // dashes and underscores are treated equally
        let dashes = param("a-delimited-param");
        let underscores = param("a_delimited_param");
        assert_eq!(dashes, underscores);

        // same key, same values is equal
        let dashes = param("a-delimited-param=same_values");
        let underscores = param("a_delimited_param=same_values");
        assert_eq!(dashes, underscores);

        // same key, different values is not equal
        let dashes = param("a-delimited-param=different_values");
        let underscores = param("a_delimited_param=DiFfErEnT_valUEZ");
        assert_ne!(dashes, underscores);

        // mixed variants are never equal
        let switch = param("same_key");
        let keyvalue = param("same_key=but_with_a_value");
        assert_ne!(switch, keyvalue);
    }

    #[test]
    fn test_parameter_tryfrom() {
        // ok switch
        let p = bytes::Parameter::parse(b"foo").unwrap();
        let utf = Parameter::try_from(p).unwrap();
        assert_eq!(utf.key(), "foo".into());
        assert_eq!(utf.value(), None);

        // ok key/value
        let p = bytes::Parameter::parse(b"foo=bar").unwrap();
        let utf = Parameter::try_from(p).unwrap();
        assert_eq!(utf.key(), "foo".into());
        assert_eq!(utf.value(), Some("bar".into()));

        // bad switch
        let p = bytes::Parameter::parse(b"f\xffoo").unwrap();
        let e = Parameter::try_from(p);
        assert_eq!(
            e.unwrap_err().to_string(),
            "Parameter key is not valid UTF-8"
        );

        // bad key/value
        let p = bytes::Parameter::parse(b"foo=b\xffar").unwrap();
        let e = Parameter::try_from(p);
        assert_eq!(
            e.unwrap_err().to_string(),
            "Parameter value is not valid UTF-8"
        );
    }

    #[test]
    fn test_kargs_simple() {
        // example taken lovingly from:
        // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/params.c?id=89748acdf226fd1a8775ff6fa2703f8412b286c8#n160
        let kargs = Cmdline::from("foo=bar,bar2 baz=fuz wiz");
        assert!(kargs.is_borrowed());
        let mut iter = kargs.iter();

        assert_eq!(iter.next(), Some(param("foo=bar,bar2")));
        assert_eq!(iter.next(), Some(param("baz=fuz")));
        assert_eq!(iter.next(), Some(param("wiz")));
        assert_eq!(iter.next(), None);

        // Test the find API
        assert_eq!(kargs.find("foo").unwrap().value().unwrap(), "bar,bar2");
        assert!(kargs.find("nothing").is_none());
    }

    #[test]
    fn test_cmdline_default() {
        let kargs: Cmdline = Default::default();
        assert_eq!(kargs.iter().next(), None);
    }

    #[test]
    fn test_cmdline_new() {
        let kargs = Cmdline::new();
        assert_eq!(kargs.iter().next(), None);
        assert!(kargs.is_owned());

        // Verify we can store it in an owned ('static) context
        let _static_kargs: CmdlineOwned = Cmdline::new();
    }

    #[test]
    fn test_kargs_simple_from_string() {
        let kargs = Cmdline::from("foo=bar,bar2 baz=fuz wiz".to_string());
        assert!(kargs.is_owned());
        let mut iter = kargs.iter();

        assert_eq!(iter.next(), Some(param("foo=bar,bar2")));
        assert_eq!(iter.next(), Some(param("baz=fuz")));
        assert_eq!(iter.next(), Some(param("wiz")));
        assert_eq!(iter.next(), None);

        // Test the find API
        assert_eq!(kargs.find("foo").unwrap().value().unwrap(), "bar,bar2");
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
        let kargs = Cmdline::from("a-b=1 a_b=2");
        // find should find the first one, which is a-b=1
        let p = kargs.find("a_b").unwrap();
        assert_eq!(p.key(), "a-b".into());
        assert_eq!(p.value().unwrap(), "1");
        let p = kargs.find("a-b").unwrap();
        assert_eq!(p.key(), "a-b".into());
        assert_eq!(p.value().unwrap(), "1");

        let kargs = Cmdline::from("a_b=2 a-b=1");
        // find should find the first one, which is a_b=2
        let p = kargs.find("a_b").unwrap();
        assert_eq!(p.key(), "a_b".into());
        assert_eq!(p.value().unwrap(), "2");
        let p = kargs.find("a-b").unwrap();
        assert_eq!(p.key(), "a_b".into());
        assert_eq!(p.value().unwrap(), "2");
    }

    #[test]
    fn test_kargs_extra_whitespace() {
        let kargs = Cmdline::from("  foo=bar    baz=fuz  wiz   ");
        let mut iter = kargs.iter();

        assert_eq!(iter.next(), Some(param("foo=bar")));
        assert_eq!(iter.next(), Some(param("baz=fuz")));
        assert_eq!(iter.next(), Some(param("wiz")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_value_of() {
        let kargs = Cmdline::from("foo=bar baz=qux switch");

        // Test existing key with value
        assert_eq!(kargs.value_of("foo"), Some("bar"));
        assert_eq!(kargs.value_of("baz"), Some("qux"));

        // Test key without value
        assert_eq!(kargs.value_of("switch"), None);

        // Test non-existent key
        assert_eq!(kargs.value_of("missing"), None);

        // Test dash/underscore equivalence
        let kargs = Cmdline::from("dash-key=value1 under_key=value2");
        assert_eq!(kargs.value_of("dash_key"), Some("value1"));
        assert_eq!(kargs.value_of("under-key"), Some("value2"));
    }

    #[test]
    fn test_require_value_of() {
        let kargs = Cmdline::from("foo=bar baz=qux switch");

        // Test existing key with value
        assert_eq!(kargs.require_value_of("foo").unwrap(), "bar");
        assert_eq!(kargs.require_value_of("baz").unwrap(), "qux");

        // Test key without value should fail
        let err = kargs.require_value_of("switch").unwrap_err();
        assert!(
            err.to_string()
                .contains("Failed to find kernel argument 'switch'")
        );

        // Test non-existent key should fail
        let err = kargs.require_value_of("missing").unwrap_err();
        assert!(
            err.to_string()
                .contains("Failed to find kernel argument 'missing'")
        );

        // Test dash/underscore equivalence
        let kargs = Cmdline::from("dash-key=value1 under_key=value2");
        assert_eq!(kargs.require_value_of("dash_key").unwrap(), "value1");
        assert_eq!(kargs.require_value_of("under-key").unwrap(), "value2");
    }

    #[test]
    fn test_find_str() {
        let kargs = Cmdline::from("foo=bar baz=qux switch rd.break");
        let p = kargs.find("foo").unwrap();
        assert_eq!(p, param("foo=bar"));
        let p = kargs.find("rd.break").unwrap();
        assert_eq!(p, param("rd.break"));
        assert!(kargs.find("missing").is_none());
    }

    #[test]
    fn test_find_all_str() {
        let kargs = Cmdline::from("foo=bar rd.foo=a rd.bar=b rd.baz rd.qux=c notrd.val=d");
        let mut rd_args: Vec<_> = kargs.find_all_starting_with("rd.").collect();
        rd_args.sort_by(|a, b| a.key().cmp(&b.key()));
        assert_eq!(rd_args.len(), 4);
        assert_eq!(rd_args[0], param("rd.bar=b"));
        assert_eq!(rd_args[1], param("rd.baz"));
        assert_eq!(rd_args[2], param("rd.foo=a"));
        assert_eq!(rd_args[3], param("rd.qux=c"));
    }

    #[test]
    fn test_param_key_eq() {
        let k1 = ParameterKey::from("a-b");
        let k2 = ParameterKey::from("a_b");
        assert_eq!(k1, k2);
        let k1 = ParameterKey::from("a-b");
        let k2 = ParameterKey::from("a-c");
        assert_ne!(k1, k2);
    }

    #[test]
    fn test_add() {
        let mut kargs = Cmdline::from("console=tty0 console=ttyS1");

        // add new parameter with duplicate key but different value
        assert!(matches!(kargs.add(&param("console=ttyS2")), Action::Added));
        let mut iter = kargs.iter();
        assert_eq!(iter.next(), Some(param("console=tty0")));
        assert_eq!(iter.next(), Some(param("console=ttyS1")));
        assert_eq!(iter.next(), Some(param("console=ttyS2")));
        assert_eq!(iter.next(), None);

        // try to add exact duplicate - should return Existed
        assert!(matches!(
            kargs.add(&param("console=ttyS1")),
            Action::Existed
        ));
        iter = kargs.iter();
        assert_eq!(iter.next(), Some(param("console=tty0")));
        assert_eq!(iter.next(), Some(param("console=ttyS1")));
        assert_eq!(iter.next(), Some(param("console=ttyS2")));
        assert_eq!(iter.next(), None);

        // add completely new parameter
        assert!(matches!(kargs.add(&param("quiet")), Action::Added));
        iter = kargs.iter();
        assert_eq!(iter.next(), Some(param("console=tty0")));
        assert_eq!(iter.next(), Some(param("console=ttyS1")));
        assert_eq!(iter.next(), Some(param("console=ttyS2")));
        assert_eq!(iter.next(), Some(param("quiet")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_add_empty_cmdline() {
        let mut kargs = Cmdline::from("");
        assert!(matches!(kargs.add(&param("foo")), Action::Added));
        assert_eq!(&*kargs, "foo");
    }

    #[test]
    fn test_add_or_modify() {
        let mut kargs = Cmdline::from("foo=bar");

        // add new
        assert!(matches!(kargs.add_or_modify(&param("baz")), Action::Added));
        let mut iter = kargs.iter();
        assert_eq!(iter.next(), Some(param("foo=bar")));
        assert_eq!(iter.next(), Some(param("baz")));
        assert_eq!(iter.next(), None);

        // modify existing
        assert!(matches!(
            kargs.add_or_modify(&param("foo=fuz")),
            Action::Modified
        ));
        iter = kargs.iter();
        assert_eq!(iter.next(), Some(param("foo=fuz")));
        assert_eq!(iter.next(), Some(param("baz")));
        assert_eq!(iter.next(), None);

        // already exists with same value returns false and doesn't
        // modify anything
        assert!(matches!(
            kargs.add_or_modify(&param("foo=fuz")),
            Action::Existed
        ));
        iter = kargs.iter();
        assert_eq!(iter.next(), Some(param("foo=fuz")));
        assert_eq!(iter.next(), Some(param("baz")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_add_or_modify_empty_cmdline() {
        let mut kargs = Cmdline::from("");
        assert!(matches!(kargs.add_or_modify(&param("foo")), Action::Added));
        assert_eq!(&*kargs, "foo");
    }

    #[test]
    fn test_add_or_modify_duplicate_parameters() {
        let mut kargs = Cmdline::from("a=1 a=2");
        assert!(matches!(
            kargs.add_or_modify(&param("a=3")),
            Action::Modified
        ));
        let mut iter = kargs.iter();
        assert_eq!(iter.next(), Some(param("a=3")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_remove() {
        let mut kargs = Cmdline::from("foo bar baz");

        // remove existing
        assert!(kargs.remove(&"bar".into()));
        let mut iter = kargs.iter();
        assert_eq!(iter.next(), Some(param("foo")));
        assert_eq!(iter.next(), Some(param("baz")));
        assert_eq!(iter.next(), None);

        // doesn't exist? returns false and doesn't modify anything
        assert!(!kargs.remove(&"missing".into()));
        iter = kargs.iter();
        assert_eq!(iter.next(), Some(param("foo")));
        assert_eq!(iter.next(), Some(param("baz")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_remove_duplicates() {
        let mut kargs = Cmdline::from("a=1 b=2 a=3");
        assert!(kargs.remove(&"a".into()));
        let mut iter = kargs.iter();
        assert_eq!(iter.next(), Some(param("b=2")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_remove_exact() {
        let mut kargs = Cmdline::from("foo foo=bar foo=baz");

        // remove existing
        assert!(kargs.remove_exact(&param("foo=bar")));
        let mut iter = kargs.iter();
        assert_eq!(iter.next(), Some(param("foo")));
        assert_eq!(iter.next(), Some(param("foo=baz")));
        assert_eq!(iter.next(), None);

        // doesn't exist? returns false and doesn't modify anything
        assert!(!kargs.remove_exact(&param("foo=wuz")));
        iter = kargs.iter();
        assert_eq!(iter.next(), Some(param("foo")));
        assert_eq!(iter.next(), Some(param("foo=baz")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_extend() {
        let mut kargs = Cmdline::from("foo=bar baz");
        let other = Cmdline::from("qux=quux foo=updated");

        kargs.extend(&other);

        // Sanity check that the lifetimes of the two Cmdlines are not
        // tied to each other.
        drop(other);

        // Should have preserved the original foo, added qux, baz
        // unchanged, and added the second (duplicate key) foo
        let mut iter = kargs.iter();
        assert_eq!(iter.next(), Some(param("foo=bar")));
        assert_eq!(iter.next(), Some(param("baz")));
        assert_eq!(iter.next(), Some(param("qux=quux")));
        assert_eq!(iter.next(), Some(param("foo=updated")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_extend_empty() {
        let mut kargs = Cmdline::from("");
        let other = Cmdline::from("foo=bar baz");

        kargs.extend(&other);

        let mut iter = kargs.iter();
        assert_eq!(iter.next(), Some(param("foo=bar")));
        assert_eq!(iter.next(), Some(param("baz")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_into_iterator() {
        let kargs = Cmdline::from("foo=bar baz=qux wiz");
        let params: Vec<_> = (&kargs).into_iter().collect();

        assert_eq!(params.len(), 3);
        assert_eq!(params[0], param("foo=bar"));
        assert_eq!(params[1], param("baz=qux"));
        assert_eq!(params[2], param("wiz"));
    }

    #[test]
    fn test_cmdline_eq() {
        // Ordering, quoting, and the whole dash-underscore
        // equivalence thing shouldn't affect whether these are
        // semantically equal
        assert_eq!(
            Cmdline::from("foo bar-with-delim=\"with spaces\""),
            Cmdline::from("\"bar_with_delim=with spaces\" foo")
        );

        // Uneven lengths are not equal even if the parameters are. Or
        // to put it another way, duplicate parameters break equality.
        // Check with both orderings.
        assert_ne!(Cmdline::from("foo"), Cmdline::from("foo foo"));
        assert_ne!(Cmdline::from("foo foo"), Cmdline::from("foo"));

        // Equal lengths but differing duplicates are also not equal
        assert_ne!(Cmdline::from("a a b"), Cmdline::from("a b b"));
    }
}
