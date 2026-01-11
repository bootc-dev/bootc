//! Byte-based kernel command line parsing utilities.
//!
//! This module provides functionality for parsing and working with kernel command line
//! arguments, supporting both key-only switches and key-value pairs with proper quote handling.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::ops::Deref;

use crate::{Action, utf8};

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// A parsed kernel command line.
///
/// Wraps the raw command line bytes and provides methods for parsing and iterating
/// over individual parameters. Uses copy-on-write semantics to avoid unnecessary
/// allocations when working with borrowed data.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Cmdline<'a>(Cow<'a, [u8]>);

/// An owned Cmdline.  Alias for `Cmdline<'static>`.
pub type CmdlineOwned = Cmdline<'static>;

impl<'a, T: AsRef<[u8]> + ?Sized> From<&'a T> for Cmdline<'a> {
    /// Creates a new `Cmdline` from any type that can be referenced as bytes.
    ///
    /// Uses borrowed data when possible to avoid unnecessary allocations.
    fn from(input: &'a T) -> Self {
        Self(Cow::Borrowed(input.as_ref()))
    }
}

impl Deref for Cmdline<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
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

impl From<Vec<u8>> for CmdlineOwned {
    /// Creates a new `Cmdline` from an owned `Vec<u8>`.
    fn from(input: Vec<u8>) -> Self {
        Self(Cow::Owned(input))
    }
}

/// An iterator over kernel command line parameters.
///
/// This is created by the `iter` method on `Cmdline`.
#[derive(Debug)]
pub struct CmdlineIter<'a>(CmdlineIterBytes<'a>);

impl<'a> Iterator for CmdlineIter<'a> {
    type Item = Parameter<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().and_then(Parameter::parse_internal)
    }
}

/// An iterator over kernel command line parameters as byte slices.
///
/// This is created by the `iter_bytes` method on `Cmdline`.
#[derive(Debug)]
pub struct CmdlineIterBytes<'a>(&'a [u8]);

impl<'a> Iterator for CmdlineIterBytes<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        let input = self.0.trim_ascii_start();

        if input.is_empty() {
            self.0 = input;
            return None;
        }

        let mut in_quotes = false;
        let end = input.iter().position(move |c| {
            if *c == b'"' {
                in_quotes = !in_quotes;
            }
            !in_quotes && c.is_ascii_whitespace()
        });

        let end = end.unwrap_or(input.len());
        let (param, rest) = input.split_at(end);
        self.0 = rest;

        Some(param)
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
    /// Returns an error if the file cannot be read or if there are I/O issues.
    pub fn from_proc() -> Result<Self> {
        Ok(Self(Cow::Owned(std::fs::read("/proc/cmdline")?)))
    }

    /// Returns an iterator over all parameters in the command line.
    ///
    /// Properly handles quoted values containing whitespace and splits on
    /// unquoted whitespace characters. Parameters are parsed as either
    /// key-only switches or key=value pairs.
    pub fn iter(&'a self) -> CmdlineIter<'a> {
        CmdlineIter(self.iter_bytes())
    }

    /// Returns an iterator over all parameters in the command line as byte slices.
    ///
    /// This is similar to `iter()` but yields `&[u8]` directly instead of `Parameter`,
    /// which can be more convenient when you just need the raw byte representation.
    pub fn iter_bytes(&self) -> CmdlineIterBytes<'_> {
        CmdlineIterBytes(&self.0)
    }

    /// Returns an iterator over all parameters in the command line
    /// which are valid UTF-8.
    pub fn iter_utf8(&'a self) -> impl Iterator<Item = utf8::Parameter<'a>> {
        self.iter()
            .filter_map(|p| utf8::Parameter::try_from(p).ok())
    }

    /// Locate a kernel argument with the given key name.
    ///
    /// Returns the first parameter matching the given key, or `None` if not found.
    /// Key comparison treats dashes and underscores as equivalent.
    pub fn find<T: AsRef<[u8]> + ?Sized>(&'a self, key: &T) -> Option<Parameter<'a>> {
        let key = ParameterKey(key.as_ref());
        self.iter().find(|p| p.key == key)
    }

    /// Locate a kernel argument with the given key name.
    ///
    /// Returns an error if a parameter with the given key name is
    /// found, but the value is not valid UTF-8.
    ///
    /// Otherwise, returns the first parameter matching the given key,
    /// or `None` if not found.  Key comparison treats dashes and
    /// underscores as equivalent.
    pub fn find_utf8<T: AsRef<[u8]> + ?Sized>(
        &'a self,
        key: &T,
    ) -> Result<Option<utf8::Parameter<'a>>> {
        let bytes = match self.find(key.as_ref()) {
            Some(p) => p,
            None => return Ok(None),
        };

        Ok(Some(utf8::Parameter::try_from(bytes)?))
    }

    /// Find all kernel arguments starting with the given prefix.
    ///
    /// This is a variant of [`Self::find`].
    pub fn find_all_starting_with<T: AsRef<[u8]> + ?Sized>(
        &'a self,
        prefix: &'a T,
    ) -> impl Iterator<Item = Parameter<'a>> + 'a {
        self.iter()
            .filter(move |p| p.key.0.starts_with(prefix.as_ref()))
    }

    /// Locate the value of the kernel argument with the given key name.
    ///
    /// Returns the first value matching the given key, or `None` if not found.
    /// Key comparison treats dashes and underscores as equivalent.
    pub fn value_of<T: AsRef<[u8]> + ?Sized>(&'a self, key: &T) -> Option<&'a [u8]> {
        self.find(&key).and_then(|p| p.value)
    }

    /// Find the value of the kernel argument with the provided name, which must be present.
    ///
    /// Otherwise the same as [`Self::value_of`].
    pub fn require_value_of<T: AsRef<[u8]> + ?Sized>(&'a self, key: &T) -> Result<&'a [u8]> {
        let key = key.as_ref();
        self.value_of(key).ok_or_else(|| {
            let key = String::from_utf8_lossy(key);
            anyhow::anyhow!("Failed to find kernel argument '{key}'")
        })
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
        // Check if the exact parameter already exists
        for p in self.iter() {
            if p == *param {
                // Exact match found, don't add duplicate
                return Action::Existed;
            }
        }

        // The exact parameter was not found, so we append it.
        let self_mut = self.0.to_mut();
        if self_mut
            .last()
            .filter(|v| !v.is_ascii_whitespace())
            .is_some()
        {
            self_mut.push(b' ');
        }
        self_mut.extend_from_slice(param.parameter);
        Action::Added
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
        let mut new_params = Vec::new();
        let mut modified = false;
        let mut seen_key = false;

        for p in self.iter() {
            if p.key == param.key {
                if !seen_key {
                    // This is the first time we've seen this key.
                    // We will replace it with the new parameter.
                    if p != *param {
                        modified = true;
                    }
                    new_params.push(param.parameter);
                } else {
                    // This is a subsequent parameter with the same key.
                    // We will remove it, which constitutes a modification.
                    modified = true;
                }
                seen_key = true;
            } else {
                new_params.push(p.parameter);
            }
        }

        if !seen_key {
            // The parameter was not found, so we append it.
            let self_mut = self.0.to_mut();
            if self_mut
                .last()
                .filter(|v| !v.is_ascii_whitespace())
                .is_some()
            {
                self_mut.push(b' ');
            }
            self_mut.extend_from_slice(param.parameter);
            return Action::Added;
        }
        if modified {
            self.0 = Cow::Owned(new_params.join(b" ".as_slice()));
            Action::Modified
        } else {
            // The parameter already existed with the same content, and there were no duplicates.
            Action::Existed
        }
    }

    /// Remove parameter(s) with the given key from the command line
    ///
    /// Returns `true` if parameter(s) were removed.
    pub fn remove(&mut self, key: &ParameterKey) -> bool {
        let mut removed = false;
        let mut new_params = Vec::new();

        for p in self.iter() {
            if p.key == *key {
                removed = true;
            } else {
                new_params.push(p.parameter);
            }
        }

        if removed {
            self.0 = Cow::Owned(new_params.join(b" ".as_slice()));
        }

        removed
    }

    /// Remove all parameters that exactly match the given parameter
    /// from the command line
    ///
    /// Returns `true` if parameter(s) were removed.
    pub fn remove_exact(&mut self, param: &Parameter) -> bool {
        let mut removed = false;
        let mut new_params = Vec::new();

        for p in self.iter() {
            if p == *param {
                removed = true;
            } else {
                new_params.push(p.parameter);
            }
        }

        if removed {
            self.0 = Cow::Owned(new_params.join(b" ".as_slice()));
        }

        removed
    }

    #[cfg(test)]
    pub(crate) fn is_owned(&self) -> bool {
        matches!(self.0, Cow::Owned(_))
    }

    #[cfg(test)]
    pub(crate) fn is_borrowed(&self) -> bool {
        matches!(self.0, Cow::Borrowed(_))
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
    fn extend<T: IntoIterator<Item = Parameter<'other>>>(&mut self, iter: T) {
        // Note this is O(N*M), but in practice this doesn't matter
        // because kernel cmdlines are typically quite small (limited
        // to at most 4k depending on arch).  Using a hash-based
        // structure to reduce this to O(N)+C would likely raise the C
        // portion so much as to erase any benefit from removing the
        // combinatorial complexity.  Plus CPUs are good at
        // caching/pipelining through contiguous memory.
        for param in iter {
            self.add(&param);
        }
    }
}

impl PartialEq for Cmdline<'_> {
    fn eq(&self, other: &Self) -> bool {
        let mut our_params = self.iter().collect::<Vec<_>>();
        our_params.sort();
        let mut their_params = other.iter().collect::<Vec<_>>();
        their_params.sort();

        our_params == their_params
    }
}

impl Eq for Cmdline<'_> {}

/// A single kernel command line parameter key
///
/// Handles quoted values and treats dashes and underscores in keys as equivalent.
#[derive(Clone, Debug)]
pub struct ParameterKey<'a>(pub(crate) &'a [u8]);

impl Deref for ParameterKey<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
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

impl<'a, T: AsRef<[u8]> + ?Sized> From<&'a T> for ParameterKey<'a> {
    fn from(s: &'a T) -> Self {
        Self(s.as_ref())
    }
}

impl ParameterKey<'_> {
    /// Returns an iterator over the canonicalized bytes of the
    /// parameter, with dashes turned into underscores.
    fn iter(&self) -> impl Iterator<Item = u8> + use<'_> {
        self.0
            .iter()
            .map(|&c: &u8| if c == b'-' { b'_' } else { c })
    }
}

impl PartialEq for ParameterKey<'_> {
    /// Compares two parameter keys for equality.
    ///
    /// Keys are compared with dashes and underscores treated as equivalent.
    /// This comparison is case-sensitive.
    fn eq(&self, other: &Self) -> bool {
        self.iter().eq(other.iter())
    }
}

impl Eq for ParameterKey<'_> {}

impl Ord for ParameterKey<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.iter().cmp(other.iter())
    }
}

impl PartialOrd for ParameterKey<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// A single kernel command line parameter.
#[derive(Clone, Debug)]
pub struct Parameter<'a> {
    /// The full original value
    parameter: &'a [u8],
    /// The parameter key as raw bytes
    key: ParameterKey<'a>,
    /// The parameter value as raw bytes, if present
    value: Option<&'a [u8]>,
}

impl<'a> Parameter<'a> {
    /// Attempt to parse a single command line parameter from a slice
    /// of bytes.
    ///
    /// Returns `Some(Parameter)`, or `None` if a Parameter could not
    /// be constructed from the input.  This occurs when the input is
    /// either empty or contains only whitespace.
    ///
    /// If the input contains multiple parameters, only the first one
    /// is parsed and the rest is discarded.
    pub fn parse<T: AsRef<[u8]> + ?Sized>(input: &'a T) -> Option<Self> {
        CmdlineIterBytes(input.as_ref())
            .next()
            .and_then(Self::parse_internal)
    }

    /// Parse a parameter from a byte slice that contains exactly one parameter.
    ///
    /// This is an internal method that assumes the input has already been
    /// split into a single parameter (e.g., by CmdlineIterBytes).
    fn parse_internal(input: &'a [u8]) -> Option<Self> {
        // *Only* the first and last double quotes are stripped
        let dequoted_input = input.strip_prefix(b"\"").unwrap_or(input);
        let dequoted_input = dequoted_input.strip_suffix(b"\"").unwrap_or(dequoted_input);

        let equals = dequoted_input.iter().position(|b| *b == b'=');

        match equals {
            None => Some(Self {
                parameter: input,
                key: ParameterKey(dequoted_input),
                value: None,
            }),
            Some(i) => {
                let (key, mut value) = dequoted_input.split_at(i);
                let key = ParameterKey(key);

                // skip `=`, we know it's the first byte because we
                // found it above
                value = &value[1..];

                // If there is a quote after the equals, skip it.  If
                // there was a closing quote at the end of the value,
                // we would have already removed it in
                // `dequoted_input` above
                value = value.strip_prefix(b"\"").unwrap_or(value);

                Some(Self {
                    parameter: input,
                    key,
                    value: Some(value),
                })
            }
        }
    }

    /// Returns the key part of the parameter
    pub fn key(&self) -> ParameterKey<'a> {
        self.key.clone()
    }

    /// Returns the optional value part of the parameter
    pub fn value(&self) -> Option<&'a [u8]> {
        self.value
    }
}

impl PartialEq for Parameter<'_> {
    fn eq(&self, other: &Self) -> bool {
        // Note we don't compare parameter because we want hyphen-dash insensitivity for the key
        self.key == other.key && self.value == other.value
    }
}

impl Eq for Parameter<'_> {}

impl Ord for Parameter<'_> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key.cmp(&other.key).then(self.value.cmp(&other.value))
    }
}

impl PartialOrd for Parameter<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Deref for Parameter<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.parameter
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

#[cfg(test)]
mod tests {
    use super::*;

    // convenience methods for tests
    fn param(s: &str) -> Parameter<'_> {
        Parameter::parse(s.as_bytes()).unwrap()
    }

    fn param_utf8(s: &str) -> utf8::Parameter<'_> {
        utf8::Parameter::parse(s).unwrap()
    }

    #[test]
    fn test_parameter_parse() {
        let p = Parameter::parse(b"foo").unwrap();
        assert_eq!(p.key.0, b"foo");
        assert_eq!(p.value, None);

        // should parse only the first parameter and discard the rest of the input
        let p = Parameter::parse(b"foo=bar baz").unwrap();
        assert_eq!(p.key.0, b"foo");
        assert_eq!(p.value, Some(b"bar".as_slice()));

        // should return None on empty or whitespace inputs
        assert!(Parameter::parse(b"").is_none());
        assert!(Parameter::parse(b"   ").is_none());
    }

    #[test]
    fn test_parameter_simple() {
        let switch = param("foo");
        assert_eq!(switch.key.0, b"foo");
        assert_eq!(switch.value, None);

        let kv = param("bar=baz");
        assert_eq!(kv.key.0, b"bar");
        assert_eq!(kv.value, Some(b"baz".as_slice()));
    }

    #[test]
    fn test_parameter_quoted() {
        let p = param("foo=\"quoted value\"");
        assert_eq!(p.value, Some(b"quoted value".as_slice()));

        let p = param("foo=\"unclosed quotes");
        assert_eq!(p.value, Some(b"unclosed quotes".as_slice()));

        let p = param("foo=trailing_quotes\"");
        assert_eq!(p.value, Some(b"trailing_quotes".as_slice()));

        let outside_quoted = param("\"foo=quoted value\"");
        let value_quoted = param("foo=\"quoted value\"");
        assert_eq!(outside_quoted, value_quoted);
    }

    #[test]
    fn test_parameter_extra_whitespace() {
        let p = param("  foo=bar  ");
        assert_eq!(p.key.0, b"foo");
        assert_eq!(p.value, Some(b"bar".as_slice()));
    }

    #[test]
    fn test_parameter_internal_key_whitespace() {
        // parse should only consume the first parameter
        let p = Parameter::parse("foo bar=baz".as_bytes()).unwrap();
        assert_eq!(p.key.0, b"foo");
        assert_eq!(p.value, None);
    }

    #[test]
    fn test_parameter_pathological() {
        // valid things that certified insane people would do

        // you can quote just the key part in a key-value param, but
        // the end quote is actually part of the key as far as the
        // kernel is concerned...
        let p = param("\"foo\"=bar");
        assert_eq!(p.key.0, b"foo\"");
        assert_eq!(p.value, Some(b"bar".as_slice()));
        // and it is definitely not equal to an unquoted foo ...
        assert_ne!(p, param("foo=bar"));

        // ... but if you close the quote immediately after the
        // equals sign, it does get removed.
        let p = param("\"foo=\"bar");
        assert_eq!(p.key.0, b"foo");
        assert_eq!(p.value, Some(b"bar".as_slice()));
        // ... so of course this makes sense ...
        assert_eq!(p, param("foo=bar"));

        // quotes only get stripped from the absolute ends of values
        let p = param("foo=\"internal\"quotes\"are\"ok\"");
        assert_eq!(p.value, Some(b"internal\"quotes\"are\"ok".as_slice()));

        // non-UTF8 things are in fact valid
        let non_utf8_byte = b"\xff";
        #[allow(invalid_from_utf8)]
        let failed_conversion = str::from_utf8(non_utf8_byte);
        assert!(failed_conversion.is_err());
        let mut p = b"foo=".to_vec();
        p.push(non_utf8_byte[0]);
        let p = Parameter::parse(&p).unwrap();
        assert_eq!(p.value, Some(non_utf8_byte.as_slice()));
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
    fn test_kargs_simple() {
        // example taken lovingly from:
        // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/kernel/params.c?id=89748acdf226fd1a8775ff6fa2703f8412b286c8#n160
        let kargs = Cmdline::from(b"foo=bar,bar2 baz=fuz wiz".as_slice());
        let mut iter = kargs.iter();

        assert_eq!(iter.next(), Some(param("foo=bar,bar2")));
        assert_eq!(iter.next(), Some(param("baz=fuz")));
        assert_eq!(iter.next(), Some(param("wiz")));
        assert_eq!(iter.next(), None);

        // Test the find API
        assert_eq!(kargs.find("foo").unwrap().value.unwrap(), b"bar,bar2");
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
    fn test_kargs_iter_utf8() {
        let kargs = Cmdline::from(b"foo=bar,bar2 \xff baz=fuz bad=oh\xffno wiz");
        let mut iter = kargs.iter_utf8();

        assert_eq!(iter.next(), Some(param_utf8("foo=bar,bar2")));
        assert_eq!(iter.next(), Some(param_utf8("baz=fuz")));
        assert_eq!(iter.next(), Some(param_utf8("wiz")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_kargs_find_utf8() {
        let kargs = Cmdline::from(b"foo=bar,bar2 \xff baz=fuz bad=oh\xffno wiz");

        // found it
        assert_eq!(
            kargs.find_utf8("foo").unwrap().unwrap().value().unwrap(),
            "bar,bar2"
        );

        // didn't find it
        assert!(kargs.find_utf8("nothing").unwrap().is_none());

        // found it but key is invalid
        let p = kargs.find_utf8("bad");
        assert_eq!(
            p.unwrap_err().to_string(),
            "Parameter value is not valid UTF-8"
        );
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
    fn test_kargs_extra_whitespace() {
        let kargs = Cmdline::from(b"  foo=bar    baz=fuz  wiz   ".as_slice());
        let mut iter = kargs.iter();

        assert_eq!(iter.next(), Some(param("foo=bar")));
        assert_eq!(iter.next(), Some(param("baz=fuz")));
        assert_eq!(iter.next(), Some(param("wiz")));
        assert_eq!(iter.next(), None);
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
    fn test_require_value_of() {
        let kargs = Cmdline::from(b"foo=bar baz=qux switch".as_slice());

        // Test existing key with value
        assert_eq!(kargs.require_value_of("foo").unwrap(), b"bar");
        assert_eq!(kargs.require_value_of("baz").unwrap(), b"qux");

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
        let kargs = Cmdline::from(b"dash-key=value1 under_key=value2".as_slice());
        assert_eq!(kargs.require_value_of("dash_key").unwrap(), b"value1");
        assert_eq!(kargs.require_value_of("under-key").unwrap(), b"value2");
    }

    #[test]
    fn test_find_all() {
        let kargs =
            Cmdline::from(b"foo=bar rd.foo=a rd.bar=b rd.baz rd.qux=c notrd.val=d".as_slice());
        let mut rd_args: Vec<_> = kargs.find_all_starting_with(b"rd.".as_slice()).collect();
        rd_args.sort_by(|a, b| a.key.0.cmp(b.key.0));
        assert_eq!(rd_args.len(), 4);
        assert_eq!(rd_args[0], param("rd.bar=b"));
        assert_eq!(rd_args[1], param("rd.baz"));
        assert_eq!(rd_args[2], param("rd.foo=a"));
        assert_eq!(rd_args[3], param("rd.qux=c"));
    }

    #[test]
    fn test_add() {
        let mut kargs = Cmdline::from(b"console=tty0 console=ttyS1");

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
        let mut kargs = Cmdline::from(b"");
        assert!(matches!(kargs.add(&param("foo")), Action::Added));
        assert_eq!(kargs.0, b"foo".as_slice());
    }

    #[test]
    fn test_add_or_modify() {
        let mut kargs = Cmdline::from(b"foo=bar");

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
        let mut kargs = Cmdline::from(b"");
        assert!(matches!(kargs.add_or_modify(&param("foo")), Action::Added));
        assert_eq!(kargs.0, b"foo".as_slice());
    }

    #[test]
    fn test_add_or_modify_duplicate_parameters() {
        let mut kargs = Cmdline::from(b"a=1 a=2");
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
        let mut kargs = Cmdline::from(b"foo bar baz");

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
        let mut kargs = Cmdline::from(b"a=1 b=2 a=3");
        assert!(kargs.remove(&"a".into()));
        let mut iter = kargs.iter();
        assert_eq!(iter.next(), Some(param("b=2")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_remove_exact() {
        let mut kargs = Cmdline::from(b"foo foo=bar foo=baz");

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
        let mut kargs = Cmdline::from(b"foo=bar baz");
        let other = Cmdline::from(b"qux=quux foo=updated");

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
        let mut kargs = Cmdline::from(b"");
        let other = Cmdline::from(b"foo=bar baz");

        kargs.extend(&other);

        let mut iter = kargs.iter();
        assert_eq!(iter.next(), Some(param("foo=bar")));
        assert_eq!(iter.next(), Some(param("baz")));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_into_iterator() {
        let kargs = Cmdline::from(b"foo=bar baz=qux wiz");
        let params: Vec<_> = (&kargs).into_iter().collect();

        assert_eq!(params.len(), 3);
        assert_eq!(params[0], param("foo=bar"));
        assert_eq!(params[1], param("baz=qux"));
        assert_eq!(params[2], param("wiz"));
    }

    #[test]
    fn test_iter_bytes_simple() {
        let kargs = Cmdline::from(b"foo bar baz");
        let params: Vec<_> = kargs.iter_bytes().collect();

        assert_eq!(params.len(), 3);
        assert_eq!(params[0], b"foo");
        assert_eq!(params[1], b"bar");
        assert_eq!(params[2], b"baz");
    }

    #[test]
    fn test_iter_bytes_with_values() {
        let kargs = Cmdline::from(b"foo=bar baz=qux wiz");
        let params: Vec<_> = kargs.iter_bytes().collect();

        assert_eq!(params.len(), 3);
        assert_eq!(params[0], b"foo=bar");
        assert_eq!(params[1], b"baz=qux");
        assert_eq!(params[2], b"wiz");
    }

    #[test]
    fn test_iter_bytes_with_quotes() {
        let kargs = Cmdline::from(b"foo=\"bar baz\" qux");
        let params: Vec<_> = kargs.iter_bytes().collect();

        assert_eq!(params.len(), 2);
        assert_eq!(params[0], b"foo=\"bar baz\"");
        assert_eq!(params[1], b"qux");
    }

    #[test]
    fn test_iter_bytes_extra_whitespace() {
        let kargs = Cmdline::from(b"  foo   bar  ");
        let params: Vec<_> = kargs.iter_bytes().collect();

        assert_eq!(params.len(), 2);
        assert_eq!(params[0], b"foo");
        assert_eq!(params[1], b"bar");
    }

    #[test]
    fn test_iter_bytes_empty() {
        let kargs = Cmdline::from(b"");
        let params: Vec<_> = kargs.iter_bytes().collect();

        assert_eq!(params.len(), 0);
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
