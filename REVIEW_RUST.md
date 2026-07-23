# Rust-Specific Review Guidelines

These guidelines supplement the general [REVIEW.md](REVIEW.md) with
Rust-specific expectations.

## Separating Parsing from I/O

Have the parser accept a `&str`, then have a separate function that reads from
disk and calls the parser:

```rust
// ✅ Good: parser is a pure function, easy to unit test
fn parse_config(data: &str) -> Result<Config> { ... }

fn load_config(path: &Path) -> Result<Config> {
    let data = std::fs::read_to_string(path)?;
    parse_config(&data)
}
```

## Don't Ignore (Swallow) Errors

Avoid the `if let Ok(v) = ... { }` pattern which silently discards the error
branch. Most errors should be propagated with `?`. If not, at least log the
error:

```rust
// ❌ Avoid: error is silently swallowed
if let Ok(v) = do_something() {
    use_value(v);
}

// ✅ Good: propagate
let v = do_something()?;

// ✅ OK if the error is truly ignorable: log it
match do_something() {
    Ok(v) => use_value(v),
    Err(e) => tracing::debug!("ignoring error: {e}"),
}
```

## Shell Scripts

Several of our projects use the `cargo xtask` pattern to put arbitrary "glue"
code in Rust using the `xshell` crate to keep it easy to run external commands.
This is preferred over long shell scripts.

## Code Formatting

After making changes to any .rs files, `cargo fmt` should be run.
There are CI jobs that lint and expect `cargo fmt` to be a no-op.
Failing to properly format rust code will result in wasted CI
resources.

## General

Prefer rustix over `libc`. All `unsafe` code must be very carefully
justified.

