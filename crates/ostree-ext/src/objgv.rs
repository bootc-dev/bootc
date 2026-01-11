/// Type representing an ostree commit object.
macro_rules! gv_commit {
    () => {
        gvariant::gv!("(a{sv}aya(say)sstayay)")
    };
}
pub(crate) use gv_commit;

/// Type representing an ostree DIRTREE object.
macro_rules! gv_dirtree {
    () => {
        gvariant::gv!("(a(say)a(sayay))")
    };
}
pub(crate) use gv_dirtree;

#[cfg(test)]
mod tests {
    use gvariant::Marker;
    use gvariant::aligned_bytes::TryAsAligned;

    #[test]
    fn test_dirtree() {
        // Just a compilation test
        let data = b"".try_as_aligned().ok();
        if let Some(data) = data {
            let _t = gv_dirtree!().cast(data);
        }
    }
}
