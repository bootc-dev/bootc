use anyhow::Result;
use serde::Serialize;
use std::io;

/// Ensure reproducible JSON output by ordering map keys
pub(crate) trait JsonOrderedSerialize {
    fn to_json_ordered_string(&self) -> Result<String>;
    fn to_json_ordered_writer<W>(&self, writer: W) -> Result<()>
    where
        W: io::Write;
}

impl<S> JsonOrderedSerialize for S
where
    S: Serialize,
{
    fn to_json_ordered_string(&self) -> Result<String> {
        let val = serde_json::to_value(self)?;
        Ok(val.to_string())
    }

    fn to_json_ordered_writer<W>(&self, writer: W) -> Result<()>
    where
        W: io::Write,
    {
        let value = serde_json::to_value(self)?;
        serde_json::to_writer(writer, &value)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::json::JsonOrderedSerialize;
    use std::collections::HashMap;

    /// We depend on serde_json::Value being ordered, make sure this doesn't change
    #[test]
    fn test_ordering() {
        let map = HashMap::from([("A", 1), ("C", 3), ("B", 2), ("Z", 26), ("Y", 25)]);
        assert_eq!(
            map.to_json_ordered_string().unwrap(),
            "{\"A\":1,\"B\":2,\"C\":3,\"Y\":25,\"Z\":26}"
        )
    }
}
