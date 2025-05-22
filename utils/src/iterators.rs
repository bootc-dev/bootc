use std::num::NonZeroUsize;

/// Given an iterator that's clonable, split it into two iterators
/// at a given maximum number of elements.
pub fn iterator_split<I>(
    it: I,
    max: usize,
) -> (impl Iterator<Item = I::Item>, impl Iterator<Item = I::Item>)
where
    I: Iterator + Clone,
{
    let rest = it.clone();
    (it.take(max), rest.skip(max))
}

/// Gather the first N items, and provide the count of the remaining items.
/// The max count cannot be zero as that's a pathological case.
pub fn collect_until<I>(it: I, max: NonZeroUsize) -> Option<(Vec<I::Item>, usize)>
where
    I: Iterator,
{
    let mut items = Vec::with_capacity(max.get());

    let mut it = it.peekable();
    if it.peek().is_none() {
        return None;
    }

    while let Some(next) = it.next() {
        items.push(next);

        // If we've reached max items, stop collecting
        if items.len() == max.get() {
            break;
        }
    }
    // Count remaining items
    let remaining = it.count();
    items.shrink_to_fit();
    Some((items, remaining))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_it_split() {
        let a: &[&str] = &[];
        for v in [0, 1, 5] {
            let (first, rest) = iterator_split(a.iter(), v);
            assert_eq!(first.count(), 0);
            assert_eq!(rest.count(), 0);
        }
        let a = &["foo"];
        for v in [1, 5] {
            let (first, rest) = iterator_split(a.iter(), v);
            assert_eq!(first.count(), 1);
            assert_eq!(rest.count(), 0);
        }
        let (first, rest) = iterator_split(a.iter(), 1);
        assert_eq!(first.count(), 1);
        assert_eq!(rest.count(), 0);
        let a = &["foo", "bar", "baz", "blah", "other"];
        let (first, rest) = iterator_split(a.iter(), 2);
        assert_eq!(first.count(), 2);
        assert_eq!(rest.count(), 3);
    }

    #[test]
    fn test_split_empty_iterator() {
        let a: &[&str] = &[];
        for v in [1, 5].into_iter().map(|v| NonZeroUsize::new(v).unwrap()) {
            assert!(collect_until(a.iter(), v).is_none());
        }
    }

    #[test]
    fn test_split_nonempty_iterator() {
        let a = &["foo"];

        let Some((elts, 0)) = collect_until(a.iter(), NonZeroUsize::new(1).unwrap()) else {
            panic!()
        };
        assert_eq!(elts.len(), 1);

        let Some((elts, 0)) = collect_until(a.iter(), const { NonZeroUsize::new(5).unwrap() })
        else {
            panic!()
        };
        assert_eq!(elts.len(), 1);

        let a = &["foo", "bar", "baz", "blah", "other"];
        let Some((elts, 3)) = collect_until(a.iter(), const { NonZeroUsize::new(2).unwrap() })
        else {
            panic!()
        };
        assert_eq!(elts.len(), 2);
    }
}
