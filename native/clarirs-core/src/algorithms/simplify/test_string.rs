use crate::prelude::*;
use anyhow::Result;

#[test]
fn test_str_index_of() -> Result<()> {
    let ctx = Context::new();

    // (haystack, needle, start, expected position; u64::MAX is -1)
    let table: Vec<(&str, &str, u64, u64)> = vec![
        ("abcabc", "bc", 0, 1),
        ("abcabc", "bc", 2, 4),
        ("abcabc", "bc", 5, u64::MAX),
        ("abc", "", 1, 1),
        // An empty needle is found at the end of the haystack, even an empty one
        ("abc", "", 3, 3),
        ("", "", 0, 0),
        ("abc", "", 4, u64::MAX),
        ("abc", "a", u64::MAX, u64::MAX),
    ];

    for (haystack, needle, start, expected) in table {
        let result = ctx
            .str_index_of(
                ctx.stringv(haystack)?,
                ctx.stringv(needle)?,
                ctx.bvv(BitVec::from((start, 64)))?,
            )?
            .simplify()?;
        assert_eq!(
            result,
            ctx.bvv(BitVec::from((expected, 64)))?,
            "indexof({haystack:?}, {needle:?}, {start})"
        );
    }

    // An index wider than 64 bits is read by value
    let result = ctx
        .str_index_of(
            ctx.stringv("abcabc")?,
            ctx.stringv("bc")?,
            ctx.bvv(BitVec::from((2, 128)))?,
        )?
        .simplify()?;
    assert_eq!(result, ctx.bvv(BitVec::from((4, 64)))?);
    Ok(())
}

#[test]
fn test_str_substr() -> Result<()> {
    let ctx = Context::new();

    // (string, start, length, expected)
    let table: Vec<(&str, u64, u64, &str)> = vec![
        ("abc", 0, 2, "ab"),
        ("abc", 1, 9, "bc"),
        ("abc", 1, 0, ""),
        ("abc", 3, 1, ""),
        // A length that would overflow start + length still runs to the end
        ("abc", 1, u64::MAX, "bc"),
        ("abc", u64::MAX, 1, ""),
    ];

    for (string, start, length, expected) in table {
        let result = ctx
            .str_substr(
                ctx.stringv(string)?,
                ctx.bvv(BitVec::from((start, 64)))?,
                ctx.bvv(BitVec::from((length, 64)))?,
            )?
            .simplify()?;
        assert_eq!(
            result,
            ctx.stringv(expected)?,
            "substr({string:?}, {start}, {length})"
        );
    }

    // Indices wider than 64 bits are read by value
    let result = ctx
        .str_substr(
            ctx.stringv("abc")?,
            ctx.bvv(BitVec::from((1, 128)))?,
            ctx.bvv(BitVec::from((1, 128)))?,
        )?
        .simplify()?;
    assert_eq!(result, ctx.stringv("b")?);
    Ok(())
}

#[test]
fn test_str_concat() -> Result<()> {
    let ctx = Context::new();
    let x = ctx.strings("x")?;
    let y = ctx.strings("y")?;

    // Literals fold into one, however many there are
    let result = ctx
        .str_concat([ctx.stringv("a")?, ctx.stringv("b")?, ctx.stringv("c")?])?
        .simplify()?;
    assert_eq!(result, ctx.stringv("abc")?);

    // A single operand is the operand itself
    assert_eq!(ctx.str_concat([x.clone()])?.simplify()?, x);

    // Nested concats flatten into one n-ary node
    let nested = ctx.str_concat2(x.clone(), ctx.str_concat2(y.clone(), ctx.stringv("z")?)?)?;
    let expected = ctx.str_concat([x.clone(), y.clone(), ctx.stringv("z")?])?;
    assert_eq!(nested.simplify()?, expected);

    // Empty literals drop out and adjacent literals merge
    let mixed = ctx.str_concat([
        ctx.stringv("")?,
        ctx.stringv("a")?,
        ctx.stringv("b")?,
        x.clone(),
        ctx.stringv("")?,
        ctx.stringv("c")?,
        ctx.stringv("d")?,
    ])?;
    let expected = ctx.str_concat([ctx.stringv("ab")?, x.clone(), ctx.stringv("cd")?])?;
    assert_eq!(mixed.simplify()?, expected);

    // Concatenating only empty literals is the empty string
    let empties = ctx.str_concat([ctx.stringv("")?, ctx.stringv("")?])?;
    assert_eq!(empties.simplify()?, ctx.stringv("")?);

    // No operands is an error
    assert!(ctx.str_concat(Vec::new()).is_err());
    Ok(())
}
