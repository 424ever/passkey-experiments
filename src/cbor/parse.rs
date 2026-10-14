//! https://www.rfc-editor.org/info/rfc8949/#section-3

use std::{borrow::Cow, marker::PhantomData};

use winnow::{
    ModalResult, Parser, binary,
    combinator::{repeat, terminated},
    error::{ContextError, ErrMode},
    stream::Accumulate,
    token::{any, take},
};

use crate::cbor::model::{DataItem, Total};

pub fn data_item<'i>(i: &mut &'i [u8]) -> ModalResult<DataItem<'i>> {
    let (major_type, additional_information, argument) = head.parse_next(i)?;

    match major_type {
        0 => Ok(DataItem::Positive(argument.unwrap())),
        1 => Ok(DataItem::Negative(argument.unwrap())),
        2 => byte_string(argument)
            .map(DataItem::ByteString)
            .parse_next(i),
        3 => text_string(argument)
            .map(DataItem::TextString)
            .parse_next(i),
        4 => repeat_exact_or_until_break(argument, data_item)
            .map(DataItem::Array)
            .parse_next(i),
        5 => repeat_exact_or_until_break(argument, (data_item, data_item))
            .map(DataItem::Map)
            .parse_next(i),
        6 => data_item
            .map(|i| DataItem::Tagged {
                tag: argument.unwrap(),
                content: Box::new(i),
            })
            .parse_next(i),
        7 => match additional_information {
            n @ 0..=23 => simple(n).ok_or(ErrMode::Backtrack(ContextError::new())),
            24 => match argument {
                None => return Err(ErrMode::Backtrack(ContextError::new())),
                Some(n) if n <= 31 => return Err(ErrMode::Backtrack(ContextError::new())),
                Some(n) => {
                    return simple(n.try_into().unwrap())
                        .ok_or(ErrMode::Backtrack(ContextError::new()));
                }
            },
            25 => Err(ErrMode::Cut(ContextError::new())),
            26 => binary::be_f32
                .parse_next(i)
                .map(|f| DataItem::F32(Total::new(f))),
            27 => binary::be_f64
                .parse_next(i)
                .map(|f| DataItem::F64(Total::new(f))),
            28..=30 => Err(ErrMode::Cut(ContextError::new())),
            31 => Err(ErrMode::Backtrack(ContextError::new())), // "break" Stop Code
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }
}

pub(crate) fn head<'i>(i: &mut &'i [u8]) -> ModalResult<(u8, u8, Option<u64>)> {
    let initial_byte = any.parse_next(i)?;
    let major_type = (initial_byte & 0b11100000) >> 5;
    let additional_information = initial_byte & 0b00011111;

    let argument = match additional_information {
        ad @ 0..24 => Some(ad.into()),
        ad @ 24..=27 => Some(
            take(ad - 23)
                .map(|b: &[u8]| {
                    let mut buf = [0u8; 8];
                    buf[(8 - b.len())..].copy_from_slice(b);
                    u64::from_be_bytes(buf)
                })
                .parse_next(i)?,
        ),
        28 | 29 | 30 => return Err(ErrMode::Backtrack(ContextError::new())),
        31 => match major_type {
            0 | 1 | 6 => return Err(ErrMode::Backtrack(ContextError::new())),
            2 | 3 | 4 | 5 | 7 => None,
            _ => unreachable!(),
        },
        _ => unreachable!(),
    };

    Ok((major_type, additional_information, argument))
}

fn stop_code<'i>(i: &mut &'i [u8]) -> ModalResult<()> {
    head.verify(|h| matches!(h, (7, _, None)))
        .void()
        .parse_next(i)
}

fn simple(i: u8) -> Option<DataItem<'static>> {
    match i {
        20 => Some(DataItem::False),
        21 => Some(DataItem::True),
        22 => Some(DataItem::Null),
        23 => Some(DataItem::Undefined),
        24..=31 => None,
        n => Some(DataItem::Simple(n)),
    }
}

fn byte_string(
    len: Option<u64>,
) -> impl for<'a> Parser<&'a [u8], Cow<'a, [u8]>, ErrMode<ContextError>> {
    ByteString::new(
        len,
        2,
        |i| Ok::<_, !>(i),
        |mut a, b| {
            a.extend_from_slice(b);
            a
        },
    )
}

fn text_string(
    len: Option<u64>,
) -> impl for<'a> Parser<&'a [u8], Cow<'a, str>, ErrMode<ContextError>> {
    ByteString::new(
        len,
        3,
        |i| str::from_utf8(i),
        |mut a, b| {
            a.push_str(b);
            a
        },
    )
}

struct ByteString<C, A> {
    len: Option<u64>,
    major_type: u8,
    conv: C,
    acc: A,
}

impl<C, A> ByteString<C, A> {
    fn new<O, CE>(len: Option<u64>, major_type: u8, conv: C, acc: A) -> Self
    where
        C: for<'i> Fn(&'i [u8]) -> Result<&'i O, CE>,
        A: for<'a> Fn(<O as ToOwned>::Owned, &O) -> <O as ToOwned>::Owned,
        O: ToOwned + ?Sized,
    {
        Self {
            len,
            major_type,
            conv,
            acc,
        }
    }
}

impl<'i, C, O, CE, A> Parser<&'i [u8], Cow<'i, O>, ErrMode<ContextError>> for ByteString<C, A>
where
    C: for<'a> Fn(&'a [u8]) -> Result<&'a O, CE>,
    A: for<'a> Fn(<O as ToOwned>::Owned, &O) -> <O as ToOwned>::Owned,
    CE: Send + Sync + std::error::Error + 'static,
    O: ToOwned + ?Sized,
    O::Owned: Default,
{
    fn parse_next(
        &mut self,
        input: &mut &'i [u8],
    ) -> winnow::Result<Cow<'i, O>, ErrMode<ContextError>> {
        match self.len {
            Some(n) => take(n)
                .try_map(|b| (self.conv)(b).map(Cow::Borrowed))
                .parse_next(input),
            None => {
                let mut res = O::Owned::default();
                while let Ok(chunk_hd) = head
                    .verify(|h| h.0 == self.major_type && h.2.is_some())
                    .parse_next(input)
                {
                    res = (self.acc)(
                        res,
                        (self.conv)(take(chunk_hd.2.unwrap()).parse_next(input)?)
                            .map_err(|_| ErrMode::Backtrack(ContextError::new()))?,
                    );
                }
                stop_code.parse_next(input)?;

                Ok(Cow::Owned(res))
            }
        }
    }
}

fn repeat_exact_or_until_break<P, O, E, A>(
    len: Option<u64>,
    parse_next: P,
) -> RepeatExcactOrUntilBreak<P, O, E, A> {
    RepeatExcactOrUntilBreak {
        len,
        next: parse_next,
        marker: PhantomData,
    }
}

struct RepeatExcactOrUntilBreak<ParseNext, Output, Error, Accumulate> {
    len: Option<u64>,
    next: ParseNext,
    marker: PhantomData<(Output, Error, Accumulate)>,
}

impl<'i, ParseNext, Output, Acc> Parser<&'i [u8], Acc, ErrMode<ContextError>>
    for RepeatExcactOrUntilBreak<ParseNext, Output, ErrMode<ContextError>, Acc>
where
    ParseNext: Parser<&'i [u8], Output, ErrMode<ContextError>>,
    Acc: Accumulate<Output>,
{
    fn parse_next(&mut self, input: &mut &'i [u8]) -> winnow::Result<Acc, ErrMode<ContextError>> {
        let p = |i: &mut &'i [u8]| self.next.parse_next(i);
        match self.len {
            Some(n) => repeat(n as usize, p).parse_next(input),
            None => terminated(repeat(.., p), stop_code).parse_next(input),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::array;
    use std::collections::BTreeMap;

    use super::*;
    // https://www.rfc-editor.org/info/rfc8949/#section-3.1
    #[test]
    fn positive_integer() {
        assert_eq!(data_item.parse(&[0b000_01010]), Ok(DataItem::Positive(10)));
        assert_eq!(
            data_item.parse(&[0b000_11001, 0x01, 0xf4]),
            Ok(DataItem::Positive(500))
        );
    }

    #[test]
    fn negative_integer() {
        assert_eq!(
            data_item.parse(&[0b001_11001, 0x01, 0xf3]),
            Ok(DataItem::Negative(499))
        );
    }

    #[test]
    fn byte_string() {
        assert_eq!(
            data_item.parse(&[0b010_00101, 1, 2, 3, 4, 5]),
            Ok(DataItem::ByteString(Cow::Borrowed(&[1, 2, 3, 4, 5])))
        );
        assert_eq!(
            data_item.parse(&array::from_fn::<u8, 503, _>(|i| match i {
                0 => 0b010_11001,
                1 => 0x01,
                2 => 0xf4,
                i => ((i - 3) % 256).try_into().unwrap(),
            })),
            Ok(DataItem::ByteString(Cow::Borrowed(&array::from_fn::<
                u8,
                500,
                _,
            >(|i| {
                (i % 256).try_into().unwrap()
            }))))
        );
    }

    #[test]
    fn text_string() {
        assert_eq!(
            data_item.parse(&[0b011_00101, 104, 101, 108, 108, 111]),
            Ok(DataItem::TextString("hello".into()))
        );
    }

    #[test]
    fn array() {
        assert_eq!(
            data_item.parse(&[
                0b100_00010, // array initial byte
                0b000_11000, // int initial byte
                42,          // int value
                0b011_00010, // string initial byte
                0x34,        // '4'
                0x32         // '2'
            ]),
            Ok(DataItem::Array(vec![
                DataItem::Positive(42),
                DataItem::TextString("42".into())
            ]))
        );
    }

    #[test]
    fn map() {
        assert_eq!(
            data_item.parse(&[
                0b101_00001, // map initial byte
                0b000_11000, // key initial byte
                42,          // int value
                0b011_00010, // value initial byte
                0x34,        // '4'
                0x32         // '2'
            ]),
            Ok(DataItem::Map(BTreeMap::from_iter(vec![(
                DataItem::Positive(42),
                DataItem::TextString("42".into())
            )])))
        );
    }

    #[test]
    fn tagged() {
        assert_eq!(
            data_item.parse(&[
                0b110_01010, // tag
                0b000_11000, // content initial byte
                42,          // int value
            ]),
            Ok(DataItem::Tagged {
                tag: 10,
                content: Box::new(DataItem::Positive(42))
            })
        );
    }

    #[test]
    fn indefinite_array() {
        // https://www.rfc-editor.org/info/rfc8949/#section-3.2.2
        // [1, [2, 3], [4, 5]]
        use DataItem::*;
        let test_arr = Ok(Array(vec![
            Positive(1),
            Array(vec![Positive(2), Positive(3)]),
            Array(vec![Positive(4), Positive(5)]),
        ]));
        // 0x9f 01 82 02 03 9f 04 05 ff ff
        assert_eq!(
            data_item.parse(&[0x9f, 0x01, 0x82, 0x02, 0x03, 0x9f, 0x04, 0x05, 0xff, 0xff]),
            test_arr
        );
        // 0x9f 01 82 02 03 82 04 05 ff
        assert_eq!(
            data_item.parse(&[0x9f, 0x01, 0x82, 0x02, 0x03, 0x82, 0x04, 0x05, 0xff]),
            test_arr
        );
        // 0x83 01 82 02 03 9f 04 05 ff
        assert_eq!(
            data_item.parse(&[0x83, 0x01, 0x82, 0x02, 0x03, 0x9f, 0x04, 0x05, 0xff]),
            test_arr
        );
        // 0x83 01 9f 02 03 ff 82 04 05
        assert_eq!(
            data_item.parse(&[0x83, 0x01, 0x9f, 0x02, 0x03, 0xff, 0x82, 0x04, 0x05]),
            test_arr
        );

        // 0xbf 63 46 75 6e f5 63 41 6d 74 21 ff
        // BF           -- Start indefinite-length map
        // 63        -- First key, UTF-8 string length 3
        //   46756e --   "Fun"
        // F5        -- First value, true
        // 63        -- Second key, UTF-8 string length 3
        //   416d74 --   "Amt"
        // 21        -- Second value, -2
        // FF        -- "break"
        assert_eq!(
            data_item.parse(&[
                0xbf, 0x63, 0x46, 0x75, 0x6e, 0xf5, 0x63, 0x41, 0x6d, 0x74, 0x21, 0xff
            ]),
            Ok(Map(BTreeMap::from_iter(vec![
                (TextString("Fun".into()), True),
                (TextString("Amt".into()), Negative(1))
            ])))
        )
    }

    #[test]
    fn indefinite_string() {
        // https://www.rfc-editor.org/info/rfc8949/#section-3.2.3
        assert_eq!(
            data_item.parse(&[
                0b010_11111,
                0b010_00100,
                0xaa,
                0xbb,
                0xcc,
                0xdd,
                0b010_00011,
                0xee,
                0xff,
                0x99,
                0b111_11111
            ]),
            Ok(DataItem::ByteString(Cow::Borrowed(&[
                0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x99
            ])))
        );
    }
}
