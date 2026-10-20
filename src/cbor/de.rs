use std::{borrow::Cow, fmt::Display};

use serde::{
    Deserialize,
    de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor},
    forward_to_deserialize_any,
};
use thiserror::Error;
use winnow::{Parser, token::rest};

use crate::cbor::{model::DataItem, parse::data_item};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("parse error: {0}")]
    ParseError(String),
    #[error("{0}")]
    Custom(String),
}

impl serde::de::Error for Error {
    fn custom<T>(msg: T) -> Self
    where
        T: Display,
    {
        Self::Custom(msg.to_string())
    }
}

pub struct Deserializer<'de> {
    input: &'de [u8],
}

impl<'de> Deserializer<'de> {
    pub fn from_bytes(input: &'de [u8]) -> Self {
        Self { input }
    }
}

pub fn from_bytes<'de, T>(input: &'de [u8]) -> Result<T, Error>
where
    T: Deserialize<'de>,
{
    let mut deserializer = Deserializer::from_bytes(input);
    let t = T::deserialize(&mut deserializer)?;
    if deserializer.input.is_empty() {
        Ok(t)
    } else {
        Err(Error::custom("traling input bytes"))
    }
}

impl<'de> serde::Deserializer<'de> for &mut Deserializer<'de> {
    type Error = Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let (it, rest) = (data_item, rest)
            .parse(self.input)
            .map_err(|e| Error::ParseError(e.to_string()))?;
        self.input = rest;
        ItemDeserializer(it).deserialize_any(visitor)
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        let (it, rest) = (data_item, rest)
            .parse(self.input)
            .map_err(|e| Error::ParseError(e.to_string()))?;
        self.input = rest;
        ItemDeserializer(it).deserialize_option(visitor)
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes
        byte_buf unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

struct ItemDeserializer<'de>(DataItem<'de>);

impl<'de> serde::Deserializer<'de> for ItemDeserializer<'de> {
    type Error = Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.0 {
            DataItem::Positive(n) => visitor.visit_u64(n),
            DataItem::Negative(n) => match i64::try_from(n) {
                Ok(i) => visitor.visit_i64(-1 - i),
                Err(_) => visitor.visit_i128(-1 - i128::from(n)),
            },
            DataItem::Simple(n) => visitor.visit_u8(n),
            DataItem::F32(total) => visitor.visit_f32(total.into_inner()),
            DataItem::F64(total) => visitor.visit_f64(total.into_inner()),
            DataItem::ByteString(cow) => match cow {
                Cow::Borrowed(s) => visitor.visit_borrowed_bytes(s),
                Cow::Owned(s) => visitor.visit_byte_buf(s),
            },
            DataItem::TextString(cow) => match cow {
                Cow::Borrowed(s) => visitor.visit_borrowed_str(s),
                Cow::Owned(s) => visitor.visit_string(s),
            },
            DataItem::Array(data_items) => visitor.visit_seq(ArrayDeser(data_items.into_iter())),
            DataItem::Map(btree_map) => visitor.visit_map(MapDeser {
                iter: btree_map.into_iter(),
                value: None,
            }),
            DataItem::Tagged { .. } => Err(Error::custom("tagged items are not supported yet")),
            DataItem::True => visitor.visit_bool(true),
            DataItem::False => visitor.visit_bool(false),
            DataItem::Null => visitor.visit_unit(),
            DataItem::Undefined => visitor.visit_unit(),
        }
    }

    fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, Self::Error>
    where
        V: Visitor<'de>,
    {
        match self.0 {
            DataItem::Null | DataItem::Undefined => visitor.visit_none(),
            item => visitor.visit_some(ItemDeserializer(item)),
        }
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 u8 u16 u32 u64 f32 f64 char str string bytes
        byte_buf unit unit_struct newtype_struct seq tuple
        tuple_struct map struct enum identifier ignored_any
    }
}

struct ArrayDeser<I>(I);

impl<'de, I> SeqAccess<'de> for ArrayDeser<I>
where
    I: Iterator<Item = DataItem<'de>>,
{
    type Error = Error;

    fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
    where
        T: DeserializeSeed<'de>,
    {
        self.0
            .next()
            .map(|item| seed.deserialize(ItemDeserializer(item)))
            .transpose()
    }
}

struct MapDeser<'de, I> {
    iter: I,
    value: Option<DataItem<'de>>,
}

impl<'de, I> MapAccess<'de> for MapDeser<'de, I>
where
    I: Iterator<Item = (DataItem<'de>, DataItem<'de>)>,
{
    type Error = Error;

    fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, Self::Error>
    where
        K: DeserializeSeed<'de>,
    {
        match self.iter.next() {
            Some((k, v)) => {
                self.value = Some(v);
                seed.deserialize(ItemDeserializer(k)).map(Some)
            }
            None => Ok(None),
        }
    }

    fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, Self::Error>
    where
        V: DeserializeSeed<'de>,
    {
        let v = self
            .value
            .take()
            .ok_or_else(|| Error::custom("value requested before key"))?;
        seed.deserialize(ItemDeserializer(v))
    }
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    #[test]
    fn deser() {
        // an example from appendix A
        #[derive(Debug, Deserialize, PartialEq, Eq)]
        struct S {
            a: u64,
            b: Vec<u64>,
        }
        let input = [0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x82, 0x02, 0x03];
        assert_eq!(
            super::from_bytes::<S>(&input),
            Ok(S {
                a: 1,
                b: vec![2, 3]
            })
        );
    }
}
