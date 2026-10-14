//! https://www.rfc-editor.org/info/rfc8949/

use std::{
    borrow::Cow,
    cmp::Ordering,
    collections::BTreeMap,
    hash::{Hash, Hasher},
};

/// https://www.rfc-editor.org/info/rfc8949/#section-2
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Clone)]
pub enum DataItem<'i> {
    // Basic
    Positive(u64),
    Negative(u64),
    Simple(u8),
    F32(Total<f32>),
    F64(Total<f64>),
    ByteString(Cow<'i, [u8]>),
    TextString(Cow<'i, str>),
    Array(Vec<DataItem<'i>>),
    Map(BTreeMap<DataItem<'i>, DataItem<'i>>),
    Tagged {
        tag: u64,
        content: Box<DataItem<'i>>,
    },
    // Extended
    True,
    False,
    Null,
    Undefined,
}

#[derive(Debug, Clone, Copy)]
pub struct Total<T>(T);

impl<T> Total<T> {
    pub fn new(t: T) -> Self {
        Self(t)
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

macro_rules! total_impl {
    ($type:ty) => {
        impl Total<$type> {
            fn canonical(self) -> $type {
                if self.0.is_nan() {
                    <$type>::NAN
                } else if self.0 == 0. {
                    0.
                } else {
                    self.0
                }
            }
        }
        impl Ord for Total<$type> {
            fn cmp(&self, other: &Self) -> Ordering {
                self.canonical().total_cmp(&other.canonical())
            }
        }
        impl PartialOrd for Total<$type> {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }
        impl PartialEq for Total<$type> {
            fn eq(&self, other: &Self) -> bool {
                self.cmp(other) == Ordering::Equal
            }
        }
        impl Eq for Total<$type> {}
        impl Hash for Total<$type> {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.canonical().to_bits().hash(state);
            }
        }
    };
}

total_impl!(f32);
total_impl!(f64);
