use crate::contract::{Code, DEPTH_LIMIT};
use num_bigint::BigInt;
use std::{cmp::Ordering, collections::BTreeMap};

pub(crate) type Object = BTreeMap<String, Value>;

/// Compact JSON whose values already have representable JSON types. The
/// destination is memory, so encoding has no recoverable writer error.
pub(crate) trait Encode {
    fn encode(&self, out: &mut Vec<u8>);
}

impl Encode for str {
    fn encode(&self, out: &mut Vec<u8>) {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        out.push(b'"');
        for &byte in self.as_bytes() {
            let escape = match byte {
                b'"' => b'"',
                b'\\' => b'\\',
                0x08 => b'b',
                0x09 => b't',
                0x0a => b'n',
                0x0c => b'f',
                0x0d => b'r',
                0x00..=0x1f => {
                    out.extend_from_slice(&[
                        b'\\',
                        b'u',
                        b'0',
                        b'0',
                        HEX[(byte >> 4) as usize],
                        HEX[(byte & 0x0f) as usize],
                    ]);
                    continue;
                }
                _ => {
                    out.push(byte);
                    continue;
                }
            };
            out.extend_from_slice(&[b'\\', escape]);
        }
        out.push(b'"');
    }
}

impl Encode for String {
    fn encode(&self, out: &mut Vec<u8>) {
        self.as_str().encode(out);
    }
}

impl Encode for bool {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(if *self { b"true" } else { b"false" });
    }
}

impl Encode for usize {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.to_string().as_bytes());
    }
}

impl Encode for u64 {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(self.to_string().as_bytes());
    }
}

impl<T: Encode> Encode for Option<T> {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Some(value) => value.encode(out),
            None => out.extend_from_slice(b"null"),
        }
    }
}

impl<T: Encode> Encode for [T] {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(b'[');
        for (index, value) in self.iter().enumerate() {
            if index != 0 {
                out.push(b',');
            }
            value.encode(out);
        }
        out.push(b']');
    }
}

impl<T: Encode> Encode for Vec<T> {
    fn encode(&self, out: &mut Vec<u8>) {
        self.as_slice().encode(out);
    }
}

pub(crate) struct ObjectEncoder<'a> {
    out: &'a mut Vec<u8>,
    first: bool,
}

impl<'a> ObjectEncoder<'a> {
    pub(crate) fn new(out: &'a mut Vec<u8>) -> Self {
        out.push(b'{');
        Self { out, first: true }
    }

    pub(crate) fn field(&mut self, name: &str, value: &(impl Encode + ?Sized)) {
        if !self.first {
            self.out.push(b',');
        }
        self.first = false;
        name.encode(self.out);
        self.out.push(b':');
        value.encode(self.out);
    }

    pub(crate) fn finish(self) {
        self.out.push(b'}');
    }
}

#[derive(Debug)]
pub(crate) enum Value {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Value>),
    Object(Object),
}

impl Value {
    pub(crate) fn object(&self) -> Option<&Object> {
        if let Self::Object(value) = self {
            Some(value)
        } else {
            None
        }
    }

    pub(crate) fn string(&self) -> Option<&str> {
        if let Self::String(value) = self {
            Some(value)
        } else {
            None
        }
    }

    pub(crate) fn array(&self) -> Option<&[Self]> {
        if let Self::Array(value) = self {
            Some(value)
        } else {
            None
        }
    }

    pub(crate) fn number(&self) -> Option<&str> {
        if let Self::Number(value) = self {
            Some(value)
        } else {
            None
        }
    }

    pub(crate) fn equal(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Null, Self::Null) => true,
            (Self::Bool(a), Self::Bool(b)) => a == b,
            (Self::Number(a), Self::Number(b)) => Decimal::new(a).cmp(&Decimal::new(b)).is_eq(),
            (Self::String(a), Self::String(b)) => a == b,
            (Self::Array(a), Self::Array(b)) => {
                a.len() == b.len() && a.iter().zip(b).all(|(a, b)| a.equal(b))
            }
            (Self::Object(a), Self::Object(b)) => {
                a.len() == b.len()
                    && a.iter()
                        .zip(b)
                        .all(|((ak, a), (bk, b))| ak == bk && a.equal(b))
            }
            _ => false,
        }
    }
}

impl Encode for Value {
    fn encode(&self, out: &mut Vec<u8>) {
        match self {
            Self::Null => out.extend_from_slice(b"null"),
            Self::Bool(value) => value.encode(out),
            Self::Number(value) => out.extend_from_slice(value.as_bytes()),
            Self::String(value) => value.encode(out),
            Self::Array(items) => items.as_slice().encode(out),
            Self::Object(fields) => {
                let mut object = ObjectEncoder::new(out);
                for (key, value) in fields {
                    object.field(key, value);
                }
                object.finish();
            }
        }
    }
}

/// Exact decimal with a signed, unbounded power of ten. Comparing values never
/// expands the exponent to a string of zeroes.
pub(crate) struct Decimal {
    sign: i8,
    digits: Vec<u8>,
    exponent: BigInt,
}

impl Decimal {
    pub(crate) fn new(token: &str) -> Self {
        let (sign, token) = token
            .strip_prefix('-')
            .map_or((1, token), |rest| (-1, rest));
        let (mantissa, power) = token.split_once(['e', 'E']).unwrap_or((token, "0"));
        let fraction = mantissa
            .split_once('.')
            .map_or(0, |(_, fraction)| fraction.len());
        let digits: Vec<_> = mantissa.bytes().filter(u8::is_ascii_digit).collect();
        let start = digits.iter().position(|d| *d != b'0');
        let Some(start) = start else {
            return Self {
                sign: 0,
                digits: Vec::new(),
                exponent: BigInt::ZERO,
            };
        };
        let end = digits.iter().rposition(|d| *d != b'0').unwrap() + 1;
        let exponent = power.parse::<BigInt>().expect("token was parsed as JSON") - fraction
            + (digits.len() - end);
        Self {
            sign,
            digits: digits[start..end].to_vec(),
            exponent,
        }
    }

    pub(crate) fn integer(&self) -> bool {
        self.exponent >= BigInt::ZERO
    }
    pub(crate) fn nonnegative(&self) -> bool {
        self.sign >= 0
    }

    pub(crate) fn to_u64(&self) -> Option<u64> {
        if self.sign == 0 {
            return Some(0);
        }
        if !self.nonnegative() {
            return None;
        }
        let zeros = usize::try_from(&self.exponent).ok()?;
        if zeros.checked_add(self.digits.len())? > 20 {
            return None;
        }
        self.digits
            .iter()
            .copied()
            .chain(std::iter::repeat_n(b'0', zeros))
            .try_fold(0_u64, |acc, digit| {
                acc.checked_mul(10)?.checked_add(u64::from(digit - b'0'))
            })
    }

    pub(crate) fn cmp(&self, other: &Self) -> Ordering {
        let sign = self.sign.cmp(&other.sign);
        if !sign.is_eq() || self.sign == 0 {
            return sign;
        }
        let left = &self.exponent + self.digits.len();
        let right = &other.exponent + other.digits.len();
        let size = self.digits.len().max(other.digits.len());
        let order = left.cmp(&right).then_with(|| {
            self.digits
                .iter()
                .copied()
                .chain(std::iter::repeat(b'0'))
                .take(size)
                .cmp(
                    other
                        .digits
                        .iter()
                        .copied()
                        .chain(std::iter::repeat(b'0'))
                        .take(size),
                )
        });
        if self.sign < 0 {
            order.reverse()
        } else {
            order
        }
    }
}

#[derive(Debug)]
pub(crate) struct Error {
    pub(crate) code: Code,
    pub(crate) offset: usize,
}

pub(crate) fn parse(bytes: &[u8]) -> Result<Value, Error> {
    let input = std::str::from_utf8(bytes).map_err(|e| Error {
        code: Code::InvalidUtf8,
        offset: e.valid_up_to(),
    })?;
    let mut parser = Parser { input, position: 0 };
    let value = parser.value(0)?;
    parser.whitespace();
    if parser.position != input.len() {
        return Err(parser.error(Code::InvalidJson));
    }
    Ok(value)
}

struct Parser<'a> {
    input: &'a str,
    position: usize,
}

fn decode_quoted(token: &str, end: usize) -> Result<String, Error> {
    serde_json::from_str(token).map_err(|_| Error {
        code: Code::InvalidJson,
        offset: end,
    })
}

impl Parser<'_> {
    fn error(&self, code: Code) -> Error {
        Error {
            code,
            offset: self.position,
        }
    }

    fn next(&self) -> Option<u8> {
        self.input.as_bytes().get(self.position).copied()
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.next() == Some(byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn whitespace(&mut self) {
        while matches!(self.next(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.position += 1;
        }
    }

    fn expect(&mut self, byte: u8) -> Result<(), Error> {
        if self.consume(byte) {
            Ok(())
        } else {
            Err(self.error(Code::InvalidJson))
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, Error> {
        self.whitespace();
        let value = match self.next() {
            Some(b'{' | b'[') if depth >= DEPTH_LIMIT => return Err(self.error(Code::LimitDepth)),
            Some(b'{') => self.object(depth + 1)?,
            Some(b'[') => self.array(depth + 1)?,
            Some(b'"') => Value::String(self.string()?),
            Some(b'n') => {
                self.literal(b"null")?;
                Value::Null
            }
            Some(b't') => {
                self.literal(b"true")?;
                Value::Bool(true)
            }
            Some(b'f') => {
                self.literal(b"false")?;
                Value::Bool(false)
            }
            Some(b'-' | b'0'..=b'9') => Value::Number(self.number()?),
            _ => return Err(self.error(Code::InvalidJson)),
        };
        Ok(value)
    }

    fn literal(&mut self, literal: &[u8]) -> Result<(), Error> {
        for byte in literal {
            self.expect(*byte)?;
        }
        Ok(())
    }

    fn object(&mut self, depth: usize) -> Result<Value, Error> {
        self.position += 1;
        self.whitespace();
        let mut object = BTreeMap::new();
        if !self.consume(b'}') {
            loop {
                self.whitespace();
                let position = self.position;
                let key = self.string()?;
                if object.contains_key(&key) {
                    return Err(Error {
                        code: Code::DuplicateKey,
                        offset: position,
                    });
                }
                self.whitespace();
                self.expect(b':')?;
                object.insert(key, self.value(depth)?);
                self.whitespace();
                if self.consume(b'}') {
                    break;
                }
                self.expect(b',')?;
            }
        }
        Ok(Value::Object(object))
    }

    fn array(&mut self, depth: usize) -> Result<Value, Error> {
        self.position += 1;
        self.whitespace();
        let mut array = Vec::new();
        if !self.consume(b']') {
            loop {
                array.push(self.value(depth)?);
                self.whitespace();
                if self.consume(b']') {
                    break;
                }
                self.expect(b',')?;
            }
        }
        Ok(Value::Array(array))
    }

    fn digits(&mut self) -> Result<(), Error> {
        let start = self.position;
        while matches!(self.next(), Some(b'0'..=b'9')) {
            self.position += 1;
        }
        if self.position > start {
            Ok(())
        } else {
            Err(self.error(Code::InvalidJson))
        }
    }

    fn number(&mut self) -> Result<String, Error> {
        let start = self.position;
        self.consume(b'-');
        if !self.consume(b'0') {
            self.digits()?;
        }
        if self.consume(b'.') {
            self.digits()?;
        }
        if self.consume(b'e') || self.consume(b'E') {
            if !self.consume(b'+') {
                self.consume(b'-');
            }
            self.digits()?;
        }
        Ok(self.input[start..self.position].to_owned())
    }

    fn string(&mut self) -> Result<String, Error> {
        let start = self.position;
        self.expect(b'"')?;
        while let Some(byte) = self.next() {
            match byte {
                b'"' => {
                    self.position += 1;
                    return decode_quoted(&self.input[start..self.position], self.position);
                }
                0..=31 => return Err(self.error(Code::InvalidJson)),
                b'\\' => {
                    self.escape()?;
                    continue;
                }
                _ => {}
            }
            self.position += 1;
        }
        Err(self.error(Code::InvalidJson))
    }

    fn escape(&mut self) -> Result<(), Error> {
        let start = self.position;
        self.position += 1;
        match self.next() {
            Some(b'"' | b'\\' | b'/' | b'b' | b'f' | b'n' | b'r' | b't') => {
                self.position += 1;
            }
            Some(b'u') => {
                self.position += 1;
                match self.hex_code_unit()? {
                    0xd800..=0xdbff => {
                        let low_start = self.position;
                        self.expect(b'\\')?;
                        self.expect(b'u')?;
                        if !(0xdc00..=0xdfff).contains(&self.hex_code_unit()?) {
                            return Err(Error {
                                code: Code::InvalidJson,
                                offset: low_start,
                            });
                        }
                    }
                    0xdc00..=0xdfff => {
                        return Err(Error {
                            code: Code::InvalidJson,
                            offset: start,
                        });
                    }
                    _ => (),
                }
            }
            _ => return Err(self.error(Code::InvalidJson)),
        }
        Ok(())
    }

    fn hex_code_unit(&mut self) -> Result<u16, Error> {
        let mut unit = 0;
        for _ in 0..4 {
            let digit = self
                .next()
                .and_then(|byte| char::from(byte).to_digit(16))
                .ok_or_else(|| self.error(Code::InvalidJson))?;
            unit = unit * 16 + digit as u16;
            self.position += 1;
        }
        Ok(unit)
    }
}

pub(crate) fn pointer(parent: &str, key: &str) -> String {
    format!("{parent}/{}", key.replace('~', "~0").replace('/', "~1"))
}
