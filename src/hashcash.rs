//! Rust implementation of hashcash anti-spam / denial of service
//! counter-measure tool.

use base64::{decode, encode_config};
use chrono::prelude::*;
use chrono::Duration;
use sha1::{Digest, Sha1};
use thiserror::Error;

const DATE_FMT: &str = "%y%m%d";

/// Stores a destructured hashcash token by its various components.
#[derive(Debug, PartialEq)]
pub struct Token {
    pub ver: u8,
    pub bits: u32,
    pub date: NaiveDate,
    pub resource: String,
    pub ext: String,
    pub rand: Vec<u8>,
    pub counter: Vec<u8>,
}

/// Various error types that are used during the validation of a
/// `hashcash::Token`.
#[derive(Error, Debug)]
pub enum HashcashError {
    #[error("date is older than two days")]
    ExpiryError,
    #[error("hash does not satisfy declared difficulty bits")]
    DifficultyError,
    #[error("parse error")]
    ParseError(&'static str),
}

impl Token {
    /// Given a fully qualified hashcash token string, returns a parsed version
    /// of the input.
    /// ```
    /// use hashcash::Token;
    ///
    /// let t = "1:4:180606:example::OfZIJujxSu6ojd08LI0hLg:AAHz1w";
    /// let token = Token::from_str(t).unwrap();
    ///
    /// println!("{:?}", token);
    /// ```
    pub fn from_str(stamp: &str) -> Result<Token, HashcashError> {
        let stamp_string = stamp.to_string();
        let stamp_parts: Vec<&str> = stamp_string.split(":").collect();

        if stamp_parts.len() != 7 {
            return Err(HashcashError::ParseError("Invalid number of parameters"));
        }

        let ver = match stamp_parts[0].parse::<u8>() {
            Ok(n) => n,
            Err(_) => {
                return Err(HashcashError::ParseError("Invalid version specifier"));
            }
        };
        let bits = match stamp_parts[1].parse::<u32>() {
            Ok(n) => n,
            Err(_) => {
                return Err(HashcashError::ParseError("Invalid difficulty specifier"));
            }
        };
        let date = match NaiveDate::parse_from_str(stamp_parts[2], DATE_FMT) {
            Ok(d) => d,
            Err(_) => {
                return Err(HashcashError::ParseError("Invalid date specifier"));
            }
        };
        let rand = match decode(stamp_parts[5]) {
            Ok(v) => v,
            Err(_) => {
                return Err(HashcashError::ParseError("Invalid base64 random string"));
            }
        };
        let counter = match decode(stamp_parts[6]) {
            Ok(v) => v,
            Err(_) => {
                return Err(HashcashError::ParseError("Invalid base64 counter string"));
            }
        };

        Ok(Token {
            ver,
            bits,
            date,
            resource: stamp_parts[3].to_string(),
            ext: stamp_parts[4].to_string(),
            rand,
            counter,
        })
    }

    /// Validates the `hashcash::Token`, returning any validation errors if
    /// not valid.
    ///
    /// ```
    /// use hashcash::Token;
    ///
    /// let token = "1:4:180606:example::OfZIJujxSu6ojd08LI0hLg:AAHz1w";
    ///
    /// match Token::from_str(token) {
    ///     Ok(t) => {
    ///         match t.check() {
    ///             Ok(_) => println!("OK"),
    ///             Err(e) => eprintln!("{:?}", e),
    ///         }
    ///     },
    ///     Err(e) => eprintln!("{}", e.message)
    /// }
    /// ```
    pub fn check(&self) -> Result<&Self, HashcashError> {
        let mut leading_zeros = 0;
        let mut hasher = Sha1::new();

        hasher.update(&self.to_string());
        let result = hasher.finalize();

        for byte in result {
            let front_zeros = byte.leading_zeros();
            leading_zeros += front_zeros;

            if front_zeros < 8 {
                break;
            }
        }

        if leading_zeros < self.bits {
            return Err(HashcashError::DifficultyError);
        }

        let expires_after = Duration::days(2);
        let time_delta = get_current_naive_date() - self.date;

        if time_delta >= expires_after {
            return Err(HashcashError::ExpiryError);
        }

        Ok(self)
    }

    /// Returns a fully qualified hashcash token string suitable for use as a
    /// `X-Hashcash` header value or otherwise.
    pub fn to_string(&self) -> String {
        let rand = encode_config(&self.rand, base64::STANDARD_NO_PAD);
        let counter = encode_config(&self.counter, base64::STANDARD_NO_PAD);

        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            self.ver.to_string(),
            self.bits.to_string(),
            self.date.format(DATE_FMT),
            self.resource,
            self.ext,
            rand,
            counter
        )
    }
}

fn get_current_naive_date() -> NaiveDate {
    let date = Utc::now().to_rfc3339();
    let date_normalized = DateTime::parse_from_rfc3339(&date).unwrap();

    date_normalized.naive_utc().date()
}
