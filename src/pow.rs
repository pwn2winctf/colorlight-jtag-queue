use crate::hashcash::{HashcashError, Token};
use bloomfilter::Bloom;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use hmac::{Hmac, Mac, NewMac};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use sha3::Sha3_256;
use std::collections::HashMap;
use std::env::var;
use std::sync::{Arc, RwLock};
use std::{io::Cursor, time::SystemTime};
use thiserror::Error;

lazy_static! {
    static ref POW_SKIP_VALIDATION: bool = var("POW_SKIP_VALIDATION").unwrap().parse().unwrap();
    static ref TOKEN_TIMEOUT: u64 = var("TOKEN_TIMEOUT").unwrap().parse().unwrap();
    static ref POW_DIFFICULTY: u32 = var("POW_DIFFICULTY").unwrap().parse().unwrap();
    static ref SECRET_KEY: Vec<u8> = var("SECRET_KEY").unwrap().into_bytes();
    static ref BITMAP_BYTES_PER_SEC: usize = var("BITMAP_BYTES_PER_SEC").unwrap().parse().unwrap();
    static ref EXPECT_ITEMS_PER_SEC: usize = var("EXPECT_ITEMS_PER_SEC").unwrap().parse().unwrap();
}

#[derive(Error, Debug)]
pub enum PoWError {
    #[error("token not generated by this server")]
    InvalidToken,
    #[error("token expired since epoch {0}")]
    ExpiredToken(u64),
    #[error("token already spent")]
    DoubleSpend,
    #[error("hashcash error: {0}")]
    HashcashError(#[from] HashcashError),
    #[error("rwlock error")]
    RwLockError,
}

fn time() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

type HmacSha3_256 = Hmac<Sha3_256>;

#[derive(Debug, Clone)]
pub struct PoWManager {
    pub spent_tokens: Arc<RwLock<HashMap<u64, Bloom<String>>>>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct PoWToken {
    expiration: u64,
    command: String,
}

impl PoWManager {
    pub fn new() -> Self {
        PoWManager {
            spent_tokens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn get_token(&self) -> PoWToken {
        let expiration = time() + *TOKEN_TIMEOUT;
        let mut buf = vec![];
        buf.write_u64::<LittleEndian>(expiration).unwrap();
        let mut mac = HmacSha3_256::new_from_slice(SECRET_KEY.as_slice()).unwrap();
        mac.update(buf.as_slice());
        buf.extend(mac.finalize().into_bytes());
        PoWToken {
            expiration,
            command: format!(
                "hashcash -Cmb{} {}",
                *POW_DIFFICULTY,
                base64::encode_config(buf, base64::URL_SAFE)
            ),
        }
    }

    pub fn validate_token(&self, token: &str) -> Result<(), PoWError> {
        if *POW_SKIP_VALIDATION {
            return Ok(());
        }

        // Validate hashcash PoW
        let tk = Token::from_str(token)?;
        if tk.bits != *POW_DIFFICULTY {
            return Err(PoWError::InvalidToken);
        }
        tk.check()?;
        let remounted_token = tk.to_string();

        // Validate resource was generated by this server and is not expired
        let buf = base64::decode_config(&tk.resource, base64::URL_SAFE)
            .or(Err(PoWError::InvalidToken))?;
        let (data, tag) = buf.as_slice().split_at(8);
        let mut rdr = Cursor::new(data);
        let expiration = rdr
            .read_u64::<LittleEndian>()
            .or(Err(PoWError::InvalidToken))?;
        let ts = time();
        if ts > expiration {
            return Err(PoWError::ExpiredToken(expiration));
        }
        if expiration >= ts + *TOKEN_TIMEOUT {
            return Err(PoWError::InvalidToken);
        }
        let mut mac = HmacSha3_256::new_from_slice(SECRET_KEY.as_slice()).unwrap();
        mac.update(data);
        mac.verify(tag).or(Err(PoWError::InvalidToken))?;

        // Validate token is not double spent
        let mut tokens = self.spent_tokens.write().or(Err(PoWError::RwLockError))?;
        let bloom = tokens
            .entry(expiration)
            .or_insert(Bloom::new(*BITMAP_BYTES_PER_SEC, *EXPECT_ITEMS_PER_SEC));
        let exists_bloom = bloom.check(&remounted_token);
        bloom.set(&remounted_token);

        // collect garbage
        let expired_keys: Vec<u64> = tokens
            .iter()
            .filter(|&(&k, _)| k < ts)
            .map(|(&k, _)| k)
            .collect();
        for k in expired_keys {
            tokens.remove(&k);
        }

        if exists_bloom {
            return Err(PoWError::DoubleSpend);
        }

        Ok(())
    }
}
