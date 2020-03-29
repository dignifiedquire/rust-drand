use anyhow::Result;
use bls_signatures::{PrivateKey, PublicKey, Serialize as BlsSerialize};
use serde::de::Deserializer;
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use url::Url;

/// The default threshold is calculated as floor(n * 2/3) + 1
pub fn default_threshold(n: usize) -> usize {
    ((n * 2) as f64 / 3.0).floor() as usize + 1
}

/// Holds the public key.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
#[serde(tag = "tls")]
pub enum Identity {
    Tls {
        #[serde(serialize_with = "serialize_key", deserialize_with = "deserialize_key")]
        public_key: PublicKey,
        address: Url,
    },
    NoTls {
        #[serde(serialize_with = "serialize_key", deserialize_with = "deserialize_key")]
        public_key: PublicKey,
        address: Url,
    },
}

impl Identity {
    pub fn is_tls(&self) -> bool {
        match self {
            Identity::Tls { .. } => true,
            _ => false,
        }
    }

    pub fn public_key(&self) -> &PublicKey {
        match self {
            Identity::Tls { ref public_key, .. } => public_key,
            Identity::NoTls { ref public_key, .. } => public_key,
        }
    }

    pub fn address(&self) -> &Url {
        match self {
            Identity::Tls { ref address, .. } => address,
            Identity::NoTls { ref address, .. } => address,
        }
    }
}

/// Holds a public private keypair.
#[derive(Debug, PartialEq, Clone, Serialize, Deserialize)]
pub struct Pair {
    #[serde(serialize_with = "serialize_key", deserialize_with = "deserialize_key")]
    private_key: PrivateKey,
    public_key: Identity,
}

impl Pair {
    /// Returns a freshly created private / public key pair. Currently, drand only supports Bls12_381.
    pub fn new(url: &Url) -> Result<Self> {
        let private_key = PrivateKey::generate(&mut rand::rngs::OsRng);
        let public_key = private_key.public_key();

        Ok(Pair {
            private_key,
            public_key: Identity::NoTls {
                public_key,
                address: url.clone(),
            },
        })
    }

    /// Returns a fresh keypair associated with the given address reachable over TLS.
    pub fn new_tls(url: &Url) -> Result<Self> {
        let private_key = PrivateKey::generate(&mut rand::rngs::OsRng);
        let public_key = private_key.public_key();

        Ok(Pair {
            private_key,
            public_key: Identity::Tls {
                public_key,
                address: url.clone(),
            },
        })
    }

    /// Returns the private of this key pair.
    pub fn private(&self) -> &PrivateKey {
        &self.private_key
    }

    /// Returns the public part of this key pair.
    pub fn public(&self) -> &Identity {
        &self.public_key
    }
}

fn serialize_key<S, K: BlsSerialize>(key: &K, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let raw = key.as_bytes();
    let value = hex::encode(&raw);

    serializer.serialize_str(&value)
}

fn deserialize_key<'de, D, K: BlsSerialize>(deserializer: D) -> Result<K, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_string: String = Deserialize::deserialize(deserializer)?;
    let bytes =
        hex::decode(&hex_string).map_err(|err| serde::de::Error::custom(err.to_string()))?;
    let res = K::from_bytes(&bytes).map_err(|err| serde::de::Error::custom(err.to_string()))?;

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_public() {
        let addr = Url::parse("http://127.0.0.1:80").unwrap();
        let kp = Pair::new_tls(&addr).unwrap();

        assert_eq!(kp.public().address(), &addr);
        assert!(kp.public().is_tls());

        let toml_str = toml::to_string(&kp).unwrap();
        let kp_ret: Pair = toml::from_str(&toml_str).unwrap();

        assert_eq!(&kp, &kp_ret);

        let toml_pub = toml::to_string(kp.public()).unwrap();
        let pub_ret: Identity = toml::from_str(&toml_pub).unwrap();
        assert_eq!(kp.public(), &pub_ret);
    }
}
