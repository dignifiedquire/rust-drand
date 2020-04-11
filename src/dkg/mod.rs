mod curve;
mod orchestrator;

pub mod board;
pub mod node;

pub type Group = threshold::dkg::Group<self::curve::KeyCurve>;
pub type DkgNode = threshold::dkg::Node<self::curve::KeyCurve>;
pub type Share = threshold::Share<self::curve::PrivateKey>;

pub use self::board::{Board, ProtocolMessage};
pub use self::node::Node;
pub use curve::KeyCurve;
pub use threshold::Index;

use serde::de::Deserializer;
use serde::ser::{SerializeSeq, Serializer};
use serde::{Deserialize, Serialize};
use threshold::group::{Element, Encodable};

/// Wrapper around `threshold::DistPublic` for custom serialization.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DistPublic(
    #[serde(
        serialize_with = "serialize_dist",
        deserialize_with = "deserialize_dist"
    )]
    threshold::DistPublic<self::curve::KeyCurve>,
);

impl From<threshold::DistPublic<self::curve::KeyCurve>> for DistPublic {
    fn from(inner: threshold::DistPublic<self::curve::KeyCurve>) -> Self {
        Self(inner)
    }
}

impl std::ops::Deref for DistPublic {
    type Target = threshold::DistPublic<self::curve::KeyCurve>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

fn serialize_dist<S>(
    dist: &threshold::DistPublic<self::curve::KeyCurve>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let raw: Vec<_> = dist.clone().into();

    let mut seq = serializer.serialize_seq(Some(raw.len()))?;
    for element in raw {
        let value = hex::encode(element.marshal());
        seq.serialize_element(&value)?;
    }
    seq.end()
}

fn deserialize_dist<'de, D>(
    deserializer: D,
) -> Result<threshold::DistPublic<self::curve::KeyCurve>, D::Error>
where
    D: Deserializer<'de>,
{
    let hex_strings: Vec<String> = Deserialize::deserialize(deserializer)?;
    let coeffs = hex_strings
        .iter()
        .map(|s| {
            let bytes = hex::decode(s).map_err(|err| serde::de::Error::custom(err.to_string()))?;
            let mut coeff = self::curve::PublicKey::new();
            coeff
                .unmarshal(&bytes)
                .map_err(|err| serde::de::Error::custom(err.to_string()))?;
            Ok(coeff)
        })
        .collect::<Result<Vec<_>, _>>()?;

    let poly = coeffs.into();

    Ok(poly)
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::curve::KeyCurve;
    use rand::SeedableRng;

    #[test]
    fn test_dist_public() {
        let rng = &mut rand_xorshift::XorShiftRng::seed_from_u64(12);

        for degree in &[0usize, 1, 10, 15] {
            let dist_public: DistPublic =
                threshold::DistPublic::<KeyCurve>::new_from(*degree, rng).into();

            #[derive(Deserialize)]
            struct Values {
                key: DistPublic,
            }
            let toml_str = toml::to_string(&dist_public).unwrap();
            dbg!(&toml_str);

            let dist_public_ret: Values = toml::from_str(&format!("key = {}", toml_str)).unwrap();

            assert_eq!(&dist_public, &dist_public_ret.key);
        }
    }
}
