//! This module holds the curve to use for the example. One can switch the curve
//! by changing the exported type `Curve`.

pub use threshold::curve::bls12381::{Curve as G1Curve, PairingCurve as Pairing};
use threshold::group::Curve;
use threshold::sig::tbls::TG1Scheme;

pub type KeyCurve = G1Curve;
pub type PrivateKey = <KeyCurve as Curve>::Scalar;
pub type PublicKey = <KeyCurve as Curve>::Point;
/// The signature scheme used for signing and verifying the randomness.
pub type Scheme = TG1Scheme<Pairing>;
