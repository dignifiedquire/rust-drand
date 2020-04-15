use time::{Duration, OffsetDateTime};

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use threshold::sig::{Scheme, ThresholdScheme};

use crate::dkg;
use crate::key;

/// Manages beacon generation and responding to network requests.
#[derive(Debug)]
pub struct Handler {
    /// Stores the historic data of the beacons.
    store: sled::Db,
    config: HandlerConfig,
    /// Index in the group of the node running this beacon.
    index: usize,
}

/// Configuration for the [Handler].
#[derive(Debug)]
pub struct HandlerConfig {
    pub share: dkg::Share,
    pub private_key: key::Pair,
    pub group: key::Group,
    pub wait_time: Duration,
}

impl Handler {
    pub fn new(store: sled::Db, config: HandlerConfig) -> Result<Self> {
        let index = config
            .group
            .index(config.private_key.public())
            .ok_or_else(|| anyhow!("keypair not included in teh given group"))?;

        Ok(Self {
            store,
            config,
            index,
        })
    }
}

/// The randomness and the info to verify it.
#[derive(Debug, PartialEq, Eq)]
pub struct Beacon {
    /// The previous round this beacon points to.
    ///
    /// The beacon chain can have gaps if the network has been down for a while. The rule
    /// here is that one round corresponds to one exact time given a genesis time.
    previous_round: Round,
    /// The signature from the previous round.
    previous_signature: Vec<u8>,
    /// The current round number of this beacon.
    round: Round,
    /// The BLS signature over `round || previous_randomnes`
    signature: Vec<u8>,
}

impl Beacon {
    /// Returns the hashed signature.
    pub fn randomness(&self) -> Vec<u8> {
        Sha256::digest(&self.signature).as_ref().to_vec()
    }

    /// Verifies this beacon with the provided public key.
    pub fn verify(&self, public_key: &<dkg::Scheme as Scheme>::Public) -> Result<()> {
        let msg = self.message();

        <dkg::Scheme as ThresholdScheme>::verify(public_key, &msg, &self.signature)
            .map_err(|err| anyhow!("invalid beacon: {}", err))?;

        Ok(())
    }

    /// The message that is actually signed and verified.
    ///
    /// Currently: `Sha256(previous_round || previous_signature || round)`.
    pub fn message(&self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.input(&self.previous_round.to_bytes());
        hasher.input(&self.previous_signature);
        hasher.input(&self.round.to_bytes());
        hasher.result().as_ref().to_vec()
    }
}

/// A specific round in the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Round(u64);

impl Round {
    /// Returns the round as its byte representation.
    pub fn to_bytes(self) -> [u8; 8] {
        self.0.to_be_bytes()
    }

    /// Returns the the time this round should happen.
    pub fn time(self, period: Duration, genesis: OffsetDateTime) -> OffsetDateTime {
        assert!(period.is_positive(), "invalid negative duration");
        if self.0 == 0 {
            return genesis;
        }

        // - 1 because genesis time is for 1s round already
        let elapsed = period.whole_seconds() as u64 * (self.0 - 1);
        genesis + Duration::seconds(elapsed as i64)
    }

    pub fn next(period: Duration, genesis: OffsetDateTime) -> Self {
        assert!(period.is_positive(), "invalid negative period");
        let now = Self::now();
        dbg!(now, period, genesis);

        if now < genesis {
            dbg!("earlier");
            return Round(1);
        }

        let from_genesis = now.timestamp() - genesis.timestamp();
        dbg!(from_genesis, from_genesis as f64 / period.as_seconds_f64());
        // we take the time from genesis divided by the periods in seconds, that
        // gives us the number of periods since genesis. We add +1 since we want the
        // next round. We also add +1 because round 1 starts at genesis time.
        let round = (from_genesis as f64 / period.as_seconds_f64()).floor() as u64 + 1;
        Round(round as u64 + 1)
    }

    #[cfg(not(test))]
    fn now() -> OffsetDateTime {
        OffsetDateTime::now()
    }

    #[cfg(test)]
    fn now() -> OffsetDateTime {
        TEST_CLOCK.with(|t| OffsetDateTime::from_unix_timestamp(*t.borrow()))
    }
}

#[cfg(test)]
thread_local!(static TEST_CLOCK: std::cell::RefCell<i64> = std::cell::RefCell::new(0));

impl From<u64> for Round {
    fn from(val: u64) -> Self {
        Round(val)
    }
}

impl From<Round> for u64 {
    fn from(val: Round) -> Self {
        val.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::NumericalDuration;

    #[test]
    fn test_next_round() {
        let start = OffsetDateTime::now().timestamp();
        TEST_CLOCK.with(|t| *t.borrow_mut() = start);

        // start in 1 second
        let genesis = OffsetDateTime::from_unix_timestamp(start) + 1.seconds();
        let period = 2.seconds();

        // round 2 at t = 1
        TEST_CLOCK.with(|t| *t.borrow_mut() += 1);
        let round = Round::next(period, genesis);
        let round_time = round.time(period, genesis);

        assert_eq!(round, 2.into());
        let exp_time = genesis + period;
        assert_eq!(round_time, exp_time);

        // move to one second
        TEST_CLOCK.with(|t| *t.borrow_mut() += 1);
        let nround = Round::next(period, genesis);
        let nround_time = round.time(period, genesis);

        assert_eq!(nround, round);
        assert_eq!(nround_time, round_time);

        // move to next round
        TEST_CLOCK.with(|t| *t.borrow_mut() += 1);
        let round = Round::next(period, genesis);
        let round_time = round.time(period, genesis);

        assert_eq!(round, 3.into());
        let exp_time = genesis + period + period;
        assert_eq!(round_time, exp_time);
    }
}
