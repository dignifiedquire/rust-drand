use anyhow::{anyhow, Result};
use async_std::prelude::*;
use async_std::sync::{channel, Receiver, Sender};
use time::{Duration, OffsetDateTime};

use crate::dkg;
use crate::key;

use super::beacon::{self, Beacon, PartialBeacon, Round};

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
    pub dist_public: dkg::DistPublic,
    pub private_key: key::Pair,
    pub group: key::Group,
    pub wait_time: Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BeaconRequest {
    /// Partial beacon, sent out from the pariticipants.
    PartialBeacon(PartialBeacon),
}

// TODO: implement chain sync

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

    /// Run the beacon chain.
    pub async fn start(
        self,
        last_beacon: &Beacon,
        next_round: Round,
        start_time: OffsetDateTime,
        sender: Sender<BeaconRequest>,
        incoming_requests: Receiver<BeaconRequest>,
    ) {
        // TODO: handle sleep time before genesis

        enum Event {
            Tick,
            Beacon(Beacon),
        }

        let (beacon_sender, beacon_receiver) = channel(10);

        let ticker =
            async_std::stream::interval(self.config.group.period().expect("missing period"))
                .map(|_| Event::Tick);
        let incoming = beacon_receiver.map(Event::Beacon);
        let mut events = ticker.merge(incoming);

        let mut current_round = next_round;
        let mut previous_round = last_beacon.round();
        let mut go_to_next_round = true;
        let mut current_round_finished = false;
        let mut previous_signature: Vec<u8> = last_beacon.signature().into();

        // advance the beacon chain
        loop {
            if go_to_next_round {
                // Launch the next round and close the previous operations if they are still running

                self.run_round(
                    current_round,
                    previous_round,
                    previous_signature.clone(),
                    incoming_requests.clone(),
                    beacon_sender.clone(),
                );

                go_to_next_round = false;
                current_round_finished = false;
            }

            while let Some(event) = events.next().await {
                match event {
                    Event::Tick => {
                        if !current_round_finished {
                            // The current round has not finished while the next round is starting.
                            // Increase the round number, but still sign on the current signature.
                            current_round.inc();
                        }

                        // the ticker is king
                        go_to_next_round = true;
                    }
                    Event::Beacon(beacon) => {
                        if beacon.round() != current_round {
                            // an old round that finishes later than supposed to
                            break;
                        }

                        current_round.inc();
                        previous_signature = beacon.signature().into();
                        previous_round = beacon.round();
                        current_round_finished = true;
                        break;
                    }
                }
            }
        }
    }

    fn run_round(
        &self,
        current_round: Round,
        previous_round: Round,
        previous_signature: Vec<u8>,
        incoming: Receiver<BeaconRequest>,
        winner: Sender<Beacon>,
    ) {
        let share = &self.config.share;
        let nodes = self.config.group.identities();
        let threshold = self.config.group.threshold();
        let dist_public = &self.config.dist_public;

        // let (partials_sender, partials_receiver) = channel(10);

        let partial_signature =
            beacon::sign(share, &previous_signature, previous_round, current_round).unwrap(); // TODO: handle error

        let request = BeaconRequest::PartialBeacon(PartialBeacon::new(
            previous_round,
            previous_signature,
            current_round,
            partial_signature,
        ));

        async_std::task::spawn(async move {
            while let Some(req) = incoming.recv().await {
                // TODO: process incoming requests and send the resulting finished beacon to winner
                // send results to partials_sender
            }
        });

        // send out partial beacons of
    }
}
