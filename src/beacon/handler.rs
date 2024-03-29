use anyhow::{anyhow, Result};
use async_std::prelude::*;
use async_std::sync::{channel, Arc, Receiver, Sender};
use log::error;
use threshold::sig::Scheme;
use time::{Duration, OffsetDateTime};

use crate::dkg;
use crate::key;

use super::beacon::{self, Beacon, PartialBeacon, Round};

const DB_BEACON_STORE: &[u8] = b"beacon";
const DB_PARTIAL_BEACON_STORE: &[u8] = b"partial-beacon";

/// Manages beacon generation and responding to network requests.
#[derive(Debug)]
pub struct Handler {
    /// Stores the historic data of the beacons.
    beacon_store: sled::Tree,
    partial_beacon_store: sled::Tree,
    config: Arc<HandlerConfig>,
    /// Index in the group of the node running this beacon.
    index: usize,
}

/// Configuration for the [Handler].
#[derive(Debug)]
pub struct HandlerConfig {
    pub share: dkg::Share,
    pub public_key: <dkg::Scheme as Scheme>::Public,
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

        let beacon_store = store.open_tree(DB_BEACON_STORE)?;
        let partial_beacon_store = store.open_tree(DB_PARTIAL_BEACON_STORE)?;

        Ok(Self {
            beacon_store,
            partial_beacon_store,
            config: Arc::new(config),
            index,
        })
    }

    /// Run the beacon chain.
    pub async fn start(
        self,
        last_beacon: &Beacon,
        next_round: Round,
        start_time: OffsetDateTime,
        outgoing_requests: Sender<BeaconRequest>,
        incoming_requests: Receiver<BeaconRequest>,
    ) {
        // TODO: handle sleep time before genesis

        let store = self.partial_beacon_store.clone();
        async_std::task::spawn(async move {
            while let Some(req) = incoming_requests.recv().await {
                // process incoming requests
                match req {
                    BeaconRequest::PartialBeacon(partial_beacon) => {
                        let res = || -> Result<()> {
                            let mut key = partial_beacon.round().to_bytes().to_vec();
                            key.extend_from_slice(b"-");
                            key.extend_from_slice(&partial_beacon.index()?.to_be_bytes());
                            store.insert(key, &partial_beacon)?;
                            Ok(())
                        };

                        if let Err(err) = res() {
                            error!("failed to process incoming partial beacon: {}", err);
                        }
                    }
                }
            }
        });

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
                    outgoing_requests.clone(),
                    beacon_sender.clone(),
                )
                .await;

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

    async fn run_round(
        &self,
        current_round: Round,
        previous_round: Round,
        previous_signature: Vec<u8>,
        outgoing: Sender<BeaconRequest>,
        winner: Sender<Beacon>,
    ) {
        let threshold = self.config.group.threshold();

        let (partials_sender, partials_receiver) = channel(1);

        let partial_signature = beacon::sign(
            &self.config.share,
            &previous_signature,
            previous_round,
            current_round,
        )
        .unwrap(); // TODO: handle error

        let request = BeaconRequest::PartialBeacon(PartialBeacon::new(
            previous_round,
            previous_signature.clone(),
            current_round,
            partial_signature,
        ));

        // send out partial beacon
        outgoing.send(request.clone()).await;

        let store = self.partial_beacon_store.clone();
        async_std::task::spawn(async move {
            // process incoming partial beacons
            let mut prefix = current_round.to_bytes().to_vec();
            prefix.extend(b"-");

            let mut partials = Vec::with_capacity(threshold);
            let events = store.watch_prefix(&prefix);

            macro_rules! log_err {
                ($res:expr) => {
                    match $res {
                        Ok(res) => res,
                        Err(err) => {
                            error!("{}", err);
                            continue;
                        }
                    }
                };
            }

            // process exsting once
            for value in store.scan_prefix(&prefix).values() {
                let value = log_err!(value);
                let partial_beacon: PartialBeacon = log_err!(serde_cbor::from_slice(&value));
                partials.push(partial_beacon.partial_signature().to_vec());
                if partials.len() >= threshold {
                    break;
                }
            }

            if partials.len() < threshold {
                // process ongoing
                for el in events {
                    match el {
                        sled::Event::Insert(_, value) => {
                            let partial_beacon: PartialBeacon =
                                log_err!(serde_cbor::from_slice(&value));
                            partials.push(partial_beacon.partial_signature().to_vec());
                            if partials.len() >= threshold {
                                break;
                            }
                        }
                        _ => {}
                    }
                }
            } else {
                drop(events);
            }

            partials_sender.send(partials).await;
            drop(partials_sender); // close the channel
        });

        let config = self.config.clone();
        let store = self.beacon_store.clone();
        async_std::task::spawn(async move {
            while let Some(partial_signatures) = partials_receiver.recv().await {
                let beacon = Beacon::aggregate(
                    &config.public_key,
                    config.group.threshold(),
                    &partial_signatures,
                    previous_round,
                    previous_signature.clone(),
                    current_round,
                );

                match beacon {
                    Ok(beacon) => {
                        // store beacon
                        if let Err(err) = store.insert(beacon.round().to_bytes(), &beacon) {
                            error!("failed to store beacon: {}", err);
                        }
                        winner.send(beacon).await;
                    }
                    Err(err) => {
                        error!("failed to aggregate beacon: {}", err);
                    }
                }
            }
        });
    }
}
