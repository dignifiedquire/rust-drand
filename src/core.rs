use std::path::PathBuf;
use std::time::Duration;

pub struct Config {
    pub config_folder: PathBuf,
    pub db_folder: PathBuf,
    pub listen_addr: Option<String>,
    pub control_port: usize,
    // grpc_opts     []grpc.DialOption
    // callOpts     []grpc.CallOption
    pub dkg_timeout: Duration,
    // boltOpts     *bolt.Options
    // beaconCbs    []func(*beacon.Beacon)
    // dkgCallback  func(*key.Share)
    pub insecure: bool,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    // certmanager  *net.CertManager
    // clock        clock.Clock
}
