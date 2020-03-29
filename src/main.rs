#![deny(clippy::all)]

use std::path::PathBuf;

use anyhow::Result;
use humantime::Duration;
use lazy_static::lazy_static;
use log::{info, warn};
use structopt::StructOpt;
use url::Url;

use drand::{
    core, daemon,
    key::{self, Store},
    logger,
};

const DEFAULT_FOLDER_NAME: &str = ".drand";

lazy_static! {
    static ref DEFAULT_TIMEOUT: Duration = std::time::Duration::from_secs(60).into();
}

#[derive(Debug, StructOpt)]
#[structopt(about = "distributed randomness service")]
struct Drand {
    /// Folder to keep all drand cryptographic information, with absolute path.
    #[structopt(long, short = "f", parse(from_os_str))]
    folder: Option<PathBuf>,
    /// Set verbosity to the given level. Level 1 is the info level and level 2 is the debug level. Verbosity is at
    /// the info level by default.
    #[structopt(long, short = "v", default_value = "1")]
    verbose: usize,
    #[structopt(subcommand)]
    cmd: DrandCommand,
}

#[derive(Debug, StructOpt)]
enum DrandCommand {
    /// Start the drand daemon.
    Start {
        /// Set the TLS certificate chain (in PEM format) for this drand node.
        /// The certificates have to be specified as a list of whitespace-separated file paths.
        /// This parameter is required by default and can only be omitted if the --tls-disable flag is used.
        #[structopt(long, short = "c", parse(from_os_str), required_unless = "tls-disable")]
        tls_cert: Option<PathBuf>,
        /// Set the TLS private key (in PEM format) for this drand node.
        /// The key has to be specified as a file path.
        /// This parameter is required by default and can only be omitted if the --tls-disable flag is used.
        #[structopt(long, short = "k", parse(from_os_str), required_unless = "tls-disable")]
        tls_key: Option<PathBuf>,
        /// Disable TLS for all communications (not recommended).
        #[structopt(long, short = "d")]
        tls_disable: bool,
        /// Set the port you want to listen to for control port commands.
        #[structopt(long, default_value = "8888")]
        control: usize,
        /// Set the listening (binding) address. Useful if you have some kind of proxy.
        #[structopt(long, short = "l")]
        listen: Option<String>,
        /// Directory containing trusted certificates. Useful for testing and self signed certificates
        #[structopt(long, parse(from_os_str))]
        certs_dir: Option<PathBuf>,
        /// Push mode forces the daemon to start making beacon requests to the other node, instead of waiting the other
        /// nodes contact it to catch-up on the round.
        #[structopt(long)]
        push: bool,
    },
    /// Stop the drand daemon.
    Stop {},
    /// Launch a sharing protocol. If one group is given as
    /// argument, drand launches a DKG protocol to create a distributed
    /// keypair between all participants listed in the group. An
    /// existing group can also issue new shares to a new group: use
    /// the flag --from to specify the current group and give
    /// the new group as argument. Specify the --leader flag to make
    /// this daemon start the protocol.
    Share {
        /// Disable TLS for all communications (not recommended).
        #[structopt(long, short = "d")]
        tls_disable: bool,
        /// Set the port you want to listen to for control port commands.
        #[structopt(long, default_value = "8888")]
        control: usize,
        /// Set this node as the initator of the distributed key generation process.
        #[structopt(long)]
        leader: bool,
        /// Old group.toml path to specify when a new node wishes to participate
        /// in a resharing protocol. This flag is optional in case a node is already
        /// included in the current DKG.
        #[structopt(long, parse(from_os_str))]
        from: Option<PathBuf>,
        /// Timeout to use during the DKG, in string format.
        #[structopt(long, default_value = "1m")]
        timeout: Duration,
        /// Source flag allows to provide an executable which output will be used as additional entropy during resharing step.
        #[structopt(long, parse(from_os_str))]
        source: Option<PathBuf>,
        /// /sed with the source flag allows to only use the user's entropy to pick the dkg secret
        /// (won't be mixed with crypto/rand). Should be used for reproducibility and debbuging purposes.
        #[structopt(long, requires = "source")]
        user_source_only: bool,
    },
    /// Generate the longterm keypair (drand.private, drand.public) for this node.
    GenerateKeypair {
        /// The public address for other nodes to contact.
        address: Url,
        /// Disable TLS for all communications (not recommended).
        #[structopt(long, short = "d")]
        tls_disable: bool,
    },
    /// Merge the given list of whitespace-separated drand.public keys into the group.toml file if one is provided,
    /// if not, create a new group.toml file with the given identites.
    Group {
        /// If you want to merge keys into an existing group.toml file, run the group command and specify the group.toml
        /// file with this flag.
        #[structopt(long, short = "g", parse(from_os_str))]
        group: Option<PathBuf>,
        /// Save the requested information into a separate file instead of stdout.
        #[structopt(long, short = "o", parse(from_os_str))]
        out: Option<PathBuf>,
        /// Period to write in the group.toml file
        #[structopt(long)]
        period: Option<Duration>,
    },
    /// Check node in the group for accessibility over the gRPC communication.
    CheckGroup {
        /// Directory containing trusted certificates. Useful for testing and self signed certificates.
        #[structopt(long, parse(from_os_str))]
        certs_dir: Option<PathBuf>,
    },
    /// Get allows for public information retrieval from a remote drand node.
    Get {
        /// Disable TLS for all communications (not recommended).
        #[structopt(long, short = "d")]
        tls_disable: bool,
        /// Set the TLS certificate chain (in PEM format) for this drand node.
        /// The certificates have to be specified as a list of whitespace-separated file paths.
        /// This parameter is required by default and can only be omitted if the --tls-disable flag is used.
        #[structopt(long, short = "c", parse(from_os_str))]
        tls_cert: PathBuf,
        /// Contact the nodes at the given list of whitespace-separated addresses which have to be present in group.toml.
        #[structopt(long, short = "n")]
        nodes: Vec<String>,

        #[structopt(subcommand)]
        cmd: GetCommand,
    },
    /// Pings the daemon checking its state.
    Ping {
        /// Set the port you want to listen to for control port commands.
        #[structopt(long, default_value = "8888")]
        control: usize,
    },
    /// Resets the local distributed information (share, group file and random beacons).
    Reset {
        /// Set the port you want to listen to for control port commands.
        #[structopt(long, default_value = "8888")]
        control: usize,
    },
    /// Local information retrieval about the node's cryptographic
    /// material. Show prints the information about the collective
    /// public key (drand.cokey), the group details (group.toml), the
    /// long-term private key (drand.private), the long-term public key
    /// (drand.public), or the private key share (drand.share),
    /// respectively.
    Show {
        /// Set the port you want to listen to for control port commands.
        #[structopt(long, default_value = "8888")]
        control: usize,
        #[structopt(subcommand)]
        cmd: ShowCommand,
    },
}

#[derive(Debug, StructOpt)]
enum GetCommand {
    /// Get private randomness from the drand beacon as
    /// specified in group.toml. Only one node is contacted by
    /// default. Requests are ECIES-encrypted towards the public
    /// key of the contacted node. This command attempts to connect
    /// to the drand beacon via TLS and falls back to
    /// plaintext communication if the contacted node has not
    /// activated TLS in which case it prints a warning.
    Private {},
    /// Get the latest public randomness from the drand
    /// beacon and verify it against the collective public key
    /// as specified in group.toml. Only one node is contacted by
    /// default. This command attempts to connect to the drand
    /// beacon via TLS and falls back to plaintext communication
    /// if the contacted node has not activated TLS in which case
    /// it prints a warning.
    Public {},
    /// Get distributed public key generated during the DKG step.
    Cokey {},
}

#[derive(Debug, StructOpt)]
enum ShowCommand {
    /// Shows the private share.
    Share {},
    /// Shows the current group.toml used. The group.toml
    /// may contain the distributed public key if the DKG has been ran already.
    Group {
        /// Save the requested information into a separate file instead of stdout.
        #[structopt(long, short = "o", parse(from_os_str))]
        out: Option<PathBuf>,
    },
    /// Shows the collective key generated during DKG.
    Cokey {},
    /// Shows the long-term private key of a node.
    Private {},
    /// Shows the long-term public key of a node.
    Public {},
}

fn get_default_folder() -> PathBuf {
    let home_dir = home::home_dir().expect("Unable to determine home_dir");
    home_dir.join(DEFAULT_FOLDER_NAME)
}

fn main() -> Result<()> {
    let opts = Drand::from_args();

    opts.setup_logger();

    let config_folder = opts.folder.unwrap_or_else(get_default_folder);

    match opts.cmd {
        DrandCommand::Start { .. } => daemon::start(),
        DrandCommand::Stop { .. } => daemon::stop(),
        DrandCommand::Share { .. } => share(),
        DrandCommand::GenerateKeypair {
            address,
            tls_disable,
        } => keygen(&address, tls_disable, &config_folder),
        DrandCommand::Group { .. } => group(),
        DrandCommand::CheckGroup { .. } => check_group(),
        DrandCommand::Ping { .. } => ping(),
        DrandCommand::Reset { .. } => reset(),
        DrandCommand::Get { .. } => get(),
        DrandCommand::Show { .. } => show(),
    }
}

impl Drand {
    /// Initialize the logger according to the provided level.
    fn setup_logger(&self) {
        let log_level = match self.verbose {
            2 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Info,
        };

        logger::init_level(log_level).expect("failed to initialize the logger");
    }
}

pub fn share() -> Result<()> {
    info!("share");

    Ok(())
}

pub fn keygen(address: &Url, insecure: bool, config_folder: &PathBuf) -> Result<()> {
    let key_pair = if insecure {
        info!("Generating private / public key pair without TLS.");
        key::Pair::new(address)?
    } else {
        info!("Generating private / public key pair with TLS indication.");
        key::Pair::new_tls(address)?
    };

    let store = key::FileStore::new(config_folder)?;
    store.save_key_pair(&key_pair)?;

    info!("Generated keys at {}", store.key_folder().display());
    info!("You can copy paste the following snippet to a common group.toml file:");
    info!(
        "\n[[Nodes]]\n{}",
        toml::to_string_pretty(key_pair.public())?
    );
    info!("Or just collect all public key files and use the group command!");

    Ok(())
}

pub fn group() -> Result<()> {
    info!("group");

    Ok(())
}

pub fn check_group() -> Result<()> {
    info!("check_group");

    Ok(())
}

pub fn ping() -> Result<()> {
    info!("group");

    Ok(())
}

pub fn reset() -> Result<()> {
    info!("group");

    Ok(())
}

pub fn get() -> Result<()> {
    info!("get");

    Ok(())
}

pub fn show() -> Result<()> {
    info!("show");

    Ok(())
}
