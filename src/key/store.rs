use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use log::info;

use super::{Identity, Pair};

/// Abstracts the loading and saving of any private/public cryptographic material to be used by drand.
pub trait Store {
    fn save_key_pair(&self, pair: &Pair) -> Result<()>;
    fn load_key_pair(&self) -> Result<Pair>;
}

const KEY_FOLDER_NAME: &str = "key";
const KEY_FILE_NAME: &str = "drand_id";
const PRIVATE_EXTENSION: &str = "private";
const PUBLIC_EXTENSION: &str = "public";

pub struct FileStore {
    base_folder: PathBuf,
    key_folder: PathBuf,
    private_key_file: PathBuf,
    public_key_file: PathBuf,
}

impl FileStore {
    /// Create a new file store.
    pub fn new<P: AsRef<Path>>(base_folder: P) -> Result<Self> {
        // TODO: ensure permissions
        let key_folder = base_folder.as_ref().join(KEY_FOLDER_NAME);
        std::fs::create_dir_all(&key_folder)
            .with_context(|| format!("FileStore: failed to create {}", key_folder.display()))?;

        let mut private_key_file = key_folder.join(KEY_FILE_NAME);
        private_key_file.set_extension(PRIVATE_EXTENSION);
        let mut public_key_file = key_folder.join(KEY_FILE_NAME);
        public_key_file.set_extension(PUBLIC_EXTENSION);

        Ok(FileStore {
            key_folder,
            private_key_file,
            public_key_file,
            base_folder: base_folder.as_ref().to_path_buf(),
        })
    }

    pub fn key_folder(&self) -> &PathBuf {
        &self.key_folder
    }
}

impl Store for FileStore {
    /// First saves the private key in a file with tight permissions and then saves the public part in another file.
    fn save_key_pair(&self, pair: &Pair) -> Result<()> {
        let bytes = toml::to_vec(pair).context("failed to serialize keypair")?;
        // TODO: secure file permissions
        std::fs::write(&self.private_key_file, &bytes).with_context(|| {
            format!(
                "failed to write keypair to: {}",
                &self.private_key_file.display()
            )
        })?;

        let bytes = toml::to_vec(pair.public()).context("failed to serialize public key")?;
        std::fs::write(&self.public_key_file, &bytes).with_context(|| {
            format!(
                "failed to write public key to: {}",
                &self.public_key_file.display()
            )
        })?;

        info!(
            "Saved the key: {} at {}",
            pair.public().address(),
            self.public_key_file.display()
        );

        Ok(())
    }

    fn load_key_pair(&self) -> Result<Pair> {
        let bytes = std::fs::read(&self.private_key_file).context("failed to read keypair")?;
        let pair: Pair = toml::from_slice(&bytes).context("failed to deserialize keypair")?;

        // TODO: do we care about the public part?

        Ok(pair)
    }
}

pub fn load_public_key<P: AsRef<Path>>(path: P) -> Result<Identity> {
    let bytes = std::fs::read(path.as_ref())
        .with_context(|| format!("failed to read public key from {}", path.as_ref().display()))?;
    let pub_key: Identity = toml::from_slice(&bytes).context("failed to deserialize public key")?;
    Ok(pub_key)
}
