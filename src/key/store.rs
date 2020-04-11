use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use async_std::sync::Arc;
use log::info;

use super::{Group, Pair};
use crate::dkg::{DistPublic, Share};

/// Abstracts the loading and saving of any private/public cryptographic material to be used by drand.
pub trait Store {
    fn save_key_pair(&self, pair: &Pair) -> Result<()>;
    fn load_key_pair(&self) -> Result<Pair>;

    fn save_share(&self, share: &Share) -> Result<()>;
    fn load_share(&self) -> Result<Share>;

    fn save_dist_public(&self, share: &DistPublic) -> Result<()>;
    fn load_dist_public(&self) -> Result<DistPublic>;

    fn save_group(&self, share: &Group) -> Result<()>;
    fn load_group(&self) -> Result<Group>;
}

const KEY_FOLDER_NAME: &str = "key";
const GROUP_FOLDER_NAME: &str = "group";

const KEY_FILE_NAME: &str = "drand_id";
const PRIVATE_EXTENSION: &str = "private";
const PUBLIC_EXTENSION: &str = "public";
const SHARE_FILE_NAME: &str = "dist_key.private";
const DIST_KEY_FILE_NAME: &str = "dist_key.public";
const GROUP_FILE_NAME: &str = "drand_group.toml";

#[derive(Debug, Clone)]
pub struct FileStore {
    inner: Arc<InnerFileStore>,
}

#[derive(Debug)]
pub struct InnerFileStore {
    base_folder: PathBuf,
    key_folder: PathBuf,
    private_key_file: PathBuf,
    public_key_file: PathBuf,
    share_file: PathBuf,
    dist_key_file: PathBuf,
    group_file: PathBuf,
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

        let group_folder = base_folder.as_ref().join(GROUP_FOLDER_NAME);
        std::fs::create_dir_all(&group_folder)
            .with_context(|| format!("FileStore: failed to create {}", group_folder.display()))?;

        let share_file = group_folder.join(SHARE_FILE_NAME);
        let dist_key_file = group_folder.join(DIST_KEY_FILE_NAME);
        let group_file = group_folder.join(GROUP_FILE_NAME);

        Ok(FileStore {
            inner: Arc::new(InnerFileStore {
                key_folder,
                private_key_file,
                public_key_file,
                base_folder: base_folder.as_ref().to_path_buf(),
                share_file,
                dist_key_file,
                group_file,
            }),
        })
    }
}

impl std::ops::Deref for FileStore {
    type Target = InnerFileStore;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl InnerFileStore {
    pub fn key_folder(&self) -> &PathBuf {
        &self.key_folder
    }
}

impl Store for InnerFileStore {
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

    fn save_share(&self, share: &Share) -> Result<()> {
        info!(
            "crypto store: saving private share in {}",
            self.share_file.display()
        );
        write_to_file(&self.share_file, share).context("failed to store share")?;

        Ok(())
    }

    fn load_share(&self) -> Result<Share> {
        load_from_file(&self.share_file).context("failed to load share")
    }

    fn save_dist_public(&self, share: &DistPublic) -> Result<()> {
        info!(
            "crypto store: saving dist public in {}",
            self.dist_key_file.display()
        );
        write_to_file(&self.dist_key_file, share).context("failed to store dist public")?;

        Ok(())
    }

    fn load_dist_public(&self) -> Result<DistPublic> {
        load_from_file(&self.dist_key_file).context("failed to load dist public")
    }

    fn save_group(&self, group: &Group) -> Result<()> {
        info!(
            "crypto store: saving group in {}",
            self.group_file.display()
        );
        write_to_file(&self.group_file, group).context("failed to store group")?;

        Ok(())
    }

    fn load_group(&self) -> Result<Group> {
        load_from_file(&self.group_file).context("failed to load group")
    }
}

pub fn load_from_file<P: AsRef<Path>, S: serde::de::DeserializeOwned>(path: P) -> Result<S> {
    let bytes = std::fs::read(path.as_ref())
        .with_context(|| format!("failed to read data from {}", path.as_ref().display()))?;
    let res = toml::from_slice(&bytes).context("failed to deserialize")?;

    Ok(res)
}

pub fn write_to_file<P: AsRef<Path>, S: serde::ser::Serialize>(path: P, s: &S) -> Result<()> {
    let bytes = toml::to_vec(s).context("failed to serialize")?;
    std::fs::write(path.as_ref(), &bytes)
        .with_context(|| format!("failed to write : {}", path.as_ref().display()))?;
    Ok(())
}
