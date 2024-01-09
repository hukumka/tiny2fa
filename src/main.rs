use clap::{Parser, Subcommand};
use hmac_sha1::hmac_sha1;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;
use std::error::Error;
use std::path::PathBuf;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

#[derive(Parser)]
struct Cli {
    /// Scope at which secret key is stored.
    #[arg(short, long, default_value = "default")]
    scope: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initalizes 2FA with secret key    
    Init { key: String },
    /// Generates new temporary token
    Generate,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Init { key } => init(&cli.scope, &key),
        Commands::Generate => generate(&cli.scope),
    }
}

#[derive(Serialize, Deserialize)]
struct KeyStore {
    version: u16,
    scopes: HashMap<String, String>,
}

impl Default for KeyStore {
    fn default() -> Self {
        Self {
            version: Self::current_version(),
            scopes: HashMap::new(),
        }
    }
}

impl KeyStore {
    fn current_version() -> u16 {
        return 1;
    }

    fn path() -> Result<PathBuf> {
        let mut dir = dirs::config_dir().ok_or("Unable to locate config dir!")?;
        dir.push("tiny2fa");
        if !dir.exists() {
            std::fs::create_dir(&dir)?;
        }
        dir.push("config.yml");
        Ok(dir)
    }

    fn load() -> Result<Self> {
        let path = Self::path()?;
        if path.exists() {
            Ok(serde_yaml::from_str(&std::fs::read_to_string(&path)?)?)
        } else {
            Ok(KeyStore::default())
        }
    }

    fn save(&self) -> Result<()> {
        let path = Self::path()?;
        println!("{:?}", path);
        std::fs::write(path, &serde_yaml::to_string(self)?)?;
        Ok(())
    }
}

/// Save key associated with scope in config file
fn init(scope: &str, key: &str) -> Result<()> {
    let mut store = KeyStore::load()?;
    store.scopes.insert(scope.into(), key.into());
    store.save()?;
    Ok(())
}

/// Generate temporary token
fn generate(scope: &str) -> Result<()> {
    let store = KeyStore::load()?;
    let key = store.scopes.get(scope).ok_or_else(|| {
        format!(
            "scope {} is not initialized. Use tiny2fa init *secret*",
            scope
        )
    })?;
    let interval = 30;
    let time_offset = 0;
    let counter_value = (timestamp() - time_offset) / interval;
    let full_code = generate_code(key, counter_value)?;
    let human_code = full_code % 1_000_000;
    println!("{}", human_code);
    Ok(())
}

fn timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("Time is valid")
        .as_secs()
}

fn generate_code(key: &str, counter_value: u64) -> Result<u32> {
    let key = base32::decode(base32::Alphabet::RFC4648 { padding: true }, key)
        .ok_or("Unable to decode key")?;
    let hmac = hmac_sha1(&key, &counter_value.to_be_bytes());
    let offset = (hmac[19] & 0x0F) as usize; // 4 least significant bits
    let bytes: [u8; 4] = hmac[offset..offset + 4]
        .try_into()
        .expect("Max offset is 15, so we never go out of bounds");
    let result = u32::from_be_bytes(bytes) & 0x7FFF_FFFF;
    Ok(result)
}
