//! Command line entry point.

use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;
use timenc::{encrypt, decrypt, generate_keyfile, EncryptOptions, DecryptOptions, KdfProfile};

/// Argon2id cost profile, as selectable on the command line.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum KdfProfileArg {
    /// 256 MiB, 3 passes - about a second on typical desktop hardware.
    Balanced,
    /// 1 GiB, 4 passes - for long-term archives.
    Paranoid,
}

impl From<KdfProfileArg> for KdfProfile {
    fn from(arg: KdfProfileArg) -> Self {
        match arg {
            KdfProfileArg::Balanced => KdfProfile::Balanced,
            KdfProfileArg::Paranoid => KdfProfile::Paranoid,
        }
    }
}

#[derive(Parser)]
#[command(name = "timenc")]
#[command(author = "TimENC Contributors")]
#[command(about = "Secure file encryption with ChaCha20-Poly1305 and Argon2id", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file or directory
    Encrypt {
        /// Input file or directory to encrypt
        input: PathBuf,

        /// Output path for the .timenc file
        #[arg(short, long)]
        output: PathBuf,

        /// Password for encryption
        #[arg(short, long)]
        password: String,

        /// Optional keyfile for additional entropy
        #[arg(short, long)]
        keyfile: Option<PathBuf>,

        /// Compress the data with zstd before encrypting it
        #[arg(short = 'c', long)]
        compress: bool,

        /// Argon2id cost profile
        #[arg(long, value_enum, default_value_t = KdfProfileArg::Balanced)]
        kdf_profile: KdfProfileArg,

        /// Pad the payload so the file size does not reveal the exact
        /// plaintext size (at most ~12% overhead)
        #[arg(long)]
        pad: bool,
    },

    /// Decrypt a .timenc file
    Decrypt {
        /// Input .timenc file to decrypt
        input: PathBuf,

        /// Output directory for decrypted files
        #[arg(short, long)]
        output: PathBuf,

        /// Password for decryption
        #[arg(short, long)]
        password: String,

        /// Optional keyfile for decryption
        #[arg(short, long)]
        keyfile: Option<PathBuf>,
    },

    /// Generate a new keyfile
    GenerateKeyfile {
        /// Output path for the keyfile
        output: PathBuf,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Encrypt {
            input,
            output,
            password,
            keyfile,
            compress,
            kdf_profile,
            pad,
        } => {
            let options = EncryptOptions {
                password,
                keyfile_path: keyfile,
                output_path: output,
                compress,
                kdf_profile: kdf_profile.into(),
                pad,
            };
            encrypt(&input, options)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
        Commands::Decrypt {
            input,
            output,
            password,
            keyfile,
        } => {
            let options = DecryptOptions {
                password,
                keyfile_path: keyfile,
                output_dir: output,
            };
            decrypt(&input, options)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
        Commands::GenerateKeyfile { output } => generate_keyfile(&output)
            .map(|_| ())
            .map_err(|e| e.to_string()),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
