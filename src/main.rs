//! Command line entry point.

use clap::{Args, Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;
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

/// Where the password comes from. With neither flag it is prompted for.
#[derive(Args)]
struct PasswordArgs {
    /// Password on the command line. Insecure: it is visible in the process
    /// list and ends up in your shell history. Prefer the interactive prompt
    /// (the default) or --password-file.
    #[arg(short, long, conflicts_with = "password_file")]
    password: Option<String>,

    /// Read the password from the first line of this file
    #[arg(long, value_name = "PATH")]
    password_file: Option<PathBuf>,
}

impl PasswordArgs {
    /// Resolves the password, prompting on the terminal if no flag was given.
    /// Encryption asks twice, since a typo would make the file unrecoverable.
    fn resolve(self, confirm: bool) -> Result<String, String> {
        let password = if let Some(password) = self.password {
            Zeroizing::new(password)
        } else if let Some(path) = self.password_file {
            read_password_file(&path)?
        } else {
            let first = Zeroizing::new(
                rpassword::prompt_password("Password: ")
                    .map_err(prompt_error)?,
            );
            if confirm {
                let second = Zeroizing::new(
                    rpassword::prompt_password("Repeat password: ")
                        .map_err(prompt_error)?,
                );
                if *first != *second {
                    return Err("passwords do not match".to_string());
                }
            }
            first
        };

        if password.is_empty() {
            return Err("password must not be empty".to_string());
        }
        Ok(password.as_str().to_owned())
    }
}

fn prompt_error(e: std::io::Error) -> String {
    format!(
        "could not prompt for the password ({}) - use --password-file when no terminal is attached",
        e
    )
}

fn read_password_file(path: &Path) -> Result<Zeroizing<String>, String> {
    let contents = Zeroizing::new(
        std::fs::read_to_string(path)
            .map_err(|e| format!("could not read password file {}: {}", path.display(), e))?,
    );
    let line = contents.lines().next().unwrap_or_default();
    Ok(Zeroizing::new(line.to_owned()))
}

#[derive(Parser)]
#[command(name = "timenc")]
#[command(author = "TimENC Contributors")]
#[command(version, about = "Secure file encryption with ChaCha20-Poly1305 and Argon2id", long_about = None)]
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

        /// Output path for the .timenc file (must not exist yet)
        #[arg(short, long)]
        output: PathBuf,

        #[command(flatten)]
        password: PasswordArgs,

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

        /// Delete the source after the encrypted file has been written and
        /// verified (overwritten first, best-effort)
        #[arg(long)]
        delete_source: bool,
    },

    /// Decrypt a .timenc file
    Decrypt {
        /// Input .timenc file to decrypt
        input: PathBuf,

        /// Output directory for decrypted files
        #[arg(short, long)]
        output: PathBuf,

        #[command(flatten)]
        password: PasswordArgs,

        /// Optional keyfile for decryption
        #[arg(short, long)]
        keyfile: Option<PathBuf>,

        /// Delete the .timenc file after it has been decrypted successfully
        #[arg(long)]
        delete_source: bool,
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
            delete_source,
        } => password.resolve(true).and_then(|password| {
            let options = EncryptOptions {
                password,
                keyfile_path: keyfile,
                output_path: output,
                compress,
                kdf_profile: kdf_profile.into(),
                pad,
                delete_source,
            };
            encrypt(&input, options)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
        Commands::Decrypt {
            input,
            output,
            password,
            keyfile,
            delete_source,
        } => password.resolve(false).and_then(|password| {
            let options = DecryptOptions {
                password,
                keyfile_path: keyfile,
                output_dir: output,
                delete_source,
            };
            decrypt(&input, options)
                .map(|_| ())
                .map_err(|e| e.to_string())
        }),
        Commands::GenerateKeyfile { output } => generate_keyfile(&output)
            .map(|_| ())
            .map_err(|e| e.to_string()),
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
