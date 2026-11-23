//! Runs encryption, decryption and keyfile generation off the UI thread.
//!
//! Argon2id alone takes around a second (several in paranoid mode), so every
//! operation runs on its own thread. The UI polls the result channel once per
//! frame, and the worker wakes the UI when it is done; nothing repaints in a
//! loop while waiting.

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;

use timenc::{DecryptOptions, EncryptOptions};
use zeroize::Zeroize;

pub enum Job {
    Encrypt {
        input: PathBuf,
        options: EncryptOptions,
    },
    Decrypt {
        input: PathBuf,
        options: DecryptOptions,
    },
    Keyfile {
        output: PathBuf,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum JobKind {
    Encrypt,
    Decrypt,
    Keyfile,
}

pub enum Outcome {
    Success {
        path: PathBuf,
        /// Set when a decrypted file used a pre-v6 format.
        legacy_version: Option<u8>,
    },
    Failure(String),
}

pub struct Running {
    pub kind: JobKind,
    receiver: Receiver<Outcome>,
}

pub enum Poll {
    Pending,
    Done(Outcome),
    /// The worker thread went away without reporting (it panicked).
    Lost,
}

impl Running {
    pub fn poll(&self) -> Poll {
        match self.receiver.try_recv() {
            Ok(outcome) => Poll::Done(outcome),
            Err(TryRecvError::Empty) => Poll::Pending,
            Err(TryRecvError::Disconnected) => Poll::Lost,
        }
    }
}

/// Starts `job` on a new thread; `wake` is called once it has finished.
pub fn spawn(job: Job, wake: impl FnOnce() + Send + 'static) -> Running {
    let kind = match &job {
        Job::Encrypt { .. } => JobKind::Encrypt,
        Job::Decrypt { .. } => JobKind::Decrypt,
        Job::Keyfile { .. } => JobKind::Keyfile,
    };
    let (sender, receiver) = mpsc::channel();
    let spawned = thread::Builder::new()
        .name("timenc-worker".into())
        .spawn(move || {
            let outcome = run(job);
            let _ = sender.send(outcome);
            wake();
        });
    if let Err(e) = spawned {
        // Report it through the same channel the UI is already watching.
        let (sender, failed) = mpsc::channel();
        let _ = sender.send(Outcome::Failure(e.to_string()));
        return Running {
            kind,
            receiver: failed,
        };
    }
    Running { kind, receiver }
}

fn run(job: Job) -> Outcome {
    match job {
        Job::Encrypt { input, options } => outcome(timenc::encrypt(&input, options), None),
        Job::Decrypt { input, options } => decrypt(input, options),
        Job::Keyfile { output } => outcome(timenc::generate_keyfile(&output), None),
    }
}

fn outcome(result: timenc::Result<PathBuf>, legacy_version: Option<u8>) -> Outcome {
    match result {
        Ok(path) => Outcome::Success {
            path,
            legacy_version,
        },
        Err(e) => Outcome::Failure(e.to_string()),
    }
}

fn decrypt(input: PathBuf, options: DecryptOptions) -> Outcome {
    // Checked up front: the file may be deleted by the decryption itself.
    let legacy_version = timenc::operations::file_format_version(&input)
        .ok()
        .filter(|version| timenc::operations::is_legacy_version(*version));

    // Earlier GUI versions trimmed whitespace off the password, so a file
    // encrypted there with a password like "secret " was really encrypted with
    // "secret". Keep those files readable by retrying trimmed.
    let trimmed_retry = (options.password != options.password.trim()).then(|| {
        let mut retry = options.clone();
        let trimmed = retry.password.trim().to_string();
        retry.password.zeroize();
        retry.password = trimmed;
        retry
    });

    let mut result = timenc::decrypt(&input, options);
    if let (Err(timenc::Error::DecryptionFailed), Some(retry)) = (&result, trimmed_retry) {
        result = timenc::decrypt(&input, retry);
    }
    outcome(result, legacy_version)
}
