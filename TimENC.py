from __future__ import annotations
import os
import sys
import struct
import tempfile
import tarfile
import secrets
from pathlib import Path
from typing import Tuple, Optional, Callable, Any
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from argon2.low_level import hash_secret_raw, Type
import stat
import errno
from functools import partial

# -------------------------------------------------------------------
# Configuration Constants
# -------------------------------------------------------------------

# Application version - easily changeable here
APP_VERSION = "1.1.1"

# Encryption format version - should remain stable for compatibility
ENCRYPTION_FORMAT_VERSION = 2

try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QStackedWidget, QLabel, QLineEdit, QPushButton, QFormLayout,
        QFileDialog, QMessageBox, QStatusBar, QFrame, QComboBox
    )
    from PySide6.QtCore import QThread, QObject, Signal, Slot, Qt, QSettings, QSize
    from PySide6.QtGui import QDragEnterEvent, QDropEvent
except ImportError:
    print("Error: PySide6 not found.")
    print("Please install it using: pip install PySide6")
    sys.exit(1)


# -------------------------------------------------------------------
#
#                         LANGUAGE MANAGEMENT
#
# -------------------------------------------------------------------

LANGUAGES = {
    'de': {
        # General
        'app_title': "Timenc {version} - Sichere Verschlüsselung",
        'app_subtitle': "Sichere Dateiverschlüsselung mit Passwort und Keyfile",
        'status_ready': "✅ Bereit — {version}",
        'status_processing': "⏳ Verarbeite...",
        'status_error': "❌ Fehler: {message}",
        'status_success': "✅ Erfolg: {message}",
        'dialog_title_error': "Fehler",
        'dialog_title_success': "Erfolg",
        'dialog_error_prefix': "Ein Fehler ist aufgetreten:\n\n{message}",
        # Tabs/Navigation
        'nav_encrypt': "🔒 Verschlüsseln",
        'nav_decrypt': "🔓 Entschlüsseln",
        'nav_settings': "⚙️ Einstellungen",
        # UI Elements (Buttons, Labels, Placeholders)
        'label_file_folder': "📁 Datei / Ordner:",
        'label_output_file': "💾 Ausgabedatei:",
        'label_password': "🔑 Passwort:",
        'label_keyfile': "🗝️ Keyfile (Optional):",
        'label_timenc_file': "📄 .timenc Datei:",
        'label_output_folder': "📂 Zielordner:",
        'button_browse': "Durchsuchen...",
        'button_save_as': "Speichern unter...",
        'button_select_folder': "Ordner wählen...",
        'button_show': "Anzeigen",
        'button_hide': "Verbergen",
        'button_select': "Wählen...",
        'button_generate': "Generieren...",
        'button_encrypt': "🚀 Verschlüsseln",
        'button_decrypt': "🚀 Entschlüsseln",
        'placeholder_drop_file_folder': "Datei oder Ordner hierher ziehen...",
        'placeholder_drop_keyfile': "Keyfile hierher ziehen (optional)...",
        'placeholder_drop_timenc': "Verschlüsselte .timenc Datei hierher ziehen...",
        'placeholder_output_file': "Zieldatei (z.B. geheim.timenc)",
        'placeholder_output_folder': "Zielordner für entschlüsselte Dateien",
        'default_enc_filename': "verschluesselt.timenc",
        # UI Logic & Dialogs
        'dialog_choose_enc_input_file': "Datei zum Verschlüsseln auswählen",
        'dialog_choose_enc_input_folder': "Ordner zum Verschlüsseln auswählen",
        'dialog_save_enc_output': "Verschlüsselte Datei speichern als",
        'dialog_timenc_files': "TIMENC Dateien (*.timenc)",
        'dialog_choose_dec_input': "Verschlüsselte Datei auswählen",
        'dialog_all_files': "Alle Dateien (*.*)",
        'dialog_choose_dec_output': "Zielordner auswählen",
        'dialog_choose_keyfile': "Keyfile auswählen",
        'dialog_save_keyfile': "Neues Keyfile speichern als",
        'error_generate_keyfile': "Fehler bei Keyfile-Erstellung: {error}",
        'error_all_fields': "Bitte alle Felder ausfüllen.",
        'error_no_password': "Passwort fehlt.",
        # Core Logic Errors
        'err_file_exists': "Zieldatei existiert bereits: {path}",
        'err_path_traversal': "Unzulässiger Pfad in Archiv (Path Traversal)",
        'err_input_not_found': "Eingabe nicht gefunden: {path}",
        'err_filename_too_long': "Dateiname zu lang",
        'err_input_file_not_found': "Eingabedatei nicht gefunden: {path}",
        'err_not_timenc_file': "Keine TIMENC-Datei",
        'err_decrypt_failed': "Entschlüsselung fehlgeschlagen - falsches Passwort/Keyfile oder manipulierte Datei",
        'err_keyfile_exists': "Keyfile existiert bereits: {path}",
        # Core Logic Success
        'ok_encrypted': "Verschlüsselt: {path}",
        'ok_decrypted_extracted': "Entschlüsselt und extrahiert nach: {path}",
        'ok_decrypted': "Entschlüsselt: {path}",
        'ok_keyfile_created': "Keyfile erstellt: {path} ({size} Bytes)",
        # Settings
        'label_language': "Sprache:",
        'label_lang_de': "Deutsch",
        'label_lang_en': "Englisch",
        'label_restart_info': "Änderungen werden nach einem Neustart wirksam.",
    },
    'en': {
        # General
        'app_title': "Timenc {version} - Secure Encryption",
        'app_subtitle': "Secure file encryption with password and keyfile",
        'status_ready': "✅ Ready — {version}",
        'status_processing': "⏳ Processing...",
        'status_error': "❌ Error: {message}",
        'status_success': "✅ Success: {message}",
        'dialog_title_error': "Error",
        'dialog_title_success': "Success",
        'dialog_error_prefix': "An error occurred:\n\n{message}",
        # Tabs/Navigation
        'nav_encrypt': "🔒 Encrypt",
        'nav_decrypt': "🔓 Decrypt",
        'nav_settings': "⚙️ Settings",
        # UI Elements (Buttons, Labels, Placeholders)
        'label_file_folder': "📁 File / Folder:",
        'label_output_file': "💾 Output File:",
        'label_password': "🔑 Password:",
        'label_keyfile': "🗝️ Keyfile (Optional):",
        'label_timenc_file': "📄 .timenc File:",
        'label_output_folder': "📂 Output Folder:",
        'button_browse': "Browse...",
        'button_save_as': "Save As...",
        'button_select_folder': "Choose Folder...",
        'button_show': "Show",
        'button_hide': "Hide",
        'button_select': "Choose...",
        'button_generate': "Generate...",
        'button_encrypt': "🚀 Encrypt",
        'button_decrypt': "🚀 Decrypt",
        'placeholder_drop_file_folder': "Drop file or folder here...",
        'placeholder_drop_keyfile': "Drop keyfile here (optional)...",
        'placeholder_drop_timenc': "Drop encrypted .timenc file here...",
        'placeholder_output_file': "Target file (e.g., secret.timenc)",
        'placeholder_output_folder': "Target folder for decrypted files",
        'default_enc_filename': "encrypted.timenc",
        # UI Logic & Dialogs
        'dialog_choose_enc_input_file': "Choose file to encrypt",
        'dialog_choose_enc_input_folder': "Choose folder to encrypt",
        'dialog_save_enc_output': "Save encrypted file as",
        'dialog_timenc_files': "TIMENC Files (*.timenc)",
        'dialog_choose_dec_input': "Choose encrypted file",
        'dialog_all_files': "All Files (*.*)",
        'dialog_choose_dec_output': "Choose target folder",
        'dialog_choose_keyfile': "Choose keyfile",
        'dialog_save_keyfile': "Save new keyfile as",
        'error_generate_keyfile': "Failed to generate keyfile: {error}",
        'error_all_fields': "Please fill in all fields.",
        'error_no_password': "Password is missing.",
        # Core Logic Errors
        'err_file_exists': "Target file already exists: {path}",
        'err_path_traversal': "Invalid path in archive (Path Traversal)",
        'err_input_not_found': "Input not found: {path}",
        'err_filename_too_long': "Filename too long",
        'err_input_file_not_found': "Input file not found: {path}",
        'err_not_timenc_file': "Not a TIMENC file",
        'err_decrypt_failed': "Decryption failed - wrong password/keyfile or tampered file",
        'err_keyfile_exists': "Keyfile already exists: {path}",
        # Core Logic Success
        'ok_encrypted': "Encrypted: {path}",
        'ok_decrypted_extracted': "Decrypted and extracted to: {path}",
        'ok_decrypted': "Decrypted: {path}",
        'ok_keyfile_created': "Keyfile created: {path} ({size} Bytes)",
        # Settings
        'label_language': "Language:",
        'label_lang_de': "German",
        'label_lang_en': "English",
        'label_restart_info': "Changes will take effect after restarting the application.",
    }
}


class LanguageManager:
    """Manages translations for the application."""
    
    def __init__(self, language_code: str):
        self.set_language(language_code)

    def set_language(self, language_code: str):
        """Sets the current language."""
        self.current_lang = language_code if language_code in LANGUAGES else 'en'
        self.strings = LANGUAGES[self.current_lang]

    def tr(self, key: str, **kwargs) -> str:
        """
        Retrieves a translated string by its key.
        Replaces placeholders if kwargs are provided.
        """
        template = self.strings.get(key, f"<{key}>")
        if kwargs:
            try:
                return template.format(**kwargs)
            except KeyError:
                return f"<{key} (format error)>"
        return template


# -------------------------------------------------------------------
#
#                         CORE ENCRYPTION LOGIC
#
# -------------------------------------------------------------------

# File format identification
MAGIC = b"TIMENC"
VERSION = ENCRYPTION_FORMAT_VERSION

# Cryptography constants
ARGON2_TIME = 4
ARGON2_MEMORY_KIB = 131072  # 128 MiB
ARGON2_PARALLELISM = 4
KEY_LEN = 32
SALT_SIZE = 16
NONCE_SIZE = 12


def _get_tr_func(kwargs: dict[str, Any]) -> Callable:
    """Helper function to safely extract tr_func from kwargs."""
    tr_func = kwargs.get('tr_func')
    if tr_func and isinstance(tr_func, Callable):
        return tr_func
    # Fallback if no translation function was provided
    return lambda key, **kwa: key


def derive_key(password: bytes, salt: bytes, time_cost: int, memory_kib: int, 
               parallelism: int, keyfile_bytes: Optional[bytes] = None) -> bytes:
    """
    Derive a key using Argon2id. 
    If keyfile_bytes is provided, it is mixed into the password.
    """
    if keyfile_bytes:
        password = password + b"::KEYFILE::" + keyfile_bytes
    return hash_secret_raw(
        secret=password,
        salt=salt,
        time_cost=time_cost,
        memory_cost=memory_kib,
        parallelism=parallelism,
        hash_len=KEY_LEN,
        type=Type.ID,
    )


def _pack_u16(n: int) -> bytes: 
    return struct.pack(">H", n)


def _unpack_u16(b: bytes) -> int: 
    return struct.unpack(">H", b)[0]


def _pack_u32(n: int) -> bytes: 
    return struct.pack(">I", n)


def _unpack_u32(b: bytes) -> int: 
    return struct.unpack(">I", b)[0]


# -------------------------------------------------------------------
# Atomic file operations
# -------------------------------------------------------------------

def atomic_write_bytes(final_path: Path, data: bytes, mode: int = 0o600, **kwargs) -> None:
    """
    Atomically write bytes to final_path: write into a temporary file in same directory,
    set secure permissions, fsync, then os.replace to final path.
    Raises FileExistsError if final_path already exists.
    """
    tr_func = _get_tr_func(kwargs)
    final_dir = final_path.parent
    final_dir.mkdir(parents=True, exist_ok=True)
    if final_path.exists():
        raise FileExistsError(tr_func('err_file_exists', path=str(final_path)))
    
    # Create temp file in same directory to allow atomic os.replace on same filesystem
    fd, tmp = tempfile.mkstemp(dir=str(final_dir))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        # Set permissions after writing - using os.chmod instead of os.fchmod for cross-platform compatibility
        os.chmod(tmp, mode)
        os.replace(tmp, str(final_path))
    finally:
        # Cleanup if replace failed and tmp still exists
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass


def atomic_write_bytes_allow_overwrite(final_path: Path, data: bytes, mode: int = 0o600) -> None:
    """
    Like atomic_write_bytes but allows overwriting existing file (used for temp outputs).
    """
    final_dir = final_path.parent
    final_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(final_dir))
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        # Set permissions after writing
        os.chmod(tmp, mode)
        os.replace(tmp, str(final_path))
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass


def atomic_write_fileobj(final_path: Path, fileobj, mode: int = 0o600) -> None:
    """
    Atomically write a file-like object's bytes (fileobj should be at position 0).
    """
    final_dir = final_path.parent
    final_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(final_dir))
    try:
        with os.fdopen(fd, "wb") as f:
            fileobj.seek(0)
            while True:
                chunk = fileobj.read(65536)
                if not chunk:
                    break
                f.write(chunk)
            f.flush()
            os.fsync(f.fileno())
        # Set permissions after writing
        os.chmod(tmp, mode)
        os.replace(tmp, str(final_path))
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass


# -------------------------------------------------------------------
# Tar archive helpers
# -------------------------------------------------------------------

def _make_tar_if_needed(path: Path) -> Tuple[Path, bool]:
    """
    If path is a file -> return it (tmp_created False).
    If directory -> create a tar in tmp file and return tmp Path (tmp_created True).
    Tar creation avoids dereferencing symlinks (safer).
    """
    if path.is_file():
        return path, False
        
    final_dir = Path(tempfile.mkdtemp())
    tmp = final_dir / f"{path.name}.tar"
    try:
        # Do not dereference symlinks - include them as links
        with tarfile.open(str(tmp), "w") as tar:
            tar.add(str(path), arcname=path.name, recursive=True)
    except Exception:
        try:
            os.remove(str(tmp))
        except Exception:
            pass
        raise
    return tmp, True


def _is_within_directory(directory: str, target: str) -> bool:
    """Check if target path is within the specified directory."""
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)
    try:
        return os.path.commonpath([abs_directory]) == os.path.commonpath([abs_directory, abs_target])
    except Exception:
        return False


def safe_extract(tar: tarfile.TarFile, path: str = ".", **kwargs) -> None:
    """
    Extract tar file safely, preventing path traversal (Tar-Slip) attacks.
    """
    tr_func = _get_tr_func(kwargs)
    for member in tar.getmembers():
        member_path = os.path.join(path, member.name)
        if not _is_within_directory(path, member_path):
            raise Exception(tr_func('err_path_traversal'))
    tar.extractall(path=path)


# -------------------------------------------------------------------
# Secure file deletion
# -------------------------------------------------------------------

def secure_delete(path: Path):
    """
    Overwrite file contents blockwise and unlink. 
    Note: not guaranteed on SSDs/filesystems with snapshots.
    """
    try:
        length = path.stat().st_size
        with open(path, "r+b") as f:
            f.seek(0)
            remaining = length
            block = 65536
            while remaining > 0:
                towrite = os.urandom(min(block, remaining))
                f.write(towrite)
                remaining -= len(towrite)
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass
    try:
        path.unlink()
    except Exception:
        pass


# -------------------------------------------------------------------
# Main encryption/decryption functions
# -------------------------------------------------------------------

def encrypt(input_path: str, output_file: str, password: str, 
            keyfile_path: Optional[str] = None, **kwargs) -> str:
    """
    Encrypt a file or directory.
    
    Args:
        input_path: Path to file or directory to encrypt
        output_file: Output .timenc file path
        password: Encryption password
        keyfile_path: Optional keyfile path
        **kwargs: Additional arguments including tr_func for translations
    
    Returns:
        Success message
    """
    tr_func = _get_tr_func(kwargs)
    inp = Path(input_path)
    if not inp.exists():
        raise FileNotFoundError(tr_func('err_input_not_found', path=input_path))
        
    file_to_encrypt, tmp_created = _make_tar_if_needed(inp)
    original_name = file_to_encrypt.name
    is_dir = 1 if tmp_created else 0
    
    try:
        # Read plaintext as bytes (be mindful: this loads into RAM)
        data = file_to_encrypt.read_bytes()
        salt = os.urandom(SALT_SIZE)
        keyfile_bytes = None
        if keyfile_path:
            keyfile_bytes = Path(keyfile_path).read_bytes()
            
        # Derive key
        key = derive_key(password.encode("utf-8"), salt, ARGON2_TIME, 
                         ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, keyfile_bytes)
        
        # Make mutable for zeroization
        key_ba = bytearray(key)
        nonce = os.urandom(NONCE_SIZE)

        # Prepare header bytes (everything written BEFORE ciphertext) - this will be AAD
        header = bytearray()
        header += MAGIC
        header += bytes([VERSION])
        header += bytes([is_dir])
        name_bytes = original_name.encode("utf-8")
        if len(name_bytes) > 65535:
            raise ValueError(tr_func('err_filename_too_long'))
        header += _pack_u16(len(name_bytes))
        header += name_bytes
        header += salt
        header += _pack_u32(ARGON2_TIME)
        header += _pack_u32(ARGON2_MEMORY_KIB)
        header += bytes([ARGON2_PARALLELISM])
        header += nonce

        try:
            aead = ChaCha20Poly1305(bytes(key_ba))
            # Encrypt using header as AAD
            ciphertext = aead.encrypt(nonce, data, bytes(header))
        finally:
            # Zeroize key
            for i in range(len(key_ba)):
                key_ba[i] = 0
            del key_ba

        # Build final bytes to write: header + ciphertext
        final_bytes = bytes(header) + ciphertext

        outp = Path(output_file)
        # Atomic write, refuse to overwrite existing file to avoid accidental data loss
        atomic_write_bytes(outp, final_bytes, mode=0o600, tr_func=tr_func)
        return tr_func('ok_encrypted', path=output_file)
        
    finally:
        if tmp_created:
            try:
                secure_delete(file_to_encrypt)
            except Exception:
                pass
        # Attempt to zeroize plaintext if possible
        try:
            if 'data' in locals():
                if isinstance(data, bytes):
                    ba = bytearray(data)
                    for i in range(len(ba)):
                        ba[i] = 0
                    del ba
                else:
                    del data
        except Exception:
            pass


def decrypt(input_file: str, out_dir: str, password: str, 
            keyfile_path: Optional[str] = None, **kwargs) -> str:
    """
    Decrypt a .timenc file.
    
    Args:
        input_file: Path to .timenc file
        out_dir: Output directory for decrypted content
        password: Decryption password
        keyfile_path: Optional keyfile path
        **kwargs: Additional arguments including tr_func for translations
    
    Returns:
        Success message
    """
    tr_func = _get_tr_func(kwargs)
    enc = Path(input_file)
    if not enc.exists():
        raise FileNotFoundError(tr_func('err_input_file_not_found', path=input_file))
        
    data = enc.read_bytes()
    pos = 0
    
    # Verify file format
    if data[: len(MAGIC)] != MAGIC:
        raise ValueError(tr_func('err_not_timenc_file'))
    
    pos += len(MAGIC)
    version = data[pos]; pos += 1
    original_name = None
    is_dir = 0
    
    # Parse header (version 2+ format)
    if version >= 2:
        is_dir = data[pos]; pos += 1
        name_len = _unpack_u16(data[pos:pos+2]); pos += 2
        original_name = data[pos:pos+name_len].decode("utf-8"); pos += name_len
        
    salt = data[pos : pos + SALT_SIZE]; pos += SALT_SIZE
    time_cost = _unpack_u32(data[pos : pos + 4]); pos += 4
    memory_kib = _unpack_u32(data[pos : pos + 4]); pos += 4
    parallelism = data[pos]; pos += 1
    nonce = data[pos : pos + NONCE_SIZE]; pos += NONCE_SIZE

    # Reconstruct header bytes (exactly the bytes used as AAD)
    header_bytes = data[:pos]
    ciphertext = data[pos:]
    
    keyfile_bytes = None
    if keyfile_path:
        keyfile_bytes = Path(keyfile_path).read_bytes()

    # Derive key and decrypt
    key = derive_key(password.encode("utf-8"), salt, time_cost, memory_kib, parallelism, keyfile_bytes)
    key_ba = bytearray(key)
    
    try:
        aead = ChaCha20Poly1305(bytes(key_ba))
        try:
            plaintext = aead.decrypt(nonce, ciphertext, bytes(header_bytes))
        except Exception:
            # Generic message to avoid revealing whether password or file was wrong
            raise ValueError(tr_func('err_decrypt_failed'))
    finally:
        # Zeroize key
        for i in range(len(key_ba)):
            key_ba[i] = 0
        del key_ba

    outp = Path(out_dir)
    outp.mkdir(parents=True, exist_ok=True)

    # Write plaintext to temp file then place or extract safely
    fd, tmp = tempfile.mkstemp()
    os.close(fd)
    tmp_path = Path(tmp)
    
    try:
        tmp_path.write_bytes(plaintext)
        # Try to zeroize plaintext copy as soon as possible
        try:
            if isinstance(plaintext, bytes):
                ba = bytearray(plaintext)
                for i in range(len(ba)):
                    ba[i] = 0
                del ba
        except Exception:
            pass

        # Handle decrypted content based on type
        if version >= 2 and is_dir == 1:
            # Safe extract of directory
            with tarfile.open(str(tmp_path), "r") as tar:
                safe_extract(tar, str(outp), tr_func=tr_func)
            return tr_func('ok_decrypted_extracted', path=str(outp))
            
        elif version >= 2 and original_name:
            # Single file with original name
            target = outp / original_name
            # Atomic write, but allow overwrite if file not present -> prevent accidental overwrite
            if target.exists():
                raise FileExistsError(tr_func('err_file_exists', path=str(target)))
            atomic_write_bytes(target, tmp_path.read_bytes(), mode=0o600, tr_func=tr_func)
            return tr_func('ok_decrypted', path=str(target))
            
        else:
            # Legacy format or fallback: try to detect type
            try:
                if tarfile.is_tarfile(str(tmp_path)):
                    with tarfile.open(str(tmp_path), "r") as tar:
                        safe_extract(tar, str(outp), tr_func=tr_func)
                    return tr_func('ok_decrypted_extracted', path=str(outp))
            except Exception:
                # Fall through to writing raw
                pass
            
            # Write as generic "decrypted" file
            target = outp / "decrypted"
            if target.exists():
                raise FileExistsError(tr_func('err_file_exists', path=str(target)))
            atomic_write_bytes(target, tmp_path.read_bytes(), mode=0o600, tr_func=tr_func)
            return tr_func('ok_decrypted', path=str(target))
            
    finally:
        try:
            secure_delete(tmp_path)
        except Exception:
            pass


# -------------------------------------------------------------------
# Keyfile generation
# -------------------------------------------------------------------

def generate_keyfile(path: str, size: int = 32, **kwargs) -> str:
    """
    Generate a secure random keyfile.
    
    Args:
        path: Path where to save the keyfile
        size: Size of keyfile in bytes
        **kwargs: Additional arguments including tr_func for translations
    
    Returns:
        Success message
    """
    tr_func = _get_tr_func(kwargs)
    key_material = secrets.token_bytes(size)
    
    # Create file securely, refuse overwrite
    p = Path(path)
    if p.exists():
        raise FileExistsError(tr_func('err_keyfile_exists', path=path))
        
    # Use O_EXCL to avoid race conditions when creating
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(str(p), flags, 0o600)
    
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(key_material)
            f.flush()
            os.fsync(f.fileno())
    finally:
        # Zeroize key material if possible
        try:
            km = bytearray(key_material)
            for i in range(len(km)):
                km[i] = 0
            del km
        except Exception:
            pass
            
    return tr_func('ok_keyfile_created', path=path, size=size)


# -------------------------------------------------------------------
#
#                         GUI APPLICATION
#
# -------------------------------------------------------------------

# Application stylesheet
APP_STYLESHEET = """
/* Main background */
QWidget {
    background-color: #1A1A1A;
    color: #E0E0E0;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 14px;
}

QMainWindow {
    background-color: #1A1A1A;
}

/* Left navigation panel */
QWidget#NavWidget {
    background-color: #1E1E1E;
    border-right: 1px solid #333333;
}

/* Title in nav panel */
QLabel#Header {
    font-size: 24px;
    font-weight: bold;
    color: #FFFFFF;
    padding: 20px 15px;
}

/* Right content area */

/* Page title */
QLabel#PageHeader {
    font-size: 28px;
    font-weight: 600;
    color: #FFFFFF;
    padding-bottom: 10px;
}

/* Form container */
QFrame#TabContainer {
    background-color: #2B2B2B;
    border-radius: 8px;
    padding: 20px;
    color: #E0E0E0;
}

/* Labels in forms */
QLabel {
    color: #E0E0E0;
    background-color: transparent;
}

/* Sub-header (gray) */
QLabel#SubHeader {
    font-size: 13px;
    color: #AAAAAA;
    padding-bottom: 15px;
}

/* Input fields */
QLineEdit, QComboBox {
    background-color: #333333;
    border: 1px solid #444444;
    border-radius: 5px;
    padding: 8px 12px;
    color: #E0E0E0;
    selection-background-color: #007ACC;
}

QLineEdit:focus, QComboBox:focus {
    border: 1px solid #007ACC;
}

QLineEdit:disabled, QComboBox:disabled {
    background-color: #2A2A2A;
    color: #888888;
}

/* Dropdown styling */
QComboBox::drop-down {
    border: none;
    width: 20px;
}

QComboBox::down-arrow {
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 5px solid #AAAAAA;
    width: 0px;
    height: 0px;
}

QComboBox QAbstractItemView {
    background-color: #333333;
    border: 1px solid #444444;
    selection-background-color: #007ACC;
    color: #E0E0E0;
    outline: none;
}

/* Button styling */

/* Standard button (secondary) */
QPushButton {
    background-color: #333333;
    color: #E0E0E0;
    border: 1px solid #555555;
    padding: 8px 16px;
    border-radius: 5px;
    font-weight: normal;
}

QPushButton:hover {
    background-color: #404040;
    border: 1px solid #666666;
}

QPushButton:pressed {
    background-color: #505050;
}

QPushButton:disabled {
    background-color: #2A2A2A;
    color: #888888;
    border: 1px solid #444444;
}

/* Navigation buttons */
QPushButton#NavButton {
    background-color: transparent;
    border: none;
    color: #AAAAAA;
    padding: 12px 20px;
    font-size: 15px;
    font-weight: bold;
    text-align: left;
    border-radius: 0px;
    margin: 2px 0px;
}

QPushButton#NavButton:hover {
    background-color: #333333;
    color: #FFFFFF;
}

QPushButton#NavButton:checked {
    background-color: #2B2B2B;
    color: #FFFFFF;
    border-left: 3px solid #007ACC;
    border-top: none;
    border-right: none;
    border-bottom: none;
}

/* Main action button */
QPushButton#ActionButton {
    background-color: #007ACC;
    color: #FFFFFF;
    font-size: 16px;
    font-weight: bold;
    padding: 12px 24px;
    border: none;
    border-radius: 5px;
}

QPushButton#ActionButton:hover {
    background-color: #005FA3;
}

QPushButton#ActionButton:pressed {
    background-color: #004D84;
}

QPushButton#ActionButton:disabled {
    background-color: #1E3A5C;
    color: #888888;
}

/* Password toggle button */
QPushButton#TogglePasswordButton {
    background-color: #444444;
    color: #AAAAAA;
    padding: 8px 12px;
    border: none;
    border-radius: 0px 5px 5px 0px;
    margin: 0px;
    min-width: 60px;
}

QPushButton#TogglePasswordButton:hover {
    background-color: #555555;
    color: #E0E0E0;
}

/* Status bar */
QStatusBar {
    background-color: #1E1E1E;
    color: #AAAAAA;
    border-top: 1px solid #333333;
    padding: 8px;
}

QStatusBar::item {
    border: none;
}

/* Layout helpers */
QHBoxLayout, QVBoxLayout, QFormLayout {
    background-color: transparent;
}

/* Scrollbars */
QScrollBar:vertical {
    background: #2B2B2B;
    width: 12px;
    margin: 0px;
}

QScrollBar::handle:vertical {
    background: #444444;
    border-radius: 6px;
    min-height: 20px;
}

QScrollBar::handle:vertical:hover {
    background: #555555;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0px;
}

QScrollBar:horizontal {
    background: #2B2B2B;
    height: 12px;
    margin: 0px;
}

QScrollBar::handle:horizontal {
    background: #444444;
    border-radius: 6px;
    min-width: 20px;
}

QScrollBar::handle:horizontal:hover {
    background: #555555;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0px;
}
"""


# -------------------------------------------------------------------
# Worker thread for crypto operations
# -------------------------------------------------------------------

class Worker(QObject):
    """
    Executes a function in a separate thread to prevent GUI freezing.
    """
    finished = Signal(str)  # Signal on success (with message)
    error = Signal(str)     # Signal on error (with error message)

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs

    @Slot()
    def run(self):
        """Execute the function and emit signals."""
        try:
            result_message = self.func(*self.args, **self.kwargs)
            self.finished.emit(result_message)
        except Exception as e:
            self.error.emit(str(e))


# -------------------------------------------------------------------
# Drag and drop input field
# -------------------------------------------------------------------

class DropLineEdit(QLineEdit):
    """
    A QLineEdit that accepts drag-and-drop of files/folders.
    """
    file_dropped = Signal(str)  # Signal when a file is dropped

    def __init__(self, placeholder_text="", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder_text)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event: QDragEnterEvent):
        """Accept the event if it contains URLs (file paths)."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent):
        """Process the drop event and set the field text."""
        if event.mimeData().hasUrls():
            # Take only the first path if multiple were dropped
            url = event.mimeData().urls()[0]
            path = url.toLocalFile()
            self.setText(path)
            self.file_dropped.emit(path)  # Emit signal
            event.acceptProposedAction()
        else:
            event.ignore()


# -------------------------------------------------------------------
# Main application window
# -------------------------------------------------------------------

class TimencApp(QMainWindow):
    """Main application window for Timenc."""
    
    def __init__(self, lang_manager: LanguageManager):
        super().__init__()
        self.thread = None  # Thread management
        self.worker = None  # Worker management
        self.lang_manager = lang_manager
        
        # Load settings (needed for language dropdown)
        self.settings = QSettings("Timenc", "TimencApp")

        # Set up main window
        self.setWindowTitle(self.lang_manager.tr('app_title', version=APP_VERSION))
        self.setGeometry(100, 100, 950, 700)  # Slightly wider for new layout
        self.setMinimumSize(800, 650)

        # Central widget and main layout (now horizontal)
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # 1. Create left navigation panel
        self._create_nav_ui()
        
        # 2. Create right content area (stacked)
        self._create_content_ui()

        # Add UI parts to main layout
        main_layout.addWidget(self.nav_widget)
        main_layout.addWidget(self.stacked_widget)

        # Stretch factors: Nav (fixed) vs Content (flexible)
        main_layout.setStretch(0, 2)  # Nav panel (approx 20-30%)
        main_layout.setStretch(1, 7)  # Content area (approx 70-80%)

        # 3. Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.set_status(self.lang_manager.tr('status_ready', version=APP_VERSION))

        # Connect autosuggest logic
        self.enc_input.file_dropped.connect(self._autosuggest_encrypt_output)
        self.enc_input.textChanged.connect(self._autosuggest_encrypt_output)
        self.dec_input.file_dropped.connect(self._autosuggest_decrypt_output)
        self.dec_input.textChanged.connect(self._autosuggest_decrypt_output)

        # Set default page
        self._navigate(0, self.nav_encrypt_btn)

    def _create_nav_ui(self):
        """Create the left navigation panel."""
        self.nav_widget = QWidget()
        self.nav_widget.setObjectName("NavWidget")
        self.nav_widget.setMaximumWidth(240)
        
        nav_layout = QVBoxLayout(self.nav_widget)
        nav_layout.setContentsMargins(0, 0, 0, 10)  # Bottom padding
        nav_layout.setSpacing(5)

        # Title in nav panel
        title = QLabel("Timenc")
        title.setObjectName("Header")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        nav_layout.addWidget(title)

        # Navigation buttons
        self.nav_encrypt_btn = QPushButton(self.lang_manager.tr('nav_encrypt'))
        self.nav_encrypt_btn.setObjectName("NavButton")
        self.nav_encrypt_btn.setCheckable(True)

        self.nav_decrypt_btn = QPushButton(self.lang_manager.tr('nav_decrypt'))
        self.nav_decrypt_btn.setObjectName("NavButton")
        self.nav_decrypt_btn.setCheckable(True)

        self.nav_settings_btn = QPushButton(self.lang_manager.tr('nav_settings'))
        self.nav_settings_btn.setObjectName("NavButton")
        self.nav_settings_btn.setCheckable(True)

        # Connect signals
        self.nav_encrypt_btn.clicked.connect(lambda: self._navigate(0, self.nav_encrypt_btn))
        self.nav_decrypt_btn.clicked.connect(lambda: self._navigate(1, self.nav_decrypt_btn))
        self.nav_settings_btn.clicked.connect(lambda: self._navigate(2, self.nav_settings_btn))

        # Add to layout
        nav_layout.addWidget(self.nav_encrypt_btn)
        nav_layout.addWidget(self.nav_decrypt_btn)
        nav_layout.addStretch()  # Push settings to bottom
        nav_layout.addWidget(self.nav_settings_btn)

    def _create_content_ui(self):
        """Create the right QStackedWidget content area."""
        self.stacked_widget = QStackedWidget()

        # Create page widgets
        self.encrypt_page = QWidget()
        self.decrypt_page = QWidget()
        self.settings_page = QWidget()
        
        # Call UI builder for each page
        self._create_encrypt_ui(self.encrypt_page)
        self._create_decrypt_ui(self.decrypt_page)
        self._create_settings_ui(self.settings_page)

        # Add pages to stack (order must match _navigate)
        self.stacked_widget.addWidget(self.encrypt_page)   # Index 0
        self.stacked_widget.addWidget(self.decrypt_page)   # Index 1
        self.stacked_widget.addWidget(self.settings_page)  # Index 2

    def _navigate(self, index: int, btn: QPushButton):
        """Switch content page and mark active button."""
        # 1. Switch content page
        self.stacked_widget.setCurrentIndex(index)
        
        # 2. "Deactivate" all buttons
        self.nav_encrypt_btn.setChecked(False)
        self.nav_decrypt_btn.setChecked(False)
        self.nav_settings_btn.setChecked(False)
        
        # 3. "Activate" only the clicked button
        btn.setChecked(True)

    # --- UI Builders for content pages ---

    def _create_encrypt_ui(self, parent_widget: QWidget):
        """Create UI for the "Encrypt" page."""
        layout = QVBoxLayout(parent_widget)
        layout.setContentsMargins(25, 20, 25, 20)  # Page margins

        # Page title
        page_title = QLabel(self.lang_manager.tr('nav_encrypt'))
        page_title.setObjectName("PageHeader")
        layout.addWidget(page_title)

        # Container for better appearance
        container = QFrame()
        container.setObjectName("TabContainer")
        container_layout = QFormLayout(container)
        container_layout.setSpacing(15)
        container_layout.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)

        # 1. Input (file/folder)
        self.enc_input = DropLineEdit(self.lang_manager.tr('placeholder_drop_file_folder'))
        enc_input_btn = QPushButton(self.lang_manager.tr('button_browse'))
        enc_input_btn.clicked.connect(self._choose_encrypt_input)
        
        enc_input_layout = QHBoxLayout()
        enc_input_layout.addWidget(self.enc_input)
        enc_input_layout.addWidget(enc_input_btn)
        container_layout.addRow(QLabel(self.lang_manager.tr('label_file_folder')), enc_input_layout)

        # 2. Output (file)
        self.enc_output = QLineEdit()
        self.enc_output.setPlaceholderText(self.lang_manager.tr('placeholder_output_file'))
        enc_output_btn = QPushButton(self.lang_manager.tr('button_save_as'))
        enc_output_btn.clicked.connect(self._choose_encrypt_output)
        
        enc_output_layout = QHBoxLayout()
        enc_output_layout.addWidget(self.enc_output)
        enc_output_layout.addWidget(enc_output_btn)
        container_layout.addRow(QLabel(self.lang_manager.tr('label_output_file')), enc_output_layout)

        # 3. Password
        self.enc_pwd = QLineEdit()
        self.enc_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.enc_pwd_toggle_btn = QPushButton(self.lang_manager.tr('button_show'))
        self.enc_pwd_toggle_btn.setObjectName("TogglePasswordButton")
        self.enc_pwd_toggle_btn.setCheckable(True)
        self.enc_pwd_toggle_btn.toggled.connect(self._toggle_password_visibility)
        
        enc_pwd_layout = QHBoxLayout()
        enc_pwd_layout.addWidget(self.enc_pwd)
        enc_pwd_layout.addWidget(self.enc_pwd_toggle_btn)
        container_layout.addRow(QLabel(self.lang_manager.tr('label_password')), enc_pwd_layout)

        # 4. Keyfile
        self.enc_keyfile = DropLineEdit(self.lang_manager.tr('placeholder_drop_keyfile'))
        enc_keyfile_select_btn = QPushButton(self.lang_manager.tr('button_select'))
        enc_keyfile_gen_btn = QPushButton(self.lang_manager.tr('button_generate'))
        enc_keyfile_select_btn.clicked.connect(partial(self._choose_keyfile, self.enc_keyfile))
        enc_keyfile_gen_btn.clicked.connect(partial(self._generate_keyfile, self.enc_keyfile))

        enc_keyfile_layout = QHBoxLayout()
        enc_keyfile_layout.addWidget(self.enc_keyfile)
        enc_keyfile_layout.addWidget(enc_keyfile_select_btn)
        enc_keyfile_layout.addWidget(enc_keyfile_gen_btn)
        container_layout.addRow(QLabel(self.lang_manager.tr('label_keyfile')), enc_keyfile_layout)

        layout.addWidget(container)
        layout.addStretch()  # Spacer at bottom

        # 5. Action button
        self.enc_button = QPushButton(self.lang_manager.tr('button_encrypt'))
        self.enc_button.setObjectName("ActionButton")
        self.enc_button.clicked.connect(self._run_encrypt)
        layout.addWidget(self.enc_button)

    def _create_decrypt_ui(self, parent_widget: QWidget):
        """Create UI for the "Decrypt" page."""
        layout = QVBoxLayout(parent_widget)
        layout.setContentsMargins(25, 20, 25, 20)

        # Page title
        page_title = QLabel(self.lang_manager.tr('nav_decrypt'))
        page_title.setObjectName("PageHeader")
        layout.addWidget(page_title)

        container = QFrame()
        container.setObjectName("TabContainer")
        container_layout = QFormLayout(container)
        container_layout.setSpacing(15)
        container_layout.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)

        # 1. Input (file)
        self.dec_input = DropLineEdit(self.lang_manager.tr('placeholder_drop_timenc'))
        dec_input_btn = QPushButton(self.lang_manager.tr('button_browse'))
        dec_input_btn.clicked.connect(self._choose_decrypt_input)
        
        dec_input_layout = QHBoxLayout()
        dec_input_layout.addWidget(self.dec_input)
        dec_input_layout.addWidget(dec_input_btn)
        container_layout.addRow(QLabel(self.lang_manager.tr('label_timenc_file')), dec_input_layout)

        # 2. Output (folder)
        self.dec_output = QLineEdit()
        self.dec_output.setPlaceholderText(self.lang_manager.tr('placeholder_output_folder'))
        dec_output_btn = QPushButton(self.lang_manager.tr('button_select_folder'))
        dec_output_btn.clicked.connect(self._choose_decrypt_output)

        dec_output_layout = QHBoxLayout()
        dec_output_layout.addWidget(self.dec_output)
        dec_output_layout.addWidget(dec_output_btn)
        container_layout.addRow(QLabel(self.lang_manager.tr('label_output_folder')), dec_output_layout)

        # 3. Password
        self.dec_pwd = QLineEdit()
        self.dec_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.dec_pwd_toggle_btn = QPushButton(self.lang_manager.tr('button_show'))
        self.dec_pwd_toggle_btn.setObjectName("TogglePasswordButton")
        self.dec_pwd_toggle_btn.setCheckable(True)
        self.dec_pwd_toggle_btn.toggled.connect(self._toggle_password_visibility)

        dec_pwd_layout = QHBoxLayout()
        dec_pwd_layout.addWidget(self.dec_pwd)
        dec_pwd_layout.addWidget(self.dec_pwd_toggle_btn)
        container_layout.addRow(QLabel(self.lang_manager.tr('label_password')), dec_pwd_layout)

        # 4. Keyfile
        self.dec_keyfile = DropLineEdit(self.lang_manager.tr('placeholder_drop_keyfile'))
        dec_keyfile_select_btn = QPushButton(self.lang_manager.tr('button_select'))
        dec_keyfile_gen_btn = QPushButton(self.lang_manager.tr('button_generate'))
        dec_keyfile_select_btn.clicked.connect(partial(self._choose_keyfile, self.dec_keyfile))
        dec_keyfile_gen_btn.clicked.connect(partial(self._generate_keyfile, self.dec_keyfile))

        dec_keyfile_layout = QHBoxLayout()
        dec_keyfile_layout.addWidget(self.dec_keyfile)
        dec_keyfile_layout.addWidget(dec_keyfile_select_btn)
        dec_keyfile_layout.addWidget(dec_keyfile_gen_btn)
        container_layout.addRow(QLabel(self.lang_manager.tr('label_keyfile')), dec_keyfile_layout)

        layout.addWidget(container)
        layout.addStretch()

        # 5. Action button
        self.dec_button = QPushButton(self.lang_manager.tr('button_decrypt'))
        self.dec_button.setObjectName("ActionButton")
        self.dec_button.clicked.connect(self._run_decrypt)
        layout.addWidget(self.dec_button)

    def _create_settings_ui(self, parent_widget: QWidget):
        """Create UI for the "Settings" page."""
        layout = QVBoxLayout(parent_widget)
        layout.setContentsMargins(25, 20, 25, 20)

        # Page title
        page_title = QLabel(self.lang_manager.tr('nav_settings'))
        page_title.setObjectName("PageHeader")
        layout.addWidget(page_title)

        container = QFrame()
        container.setObjectName("TabContainer")
        container_layout = QFormLayout(container)
        container_layout.setSpacing(15)
        
        # 1. Language selection
        self.lang_combo = QComboBox()
        self.lang_combo.addItem(self.lang_manager.tr('label_lang_de'), "de")
        self.lang_combo.addItem(self.lang_manager.tr('label_lang_en'), "en")
        
        # Select current language
        current_lang_code = self.lang_manager.current_lang
        index = self.lang_combo.findData(current_lang_code)
        if index != -1:
            self.lang_combo.setCurrentIndex(index)
            
        self.lang_combo.currentIndexChanged.connect(self._on_language_change)
        container_layout.addRow(QLabel(self.lang_manager.tr('label_language')), self.lang_combo)

        # 2. Restart hint
        self.lang_info_label = QLabel(self.lang_manager.tr('label_restart_info'))
        self.lang_info_label.setObjectName("SubHeader")  # Reuse style
        self.lang_info_label.setWordWrap(True)
        container_layout.addRow(self.lang_info_label)

        layout.addWidget(container)
        layout.addStretch()

    def _on_language_change(self, index: int):
        """Called when language is changed in dropdown."""
        lang_code = self.lang_combo.itemData(index)
        # Save setting. Will be loaded on next app start.
        self.settings.setValue("language", lang_code)

    # --- UI Interaction Handlers ---

    def _choose_encrypt_input(self):
        """Select a file OR folder (with fallback, like in original)."""
        path, _ = QFileDialog.getOpenFileName(self, self.lang_manager.tr('dialog_choose_enc_input_file'))
        if not path:
            path = QFileDialog.getExistingDirectory(self, self.lang_manager.tr('dialog_choose_enc_input_folder'))
        
        if path:
            self.enc_input.setText(path)
            self._autosuggest_encrypt_output()

    def _choose_encrypt_output(self):
        """Select a target file for saving."""
        default_name = self._get_suggested_enc_output() or self.lang_manager.tr('default_enc_filename')
        path, _ = QFileDialog.getSaveFileName(self, self.lang_manager.tr('dialog_save_enc_output'),
                                              default_name, self.lang_manager.tr('dialog_timenc_files'))
        if path:
            self.enc_output.setText(path)

    def _choose_decrypt_input(self):
        """Select a .timenc file for decryption."""
        filter = f"{self.lang_manager.tr('dialog_timenc_files')};;{self.lang_manager.tr('dialog_all_files')}"
        path, _ = QFileDialog.getOpenFileName(self, self.lang_manager.tr('dialog_choose_dec_input'),
                                              filter=filter)
        if path:
            self.dec_input.setText(path)
            self._autosuggest_decrypt_output()

    def _choose_decrypt_output(self):
        """Select a target folder for decrypted files."""
        path = QFileDialog.getExistingDirectory(self, self.lang_manager.tr('dialog_choose_dec_output'))
        if path:
            self.dec_output.setText(path)

    def _choose_keyfile(self, target_line_edit: QLineEdit):
        """Select a keyfile for the specified field."""
        path, _ = QFileDialog.getOpenFileName(self, self.lang_manager.tr('dialog_choose_keyfile'))
        if path:
            target_line_edit.setText(path)

    def _generate_keyfile(self, target_line_edit: QLineEdit):
        """Generate a new keyfile and populate the field."""
        path, _ = QFileDialog.getSaveFileName(self, self.lang_manager.tr('dialog_save_keyfile'), "timenc.keyfile")
        if not path:
            return
        
        try:
            # generate_keyfile is globally defined
            # We pass the tr_func for error messages
            self.run_task(generate_keyfile, path, tr_func=self.lang_manager.tr)
            target_line_edit.setText(path)  # Set on success
        except Exception as e:
            self._on_task_error(self.lang_manager.tr('error_generate_keyfile', error=str(e)))

    def _toggle_password_visibility(self, checked: bool):
        """Toggle password visibility."""
        # Find out which button was pressed
        sender = self.sender()
        if sender == self.enc_pwd_toggle_btn:
            target_edit = self.enc_pwd
        elif sender == self.dec_pwd_toggle_btn:
            target_edit = self.dec_pwd
        else:
            return

        if checked:
            target_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            sender.setText(self.lang_manager.tr('button_hide'))
        else:
            target_edit.setEchoMode(QLineEdit.EchoMode.Password)
            sender.setText(self.lang_manager.tr('button_show'))

    # --- Autosuggest Logic ---

    def _get_suggested_enc_output(self) -> str:
        """Suggest an output name based on input."""
        in_path_str = self.enc_input.text().strip()
        if not in_path_str:
            return ""
        
        p = Path(in_path_str)
        if not p.exists():  # Path might still be incomplete
             return f"{p.name}.timenc"

        if p.is_dir():
            return str(p.parent / f"{p.name}.timenc")
        else:
            return str(p.parent / f"{p.stem}.timenc")

    def _autosuggest_encrypt_output(self):
        """Fill output field if it's empty."""
        if not self.enc_output.text().strip():
            suggestion = self._get_suggested_enc_output()
            if suggestion:
                self.enc_output.setText(suggestion)

    def _autosuggest_decrypt_output(self):
        """Suggest the input file's folder as output folder."""
        in_path_str = self.dec_input.text().strip()
        if not in_path_str or not self.dec_output.text().strip():
            p = Path(in_path_str)
            if p.is_file():
                self.dec_output.setText(str(p.parent))
            elif p.is_dir():  # Shouldn't happen, but better safe
                self.dec_output.setText(str(p))

    # --- Crypto Action Handlers (with threading) ---

    def _run_encrypt(self):
        """Start encryption thread."""
        input_path = self.enc_input.text().strip()
        output_file = self.enc_output.text().strip()
        password = self.enc_pwd.text()  # .strip() removes potentially intended spaces
        keyfile_path = self.enc_keyfile.text().strip()
        
        if not input_path or not output_file:
            self._show_error_dialog(self.lang_manager.tr('error_all_fields'))
            return
        if not password:
             self._show_error_dialog(self.lang_manager.tr('error_no_password'))
             return

        keyfile_path_or_none = keyfile_path if keyfile_path else None
        
        self.run_task(
            encrypt, 
            input_path, 
            output_file, 
            password, 
            keyfile_path_or_none,
            tr_func=self.lang_manager.tr  # Pass translation function
        )

    def _run_decrypt(self):
        """Start decryption thread."""
        input_file = self.dec_input.text().strip()
        out_dir = self.dec_output.text().strip()
        password = self.dec_pwd.text()
        keyfile_path = self.dec_keyfile.text().strip()

        if not input_file or not out_dir:
            self._show_error_dialog(self.lang_manager.tr('error_all_fields'))
            return
        if not password:
             self._show_error_dialog(self.lang_manager.tr('error_no_password'))
             return
             
        keyfile_path_or_none = keyfile_path if keyfile_path else None

        self.run_task(
            decrypt,
            input_file,
            out_dir,
            password,
            keyfile_path_or_none,
            tr_func=self.lang_manager.tr  # Pass translation function
        )

    def run_task(self, func, *args, **kwargs):
        """Generic function to start a worker thread."""
        if self.thread is not None and self.thread.isRunning():
            # Prevent two tasks running simultaneously
            return 
            
        self.set_status(self.lang_manager.tr('status_processing'))
        self.enc_button.setEnabled(False)
        self.dec_button.setEnabled(False)

        self.thread = QThread()
        self.worker = Worker(func, *args, **kwargs)  # kwargs now contains tr_func
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self._on_task_finished)
        self.worker.error.connect(self._on_task_error)
        
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)

        self.thread.start()

    # --- Thread Callbacks & UI Feedback ---

    def set_status(self, message: str, timeout: int = 0):
        """Set the status bar."""
        if timeout > 0:
            self.status_bar.showMessage(message, timeout)
        else:
            self.status_bar.showMessage(message)

    def _on_task_error(self, message: str):
        """Called on worker error."""
        self.set_status(self.lang_manager.tr('status_error', message=message))
        self._show_error_dialog(message)
        self.enc_button.setEnabled(True)
        self.dec_button.setEnabled(True)

    def _on_task_finished(self, message: str):
        """Called on worker success."""
        self.set_status(self.lang_manager.tr('status_success', message=message))
        self._show_info_dialog(message)
        self.enc_button.setEnabled(True)
        self.dec_button.setEnabled(True)

    def _show_error_dialog(self, message: str):
        """Show error popup."""
        QMessageBox.critical(self, self.lang_manager.tr('dialog_title_error'),
                             self.lang_manager.tr('dialog_error_prefix', message=message))

    def _show_info_dialog(self, message: str):
        """Show info popup."""
        QMessageBox.information(self, self.lang_manager.tr('dialog_title_success'), message)


# -------------------------------------------------------------------
#
#                         APPLICATION STARTUP
#
# -------------------------------------------------------------------

def main():
    """Main application entry point."""
    app = QApplication(sys.argv)
    
    # Set organization and app name for QSettings
    app.setOrganizationName("Timenc")
    app.setApplicationName("TimencApp")

    # Load saved language, 'de' as default
    settings = QSettings()
    lang_code = settings.value("language", "de")
    
    # Initialize language manager
    lang_manager = LanguageManager(lang_code)

    # Apply stylesheet
    app.setStyleSheet(APP_STYLESHEET)

    # Create main window with language manager
    window = TimencApp(lang_manager)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
