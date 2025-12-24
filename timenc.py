from __future__ import annotations
import os
import sys
import struct
import tempfile
import tarfile
import secrets
from pathlib import Path
from typing import Tuple, Optional, Callable, Any, Dict
import stat
import errno
from functools import partial
import json
import re
import webbrowser
import shutil # Für effizientes Verschieben von Dateien

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# -------------------------------------------------------------------
# Configuration Constants
# -------------------------------------------------------------------

APP_VERSION = "1.2.0"
# Wir erhöhen auf 3, da Streaming eine Strukturänderung erfordert
ENCRYPTION_FORMAT_VERSION = 3 

# Streaming Konfiguration
CHUNK_SIZE = 64 * 1024  # 64 KB Blöcke für RAM-Schonung
TAG_SIZE = 16           # Poly1305 Tag Größe (fest bei ChaCha20Poly1305)

# -------------------------------------------------------------------
# UPDATE CHECKER LOGIC
# -------------------------------------------------------------------

def _parse_version(version_str: str) -> tuple[int, ...]:
    """Konvertiere Versions-String in Tuple für korrekten Vergleich (1.10.0 > 1.2.0)."""
    return tuple(map(int, version_str.split('.')))


def get_latest_release_info() -> Tuple[Optional[str], Optional[str]]:
    """
    Prüft GitHub auf Updates. 
    """
    if not REQUESTS_AVAILABLE:
        return None, None

    REPO_SLUG = "SnowTimSwiss/TimENC" 
    URL = f"https://api.github.com/repos/{REPO_SLUG}/releases"

    try:
        # Kurzes Timeout, damit die App nicht hängt
        response = requests.get(URL, timeout=3)
        
        if response.status_code != 200:
            return None, None
            
        releases = response.json()
        
        # Falls keine Releases da sind oder Format falsch
        if not releases or not isinstance(releases, list):
            return None, None

        # Wir prüfen die Releases (das erste in der Liste ist meist das neueste)
        for release in releases:
            tag_name = release.get("tag_name", "")
            html_url = release.get("html_url", "")
            
            if not tag_name:
                continue

            # Tag bereinigen: 'v1.4.2' -> '1.4.2'
            clean_version = tag_name.lstrip('v')

            if re.fullmatch(r"^(\d+\.)*\d+$", clean_version):
                return clean_version, html_url
                
    except Exception:
        return None, None

    return None, None

# -------------------------------------------------------------------
# LAZY IMPORT HELPERS
# -------------------------------------------------------------------
def get_crypto_tools():
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from argon2.low_level import hash_secret_raw, Type
    return ChaCha20Poly1305, hash_secret_raw, Type

try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QStackedWidget, QLabel, QLineEdit, QPushButton, QFormLayout,
        QFileDialog, QMessageBox, QStatusBar, QFrame, QComboBox,
        QProgressBar, QGraphicsOpacityEffect, QDialog, QListWidget,
        QListWidgetItem, QGroupBox, QGridLayout, QKeySequenceEdit,
        QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
        QDialogButtonBox, QScrollArea
    )
    from PySide6.QtCore import (
        QThread, QObject, Signal, Slot, Qt, QSettings, QSize,
        QPropertyAnimation, QEasingCurve, QTimer, QEvent
    )
    from PySide6.QtGui import QDragEnterEvent, QDropEvent, QKeySequence, QShortcut, QAction
except ImportError:
    print("Error: PySide6 not found.")
    print("Please install it using: pip install PySide6")
    sys.exit(1)


# -------------------------------------------------------------------
#                         LANGUAGE MANAGEMENT
# -------------------------------------------------------------------

LANGUAGES = {
    'de': {
        'app_title': "TimENC {version} - Sichere Verschlüsselung",
        'app_subtitle': "Sichere Dateiverschlüsselung mit Passwort und Keyfile",
        'status_ready': "✅ Bereit — {version}",
        'status_processing': "⏳ Verarbeite...",
        'status_error': "❌ Fehler: {message}",
        'status_success': "✅ Erfolg: {message}",
        'dialog_title_error': "Fehler",
        'dialog_title_success': "Erfolg",
        'dialog_error_prefix': "Ein Fehler ist aufgetreten:\n\n{message}",
        'nav_encrypt': "🔒 Verschlüsseln",
        'nav_decrypt': "🔓 Entschlüsseln",
        'nav_settings': "⚙️ Einstellungen",
        'label_file_folder': "📁 Datei / Ordner:",
        'label_output_file': "💾 Ausgabedatei:",
        'label_password': "🔑 Passwort:",
        'label_keyfile': "🗝️ Keyfile (Optional):",
        'label_timenc_file': "📄 .timenc Datei:",
        'label_output_folder': "📂 Zielordner:",
        'button_browse': "Durchsuchen",
        'button_save_as': "Speichern unter",
        'button_select_folder': "Ordner wählen",
        'button_show': "Anzeigen",
        'button_hide': "Verbergen",
        'button_select': "Wählen",
        'button_generate': "Generieren",
        'button_encrypt': "🚀 Verschlüsseln",
        'button_decrypt': "🚀 Entschlüsseln",
        'placeholder_drop_file_folder': "Datei oder Ordner hierher ziehen...",
        'placeholder_drop_keyfile': "Keyfile hierher ziehen (optional)...",
        'placeholder_drop_timenc': "Verschlüsselte .timenc Datei hierher ziehen...",
        'placeholder_output_file': "Zieldatei (z.B. geheim.timenc)",
        'placeholder_output_folder': "Zielordner für entschlüsselte Dateien",
        'default_enc_filename': "verschluesselt.timenc",
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
        'err_file_exists': "Zieldatei existiert bereits: {path}",
        'err_path_traversal': "Unzulässiger Pfad in Archiv (Path Traversal)",
        'err_input_not_found': "Eingabe nicht gefunden: {path}",
        'err_filename_too_long': "Dateiname zu lang",
        'err_input_file_not_found': "Eingabedatei nicht gefunden: {path}",
        'err_not_timenc_file': "Keine TIMENC-Datei",
        'err_decrypt_failed': "Entschlüsselung fehlgeschlagen - falsches Passwort/Keyfile oder manipulierte Datei",
        'err_keyfile_exists': "Keyfile existiert bereits: {path}",
        'ok_encrypted': "Verschlüsselt: {path}",
        'ok_decrypted_extracted': "Entschlüsselt und extrahiert nach: {path}",
        'ok_decrypted': "Entschlüsselt: {path}",
        'ok_keyfile_created': "Keyfile erstellt: {path} ({size} Bytes)",
        'label_language': "Sprache:",
        'label_lang_de': "Deutsch",
        'label_lang_en': "Englisch",
        'label_restart_info': "Änderungen werden nach einem Neustart wirksam.",
        'pwd_strength_weak': "Schwach",
        'pwd_strength_medium': "Mittel",
        'pwd_strength_strong': "Stark",
        'pwd_strength_very_strong': "Sehr stark",
        'settings_shortcuts': "Tastenkombinationen",
        'settings_general': "Allgemein",
        'shortcuts_dialog_title': "Tastenkombinationen anpassen",
        'shortcut_encrypt_tab': "Verschlüsselungs-Tab",
        'shortcut_decrypt_tab': "Entschlüsselungs-Tab",
        'shortcut_settings_tab': "Einstellungs-Tab",
        'shortcut_open_file': "Datei öffnen",
        'shortcut_save_as': "Speichern unter",
        'shortcut_quit': "Beenden",
        'shortcut_show_help': "Hilfe anzeigen",
        'shortcut_reset_all': "Alle zurücksetzen",
        'shortcut_apply': "Übernehmen",
        'button_customize_shortcuts': "Tastenkombinationen anpassen...",
        'button_reset_shortcuts': "Standard wiederherstellen",
        'button_apply_shortcuts': "Übernehmen",
        'button_cancel': "Abbrechen",
        'button_ok': "OK",
        'label_shortcut_action': "Aktion",
        'label_shortcut_key': "Tastenkombination",
        'label_current_shortcut': "Aktuelle Kombination",
        'label_new_shortcut': "Neue Kombination",
        'message_shortcut_conflict': "Tastenkombination wird bereits verwendet für: {action}",
        'message_shortcut_reset': "Alle Tastenkombinationen wurden zurückgesetzt",
        'message_shortcut_applied': "Tastenkombinationen wurden übernommen",
        'update_available_title': "Update verfügbar!",
        'update_available_msg': "Heyy, du bist nicht mehr auf der neusen version, hier kannst du die neue herunterladen.\n\nNeue Version: {version}",
        'button_download': "Herunterladen",
        'button_later': "Später",
    },
    'en': {
        'app_title': "TimENC {version} - Secure Encryption",
        'app_subtitle': "Secure file encryption with password and keyfile",
        'status_ready': "✅ Ready — {version}",
        'status_processing': "⏳ Processing...",
        'status_error': "❌ Error: {message}",
        'status_success': "✅ Success: {message}",
        'dialog_title_error': "Error",
        'dialog_title_success': "Success",
        'dialog_error_prefix': "An error occurred:\n\n{message}",
        'nav_encrypt': "🔒 Encrypt",
        'nav_decrypt': "🔓 Decrypt",
        'nav_settings': "⚙️ Settings",
        'label_file_folder': "📁 File / Folder:",
        'label_output_file': "💾 Output File:",
        'label_password': "🔑 Password:",
        'label_keyfile': "🗝️ Keyfile (Optional):",
        'label_timenc_file': "📄 .timenc File:",
        'label_output_folder': "📂 Output Folder:",
        'button_browse': "Browse",
        'button_save_as': "Save As",
        'button_select_folder': "Choose Folder",
        'button_show': "Show",
        'button_hide': "Hide",
        'button_select': "Choose",
        'button_generate': "Generate",
        'button_encrypt': "🚀 Encrypt",
        'button_decrypt': "🚀 Decrypt",
        'placeholder_drop_file_folder': "Drop file or folder here...",
        'placeholder_drop_keyfile': "Drop keyfile here (optional)...",
        'placeholder_drop_timenc': "Drop encrypted .timenc file here...",
        'placeholder_output_file': "Target file (e.g., secret.timenc)",
        'placeholder_output_folder': "Target folder for decrypted files",
        'default_enc_filename': "encrypted.timenc",
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
        'err_file_exists': "Target file already exists: {path}",
        'err_path_traversal': "Invalid path in archive (Path Traversal)",
        'err_input_not_found': "Input not found: {path}",
        'err_filename_too_long': "Filename too long",
        'err_input_file_not_found': "Input file not found: {path}",
        'err_not_timenc_file': "Not a TIMENC file",
        'err_decrypt_failed': "Decryption failed - wrong password/keyfile or tampered file",
        'err_keyfile_exists': "Keyfile already exists: {path}",
        'ok_encrypted': "Encrypted: {path}",
        'ok_decrypted_extracted': "Decrypted and extracted to: {path}",
        'ok_decrypted': "Decrypted: {path}",
        'ok_keyfile_created': "Keyfile created: {path} ({size} Bytes)",
        'label_language': "Language:",
        'label_lang_de': "German",
        'label_lang_en': "English",
        'label_restart_info': "Changes will take effect after restarting the application.",
        'pwd_strength_weak': "Weak",
        'pwd_strength_medium': "Medium",
        'pwd_strength_strong': "Strong",
        'pwd_strength_very_strong': "Very Strong",
        'settings_shortcuts': "Keyboard Shortcuts",
        'settings_general': "General",
        'shortcuts_dialog_title': "Customize Keyboard Shortcuts",
        'shortcut_encrypt_tab': "Encrypt Tab",
        'shortcut_decrypt_tab': "Decrypt Tab",
        'shortcut_settings_tab': "Settings Tab",
        'shortcut_open_file': "Open File",
        'shortcut_save_as': "Save As",
        'shortcut_quit': "Quit",
        'shortcut_show_help': "Show Help",
        'shortcut_reset_all': "Reset All",
        'shortcut_apply': "Apply",
        'button_customize_shortcuts': "Customize Shortcuts...",
        'button_reset_shortcuts': "Restore Defaults",
        'button_apply_shortcuts': "Apply",
        'button_cancel': "Cancel",
        'button_ok': "OK",
        'label_shortcut_action': "Action",
        'label_shortcut_key': "Shortcut",
        'label_current_shortcut': "Current Shortcut",
        'label_new_shortcut': "New Shortcut",
        'message_shortcut_conflict': "Shortcut already used for: {action}",
        'message_shortcut_reset': "All shortcuts have been reset to defaults",
        'message_shortcut_applied': "Shortcuts have been applied",
        'update_available_title': "Update available!",
        'update_available_msg': "Heyy, you are no longer on the latest version, you can download the new one here.\n\nNew Version: {version}",
        'button_download': "Download",
        'button_later': "Later",
    }
}


class LanguageManager:
    """Manages translations for the application."""
    
    def __init__(self, language_code: str):
        self.set_language(language_code)

    def set_language(self, language_code: str):
        self.current_lang = language_code if language_code in LANGUAGES else 'en'
        self.strings = LANGUAGES[self.current_lang]

    def tr(self, key: str, **kwargs) -> str:
        template = self.strings.get(key, f"<{key}>")
        if kwargs:
            try:
                return template.format(**kwargs)
            except KeyError:
                return f"<{key} (format error)>"
        return template


# -------------------------------------------------------------------
#                         SHORTCUT MANAGER
# -------------------------------------------------------------------

class ShortcutManager:
    """Manages keyboard shortcuts for the application."""
    
    DEFAULT_SHORTCUTS = {
        'encrypt_tab': 'Ctrl+E',
        'decrypt_tab': 'Ctrl+D',
        'settings_tab': 'Ctrl+,',
        'open_file': 'Ctrl+O',
        'save_as': 'Ctrl+Shift+S',
        'quit': 'Ctrl+Q',
        'show_help': 'F1',
        'reset_all': 'Ctrl+R',
        'apply': 'Ctrl+Return'
    }
    
    def __init__(self, settings: QSettings):
        self.settings = settings
        self.shortcuts = {}
        self.load_shortcuts()
    
    def load_shortcuts(self):
        """Load shortcuts from settings or use defaults."""
        self.shortcuts = {}
        for key, default in self.DEFAULT_SHORTCUTS.items():
            saved = self.settings.value(f"shortcuts/{key}", default)
            self.shortcuts[key] = saved
    
    def save_shortcuts(self):
        """Save shortcuts to settings."""
        for key, shortcut in self.shortcuts.items():
            self.settings.setValue(f"shortcuts/{key}", shortcut)
    
    def reset_to_defaults(self):
        """Reset all shortcuts to defaults."""
        self.shortcuts = self.DEFAULT_SHORTCUTS.copy()
        self.save_shortcuts()
    
    def set_shortcut(self, key: str, shortcut: str):
        """Set a specific shortcut."""
        self.shortcuts[key] = shortcut
        self.save_shortcuts()
    
    def get_shortcut(self, key: str) -> str:
        """Get a specific shortcut."""
        return self.shortcuts.get(key, self.DEFAULT_SHORTCUTS.get(key, ""))
    
    def get_all_shortcuts(self) -> Dict[str, str]:
        """Get all shortcuts with their descriptions."""
        descriptions = {
            'encrypt_tab': 'shortcut_encrypt_tab',
            'decrypt_tab': 'shortcut_decrypt_tab',
            'settings_tab': 'shortcut_settings_tab',
            'open_file': 'shortcut_open_file',
            'save_as': 'shortcut_save_as',
            'quit': 'shortcut_quit',
            'show_help': 'shortcut_show_help',
            'reset_all': 'shortcut_reset_all',
            'apply': 'shortcut_apply'
        }
        return {desc_key: self.shortcuts.get(key, "") for key, desc_key in descriptions.items()}


# -------------------------------------------------------------------
#                         CORE ENCRYPTION LOGIC
# -------------------------------------------------------------------

MAGIC = b"TIMENC"
VERSION = ENCRYPTION_FORMAT_VERSION

ARGON2_TIME = 4
ARGON2_MEMORY_KIB = 131072
ARGON2_PARALLELISM = 4
KEY_LEN = 32
SALT_SIZE = 16
NONCE_SIZE = 12


def _get_tr_func(kwargs: dict[str, Any]) -> Callable:
    tr_func = kwargs.get('tr_func')
    if tr_func and isinstance(tr_func, Callable):
        return tr_func
    return lambda key, **kwa: key


def derive_key(password: bytes, salt: bytes, time_cost: int, memory_kib: int, 
               parallelism: int, keyfile_bytes: Optional[bytes] = None) -> bytes:
    # LAZY LOAD: Krypto erst hier laden
    _, hash_secret_raw, Type = get_crypto_tools()
    
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


def secure_delete(path: Path):
    """
    Überschreibt eine Datei mit Nullen vor dem Löschen.
    """
    try:
        if path.exists():
            length = path.stat().st_size
            with open(path, "wb") as f:
                # In Blöcken überschreiben um RAM zu sparen bei großen Temp-Dateien
                remaining = length
                block_size = 65536
                zeros = b'\0' * block_size
                while remaining > 0:
                    towrite = min(block_size, remaining)
                    f.write(zeros[:towrite])
                    remaining -= towrite
            path.unlink()
    except Exception:
        pass # Best effort

def _make_tar_if_needed(path: Path) -> Tuple[Path, bool]:
    """
    Erstellt ein Tar-Archiv, wenn der Input ein Ordner ist.
    Gibt (Pfad_zur_Datei, Ist_Temporär) zurück.
    """
    if path.is_file():
        return path, False
        
    final_dir = Path(tempfile.mkdtemp())
    tmp = final_dir / f"{path.name}.tar"
    try:
        with tarfile.open(str(tmp), "w") as tar:
            tar.add(str(path), arcname=path.name, recursive=True)
    except Exception:
        try:
            if tmp.exists(): secure_delete(tmp)
            if final_dir.exists(): shutil.rmtree(str(final_dir))
        except Exception:
            pass
        raise
    return tmp, True


def _is_within_directory(directory: str, target: str) -> bool:
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)
    try:
        return os.path.commonpath([abs_directory]) == os.path.commonpath([abs_directory, abs_target])
    except Exception:
        return False


def safe_extract(tar: tarfile.TarFile, path: str, **kwargs) -> None:
    tr_func = _get_tr_func(kwargs)
    for member in tar.getmembers():
        member_path = os.path.join(path, member.name)
        if not _is_within_directory(path, member_path):
            raise Exception(tr_func('err_path_traversal'))
    tar.extractall(path=path)

# ==============================================================================
# STREAMING ENCRYPTION LOGIC (V3)
# ==============================================================================

def encrypt(input_path: str, output_file: str, password: str, 
            keyfile_path: Optional[str] = None, **kwargs) -> str:
    ChaCha20Poly1305, _, _ = get_crypto_tools()
    tr_func = _get_tr_func(kwargs)
    
    inp = Path(input_path)
    if not inp.exists():
        raise FileNotFoundError(tr_func('err_input_not_found', path=input_path))
        
    file_to_encrypt, tmp_created = _make_tar_if_needed(inp)
    original_name = file_to_encrypt.name
    is_dir = 1 if tmp_created else 0
    
    key_ba = bytearray()
    
    try:
        salt = os.urandom(SALT_SIZE)
        keyfile_bytes = Path(keyfile_path).read_bytes() if keyfile_path else None
        
        key = derive_key(
            password.encode("utf-8"), salt,
            ARGON2_TIME, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM,
            keyfile_bytes
        )
        key_ba = bytearray(key)
        
        # Base nonce (wird in V3 pro Chunk hochgezählt)
        base_nonce = os.urandom(NONCE_SIZE)

        # Header Konstruktion
        name_bytes = original_name.encode("utf-8")
        if len(name_bytes) > 65535:
            raise ValueError(tr_func('err_filename_too_long'))
        
        header = bytearray()
        header += MAGIC
        header += bytes([VERSION]) # V3
        header += bytes([is_dir])
        header += _pack_u16(len(name_bytes))
        header += name_bytes
        header += salt
        header += _pack_u32(ARGON2_TIME)
        header += _pack_u32(ARGON2_MEMORY_KIB)
        header += bytes([ARGON2_PARALLELISM])
        header += base_nonce

        # AEAD Setup
        aead = ChaCha20Poly1305(bytes(key_ba))
        
        # Konvertiere base_nonce in int zum Inkrementieren
        nonce_int = int.from_bytes(base_nonce, 'big')

        # Streaming Loop
        with open(file_to_encrypt, "rb") as f_in, open(output_file, "wb") as f_out:
            # 1. Header schreiben
            f_out.write(header)
            
            # 2. Chunk-Verschlüsselung
            chunk_counter = 0
            while True:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                # Berechne Nonce für diesen Chunk: Base + Counter
                current_nonce_int = nonce_int + chunk_counter
                # Überlauf verhindern (wrap around bei 96 bit)
                current_nonce_int %= (2**96) 
                current_nonce = current_nonce_int.to_bytes(NONCE_SIZE, 'big')
                
                # Chunk verschlüsseln (Kein AAD für Chunks hier, Kontext ist durch Key/Nonce gegeben)
                ciphertext = aead.encrypt(current_nonce, chunk, None)
                
                f_out.write(ciphertext)
                chunk_counter += 1
            
        return tr_func('ok_encrypted', path=output_file)
        
    finally:
        # Speicher bereinigen
        for i in range(len(key_ba)):
            key_ba[i] = 0
        if tmp_created:
            secure_delete(file_to_encrypt)
            # Auch temporäres Verzeichnis löschen falls vorhanden
            if file_to_encrypt.parent.name.startswith("tmp"):
                try: shutil.rmtree(str(file_to_encrypt.parent))
                except: pass

# ==============================================================================
# STREAMING DECRYPTION LOGIC (V2 & V3 COMPATIBLE)
# ==============================================================================

def decrypt(input_file: str, out_dir: str, password: str, 
            keyfile_path: Optional[str] = None, **kwargs) -> str:
    ChaCha20Poly1305, _, _ = get_crypto_tools()
    tr_func = _get_tr_func(kwargs)
    
    enc = Path(input_file)
    if not enc.exists():
        raise FileNotFoundError(tr_func('err_input_file_not_found', path=input_file))

    key_ba = bytearray()
    
    # 1. Header Informationen lesen
    with open(enc, "rb") as f_in:
        magic = f_in.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError(tr_func('err_not_timenc_file'))
        
        version = ord(f_in.read(1))
        is_dir = ord(f_in.read(1))
        name_len = _unpack_u16(f_in.read(2))
        original_name = f_in.read(name_len).decode("utf-8")
        salt = f_in.read(SALT_SIZE)
        time_cost = _unpack_u32(f_in.read(4))
        memory_kib = _unpack_u32(f_in.read(4))
        parallelism = ord(f_in.read(1))
        nonce = f_in.read(NONCE_SIZE)
        
        header_end_pos = f_in.tell()

        # Schlüssel ableiten
        keyfile_bytes = Path(keyfile_path).read_bytes() if keyfile_path else None
        key = derive_key(password.encode("utf-8"), salt, time_cost, memory_kib, parallelism, keyfile_bytes)
        key_ba = bytearray(key)
        aead = ChaCha20Poly1305(bytes(key_ba))
        
        # Temporäre Datei für entschlüsselte Daten
        fd, tmp_name = tempfile.mkstemp()
        os.close(fd)
        tmp_path = Path(tmp_name)
            
        try:
            # --- LEGACY V2 SUPPORT (Alles in RAM laden) ---
            if version == 2:
                f_in.seek(0)
                header_len = header_end_pos
                header_bytes = f_in.read(header_len)
                ciphertext = f_in.read()
                
                try:
                    plaintext = aead.decrypt(nonce, ciphertext, header_bytes)
                    with open(tmp_path, "wb") as f_tmp:
                        f_tmp.write(plaintext)
                    # RAM säubern
                    del plaintext
                except Exception:
                    raise ValueError(tr_func('err_decrypt_failed'))

            # --- V3 SUPPORT (Streaming) ---
            elif version == 3:
                nonce_int = int.from_bytes(nonce, 'big')
                chunk_counter = 0
                
                # Verschlüsselte Chunk Größe = Plaintext Chunk + Tag Size (16 bytes für Poly1305)
                enc_chunk_size = CHUNK_SIZE + TAG_SIZE
                
                with open(tmp_path, "wb") as f_tmp:
                    while True:
                        # Verschlüsselten Chunk lesen
                        chunk_data = f_in.read(enc_chunk_size)
                        if not chunk_data:
                            break
                            
                        current_nonce_int = nonce_int + chunk_counter
                        current_nonce_int %= (2**96)
                        current_nonce = current_nonce_int.to_bytes(NONCE_SIZE, 'big')
                        
                        try:
                            # Chunk entschlüsseln
                            plaintext_chunk = aead.decrypt(current_nonce, chunk_data, None)
                            f_tmp.write(plaintext_chunk)
                        except Exception:
                            raise ValueError(tr_func('err_decrypt_failed'))
                        
                        chunk_counter += 1
            else:
                 raise ValueError(f"Unsupported version: {version}")

        except Exception as e:
            # Aufräumen bei Fehler
            secure_delete(tmp_path)
            raise e
            
    # Key aus RAM löschen
    for i in range(len(key_ba)):
        key_ba[i] = 0

    # Finalisierung: Extrahieren oder Verschieben
    outp = Path(out_dir)
    outp.mkdir(parents=True, exist_ok=True)
    
    try:
        if is_dir == 1:
            with tarfile.open(tmp_path, "r") as tar:
                safe_extract(tar, str(outp), tr_func=tr_func)
            secure_delete(tmp_path)
            return tr_func('ok_decrypted_extracted', path=str(outp))
        else:
            target = outp / (original_name or "decrypted_file")
            if target.exists():
                secure_delete(tmp_path)
                raise FileExistsError(tr_func('err_file_exists', path=str(target)))
            
            # Atomic Move (oder copy+delete)
            shutil.move(str(tmp_path), str(target))
            return tr_func('ok_decrypted', path=str(target))
            
    except Exception as e:
        if tmp_path.exists(): secure_delete(tmp_path)
        raise e


def generate_keyfile(path: str, size: int = 32, **kwargs) -> str:
    tr_func = _get_tr_func(kwargs)
    key_material = secrets.token_bytes(size)
    
    p = Path(path)
    if p.exists():
        raise FileExistsError(tr_func('err_keyfile_exists', path=path))
        
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(str(p), flags, 0o600)
    
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(key_material)
            f.flush()
            os.fsync(f.fileno())
    finally:
        try:
            km = bytearray(key_material)
            for i in range(len(km)):
                km[i] = 0
            del km
        except Exception:
            pass
            
    return tr_func('ok_keyfile_created', path=path, size=size)


# -------------------------------------------------------------------
#                         MODERN UI STYLESHEET
# -------------------------------------------------------------------

APP_STYLESHEET = """
/* ===== MODERN DESIGN SYSTEM ===== */

/* Base Colors & Typography */
QWidget {
    background-color: #0D1117;
    color: #E6EDF3;
    font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, 'Helvetica Neue', Arial, sans-serif;
    font-size: 14px;
}

QMainWindow {
    background-color: #0D1117;
}

/* ===== NAVIGATION SIDEBAR ===== */
QWidget#NavWidget {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #161B22, stop:1 #0D1117);
    border-right: 1px solid #21262D;
}

QLabel#Header {
    font-size: 26px;
    font-weight: 700;
    color: #58A6FF;
    padding: 25px 15px 20px 15px;
    background-color: transparent;
    letter-spacing: 0.5px;
}

/* Navigation Buttons */
QPushButton#NavButton {
    background-color: transparent;
    border: none;
    color: #7D8590;
    padding: 14px 20px;
    font-size: 15px;
    font-weight: 600;
    text-align: left;
    border-radius: 6px;
    margin: 3px 8px;
}

QPushButton#NavButton:hover {
    background-color: rgba(177, 186, 196, 0.12);
    color: #C9D1D9;
}

QPushButton#NavButton:checked {
    background-color: rgba(88, 166, 255, 0.15);
    color: #58A6FF;
    border-left: 3px solid #58A6FF;
    border-radius: 6px 0 0 6px;
}

/* ===== CONTENT AREA ===== */
QLabel#PageHeader {
    font-size: 32px;
    font-weight: 700;
    color: #E6EDF3;
    padding-bottom: 8px;
    background-color: transparent;
    letter-spacing: -0.5px;
}

QLabel#SubHeader {
    font-size: 14px;
    color: #7D8590;
    padding-bottom: 20px;
    background-color: transparent;
}

/* Form Container */
QFrame#TabContainer {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #161B22, stop:1 #0D1117);
    border: 1px solid #21262D;
    border-radius: 12px;
    padding: 28px;
    color: #E6EDF3;
}

/* ===== INPUT FIELDS ===== */
QLineEdit, QComboBox {
    background-color: #0D1117;
    border: 1.5px solid #30363D;
    border-radius: 6px;
    padding: 10px 14px;
    color: #E6EDF3;
    selection-background-color: #1F6FEB;
    font-size: 14px;
}

QLineEdit:hover, QComboBox:hover {
    border-color: #484F58;
}

QLineEdit:focus, QComboBox:focus {
    border-color: #58A6FF;
    background-color: #161B22;
}

QLineEdit:disabled, QComboBox:disabled {
    background-color: #161B22;
    color: #484F58;
    border-color: #21262D;
}

/* Dropdown Styling */
QComboBox::drop-down {
    border: none;
    width: 25px;
    padding-right: 8px;
}

QComboBox::down-arrow {
    image: none;
    border-left: 5px solid transparent;
    border-right: 5px solid transparent;
    border-top: 6px solid #7D8590;
    width: 0;
    height: 0;
}

QComboBox QAbstractItemView {
    background-color: #161B22;
    border: 1px solid #30363D;
    border-radius: 6px;
    selection-background-color: #1F6FEB;
    color: #E6EDF3;
    outline: none;
    padding: 4px;
}

/* Key Sequence Edit */
QKeySequenceEdit {
    background-color: #0D1117;
    border: 1.5px solid #30363D;
    border-radius: 6px;
    padding: 10px 14px;
    color: #E6EDF3;
    font-size: 14px;
}

QKeySequenceEdit:hover {
    border-color: #484F58;
}

QKeySequenceEdit:focus {
    border-color: #58A6FF;
    background-color: #161B22;
}

/* Table Widget */
QTableWidget {
    background-color: #0D1117;
    border: 1px solid #30363D;
    border-radius: 6px;
    gridline-color: #30363D;
    alternate-background-color: #161B22;
}

QTableWidget::item {
    padding: 8px;
    border-bottom: 1px solid #21262D;
}

QTableWidget::item:selected {
    background-color: #1F6FEB;
    color: #FFFFFF;
}

QHeaderView::section {
    background-color: #161B22;
    color: #C9D1D9;
    padding: 12px;
    border: none;
    border-right: 1px solid #21262D;
    border-bottom: 1px solid #21262D;
    font-weight: 600;
}

QHeaderView::section:last {
    border-right: none;
}

/* ===== BUTTONS ===== */

/* Standard Buttons */
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #21262D, stop:1 #161B22);
    color: #C9D1D9;
    border: 1px solid #30363D;
    padding: 9px 18px;
    border-radius: 6px;
    font-weight: 600;
    font-size: 14px;
}

QPushButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #30363D, stop:1 #21262D);
    border-color: #484F58;
}

QPushButton:pressed {
    background-color: #161B22;
    border-color: #484F58;
}

QPushButton:disabled {
    background-color: #0D1117;
    color: #484F58;
    border-color: #21262D;
}

/* Primary Action Buttons */
QPushButton#ActionButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #1F6FEB, stop:1 #1158C7);
    color: #FFFFFF;
    font-size: 16px;
    font-weight: 700;
    padding: 14px 32px;
    border: none;
    border-radius: 8px;
}

QPushButton#ActionButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #388BFD, stop:1 #1F6FEB);
}

QPushButton#ActionButton:pressed {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #1158C7, stop:1 #0D419D);
}

QPushButton#ActionButton:disabled {
    background-color: #21262D;
    color: #484F58;
}

/* Password Toggle Button */
QPushButton#TogglePasswordButton {
    background-color: #21262D;
    color: #7D8590;
    padding: 10px 16px;
    border: 1px solid #30363D;
    border-left: none;
    border-radius: 0 6px 6px 0;
    margin: 0;
    min-width: 70px;
    font-weight: 600;
}

QPushButton#TogglePasswordButton:hover {
    background-color: #30363D;
    color: #C9D1D9;
}

QPushButton#TogglePasswordButton:checked {
    background-color: #1F6FEB;
    color: #FFFFFF;
}

/* Dialog Buttons */
QDialogButtonBox {
    background-color: transparent;
    border-top: 1px solid #21262D;
    padding-top: 20px;
}

QDialogButtonBox QPushButton {
    min-width: 80px;
}

/* ===== PROGRESS BAR ===== */
QProgressBar {
    background-color: #161B22;
    border: 1px solid #30363D;
    border-radius: 6px;
    text-align: center;
    color: #C9D1D9;
    font-weight: 600;
    height: 24px;
}

QProgressBar::chunk {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                                stop:0 #1F6FEB, stop:1 #58A6FF);
    border-radius: 5px;
}

/* Password Strength Indicator */
QProgressBar#PasswordStrength {
    background-color: #161B22;
    border: 1px solid #30363D;
    border-radius: 4px;
    height: 6px;
    text-align: center;
}

QProgressBar#PasswordStrength::chunk {
    border-radius: 3px;
}

QProgressBar#WeakPassword::chunk {
    background-color: #F85149;
}

QProgressBar#MediumPassword::chunk {
    background-color: #D29922;
}

QProgressBar#StrongPassword::chunk {
    background-color: #3FB950;
}

QProgressBar#VeryStrongPassword::chunk {
    background-color: #56D364;
}

/* ===== STATUS BAR ===== */
QStatusBar {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                                stop:0 #0D1117, stop:1 #161B22);
    color: #7D8590;
    border-top: 1px solid #21262D;
    padding: 10px 15px;
    font-size: 13px;
}

QStatusBar::item {
    border: none;
}

/* ===== LABELS ===== */
QLabel {
    color: #C9D1D9;
    background-color: transparent;
    font-weight: 500;
}

/* Group Box */
QGroupBox {
    border: 1px solid #30363D;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 10px;
    font-weight: 600;
    color: #C9D1D9;
    background-color: #161B22;
}

QGroupBox::title {
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    padding: 0 8px;
    background-color: #161B22;
}

/* ===== SCROLLBARS ===== */
QScrollBar:vertical {
    background: #0D1117;
    width: 14px;
    margin: 0;
    border-radius: 7px;
}

QScrollBar::handle:vertical {
    background: #30363D;
    border-radius: 7px;
    min-height: 30px;
}

QScrollBar::handle:vertical:hover {
    background: #484F58;
}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
    height: 0;
}

QScrollBar:horizontal {
    background: #0D1117;
    height: 14px;
    margin: 0;
    border-radius: 7px;
}

QScrollBar::handle:horizontal {
    background: #30363D;
    border-radius: 7px;
    min-width: 30px;
}

QScrollBar::handle:horizontal:hover {
    background: #484F58;
}

QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
    width: 0;
}

/* ===== NEW STYLES FOR SHORTCUTS TABLE ===== */
QTableWidget#ShortcutsTable {
    border: 1px solid #30363D;
    border-radius: 6px;
    background-color: #0D1117;
    gridline-color: #30363D;
}

QTableWidget#ShortcutsTable::item:hover {
    background-color: rgba(88, 166, 255, 0.1);
}

QPushButton#ShortcutDialogButton {
    min-width: 120px;
    font-weight: 600;
}

/* ===== SHORTCUT DISPLAY LIST ===== */
QListWidget#ShortcutDisplayList {
    border: 1px solid #30363D;
    border-radius: 6px;
    background-color: #0D1117;
    padding: 4px;
    max-height: 200px;
}

QListWidget#ShortcutDisplayList::item {
    padding: 10px 15px;
    border-bottom: 1px solid #21262D;
}

QListWidget#ShortcutDisplayList::item:last {
    border-bottom: none;
}

QListWidget#ShortcutDisplayList::item:alternate {
    background-color: #161B22;
}

QListWidget#ShortcutDisplayList::item:hover {
    background-color: rgba(88, 166, 255, 0.1);
}
"""


# -------------------------------------------------------------------
#                         PASSWORD STRENGTH CHECKER
# -------------------------------------------------------------------

def check_password_strength(password: str) -> Tuple[int, str]:
    """
    Returns (strength_percent, strength_label)
    0 = Weak, 1 = Medium, 2 = Strong, 3 = Very Strong
    """
    if not password:
        return 0, ""
    
    score = 0
    length = len(password)
    
    # Length scoring
    if length >= 8:
        score += 25
    if length >= 12:
        score += 15
    if length >= 16:
        score += 10
    
    # Character variety
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    variety = sum([has_lower, has_upper, has_digit, has_special])
    score += variety * 12
    
    # Cap at 100
    score = min(score, 100)
    
    # Determine label
    if score < 40:
        return score, "weak"
    elif score < 70:
        return score, "medium"
    elif score < 90:
        return score, "strong"
    else:
        return score, "very_strong"


# -------------------------------------------------------------------
#                         WORKER THREAD
# -------------------------------------------------------------------

class Worker(QObject):
    finished = Signal(str)
    error = Signal(str)
    progress = Signal(int)

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs

    @Slot()
    def run(self):
        try:
            result_message = self.func(*self.args, **self.kwargs)
            self.finished.emit(result_message)
        except Exception as e:
            self.error.emit(str(e))


# -------------------------------------------------------------------
#                         DRAG & DROP INPUT
# -------------------------------------------------------------------

class DropLineEdit(QLineEdit):
    file_dropped = Signal(str)

    def __init__(self, placeholder_text="", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder_text)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent):
        if event.mimeData().hasUrls():
            url = event.mimeData().urls()[0]
            path = url.toLocalFile()
            self.setText(path)
            self.file_dropped.emit(path)
            event.acceptProposedAction()
        else:
            event.ignore()


# -------------------------------------------------------------------
#                         SHORTCUTS DIALOG
# -------------------------------------------------------------------

class ShortcutsDialog(QDialog):
    """Dialog to customize keyboard shortcuts."""
    
    def __init__(self, shortcut_manager: ShortcutManager, lang_manager: LanguageManager, parent=None):
        super().__init__(parent)
        self.shortcut_manager = shortcut_manager
        self.lang_manager = lang_manager
        self.current_shortcuts = shortcut_manager.get_all_shortcuts()
        self.new_shortcuts = self.current_shortcuts.copy()
        self.init_ui()
        self.load_current_shortcuts()
        
    def init_ui(self):
        self.setWindowTitle(self.lang_manager.tr('shortcuts_dialog_title'))
        self.setMinimumSize(750, 550)
        self.setWindowModality(Qt.WindowModality.ApplicationModal)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(15)
        
        # Create scrollable area for table
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setFrameShape(QFrame.Shape.NoFrame)
        
        # Create container for table
        container_widget = QWidget()
        container_layout = QVBoxLayout(container_widget)
        container_layout.setContentsMargins(0, 0, 0, 0)
        
        # Create table for shortcuts
        self.table = QTableWidget()
        self.table.setObjectName("ShortcutsTable")
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels([
            self.lang_manager.tr('label_shortcut_action'),
            self.lang_manager.tr('label_current_shortcut'),
            self.lang_manager.tr('label_new_shortcut')
        ])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setAlternatingRowColors(True)
        self.table.setShowGrid(True)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        
        # Set column widths
        self.table.setColumnWidth(0, 280)
        self.table.setColumnWidth(1, 140)
        
        container_layout.addWidget(self.table)
        scroll_area.setWidget(container_widget)
        layout.addWidget(scroll_area)

        # Button layout
        button_layout = QHBoxLayout()
        
        self.reset_button = QPushButton(self.lang_manager.tr('button_reset_shortcuts'))
        self.reset_button.setObjectName("ShortcutDialogButton")
        self.reset_button.clicked.connect(self.reset_to_defaults)
        
        button_layout.addWidget(self.reset_button)
        button_layout.addStretch()
        
        self.button_box = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | 
            QDialogButtonBox.StandardButton.Apply | 
            QDialogButtonBox.StandardButton.Cancel
        )
        
        self.button_box.button(QDialogButtonBox.StandardButton.Ok).setText(self.lang_manager.tr('button_ok'))
        self.button_box.button(QDialogButtonBox.StandardButton.Apply).setText(self.lang_manager.tr('button_apply_shortcuts'))
        self.button_box.button(QDialogButtonBox.StandardButton.Cancel).setText(self.lang_manager.tr('button_cancel'))
        
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        self.button_box.button(QDialogButtonBox.StandardButton.Apply).clicked.connect(self.apply_shortcuts)
        
        button_layout.addWidget(self.button_box)
        layout.addLayout(button_layout)
        
        # Connect table signals
        self.table.cellChanged.connect(self.on_cell_changed)
        
    def load_current_shortcuts(self):
        """Load current shortcuts into the table."""
        shortcuts_mapping = {
            'encrypt_tab': self.lang_manager.tr('shortcut_encrypt_tab'),
            'decrypt_tab': self.lang_manager.tr('shortcut_decrypt_tab'),
            'settings_tab': self.lang_manager.tr('shortcut_settings_tab'),
            'open_file': self.lang_manager.tr('shortcut_open_file'),
            'save_as': self.lang_manager.tr('shortcut_save_as'),
            'quit': self.lang_manager.tr('shortcut_quit'),
            'show_help': self.lang_manager.tr('shortcut_show_help'),
            'reset_all': self.lang_manager.tr('shortcut_reset_all'),
            'apply': self.lang_manager.tr('shortcut_apply')
        }
        
        # Map internal keys to display names
        internal_to_display = {
            'encrypt_tab': 'shortcut_encrypt_tab',
            'decrypt_tab': 'shortcut_decrypt_tab',
            'settings_tab': 'shortcut_settings_tab',
            'open_file': 'shortcut_open_file',
            'save_as': 'shortcut_save_as',
            'quit': 'shortcut_quit',
            'show_help': 'shortcut_show_help',
            'reset_all': 'shortcut_reset_all',
            'apply': 'shortcut_apply'
        }
        
        self.table.setRowCount(len(internal_to_display))
        
        for row, (internal_key, display_key) in enumerate(internal_to_display.items()):
            # Action name
            action_item = QTableWidgetItem(shortcuts_mapping[internal_key])
            action_item.setFlags(action_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 0, action_item)
            
            # Current shortcut
            current_shortcut = self.current_shortcuts.get(display_key, "")
            current_item = QTableWidgetItem(current_shortcut)
            current_item.setFlags(current_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.table.setItem(row, 1, current_item)
            
            # New shortcut editor
            shortcut_edit = QKeySequenceEdit()
            if current_shortcut:
                shortcut_edit.setKeySequence(QKeySequence(current_shortcut))
            shortcut_edit.keySequenceChanged.connect(lambda seq, r=row: self._on_shortcut_changed(r, seq))
            shortcut_edit.clearButtonEnabled = True
            self.table.setCellWidget(row, 2, shortcut_edit)
            
            # Store internal key reference
            shortcut_edit.internal_key = internal_key
        
        self.table.resizeColumnsToContents()
        
    def _on_shortcut_changed(self, row, sequence):
        """Handle shortcut changes."""
        shortcut_edit = self.table.cellWidget(row, 2)
        if shortcut_edit:
            internal_key = getattr(shortcut_edit, 'internal_key', None)
            if internal_key:
                self.new_shortcuts[internal_key] = sequence.toString(QKeySequence.SequenceFormat.NativeText)
        
    def on_cell_changed(self, row, column):
        """Handle cell changes - not used directly since we use QKeySequenceEdit widgets."""
        pass
        
    def get_shortcuts_from_table(self):
        """Extract shortcuts from the table."""
        shortcuts = {}
        for row in range(self.table.rowCount()):
            shortcut_edit = self.table.cellWidget(row, 2)
            
            if shortcut_edit:
                internal_key = getattr(shortcut_edit, 'internal_key', None)
                if internal_key:
                    key_sequence = shortcut_edit.keySequence()
                    shortcuts[internal_key] = key_sequence.toString(QKeySequence.SequenceFormat.NativeText)
        
        return shortcuts
        
    def check_for_conflicts(self, shortcuts: Dict[str, str]) -> Optional[str]:
        """Check for duplicate shortcuts."""
        used_shortcuts = {}
        for internal_key, shortcut in shortcuts.items():
            if shortcut and shortcut in used_shortcuts:
                # Get the display name for the conflicting action
                conflicting_key = used_shortcuts[shortcut]
                return f"{self.get_action_display_name(conflicting_key)} ({shortcut})"
            if shortcut:
                used_shortcuts[shortcut] = internal_key
        return None
        
    def get_action_display_name(self, internal_key: str) -> str:
        """Get display name for an internal key."""
        mapping = {
            'encrypt_tab': self.lang_manager.tr('shortcut_encrypt_tab'),
            'decrypt_tab': self.lang_manager.tr('shortcut_decrypt_tab'),
            'settings_tab': self.lang_manager.tr('shortcut_settings_tab'),
            'open_file': self.lang_manager.tr('shortcut_open_file'),
            'save_as': self.lang_manager.tr('shortcut_save_as'),
            'quit': self.lang_manager.tr('shortcut_quit'),
            'show_help': self.lang_manager.tr('shortcut_show_help'),
            'reset_all': self.lang_manager.tr('shortcut_reset_all'),
            'apply': self.lang_manager.tr('shortcut_apply')
        }
        return mapping.get(internal_key, internal_key)
        
    def apply_shortcuts(self):
        """Apply the shortcuts from the table."""
        shortcuts = self.get_shortcuts_from_table()
        
        # Check for conflicts
        conflict = self.check_for_conflicts(shortcuts)
        if conflict:
            QMessageBox.warning(
                self,
                self.lang_manager.tr('dialog_title_error'),
                self.lang_manager.tr('message_shortcut_conflict', action=conflict)
            )
            return
        
        # Apply shortcuts
        for internal_key, shortcut in shortcuts.items():
            self.shortcut_manager.set_shortcut(internal_key, shortcut)
        
        # Update current shortcuts display
        for row in range(self.table.rowCount()):
            shortcut_edit = self.table.cellWidget(row, 2)
            if shortcut_edit:
                internal_key = getattr(shortcut_edit, 'internal_key', None)
                if internal_key:
                    current_shortcut = shortcuts.get(internal_key, "")
                    current_item = QTableWidgetItem(current_shortcut)
                    current_item.setFlags(current_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                    self.table.setItem(row, 1, current_item)
        
        QMessageBox.information(
            self,
            self.lang_manager.tr('dialog_title_success'),
            self.lang_manager.tr('message_shortcut_applied')
        )
        
    def reset_to_defaults(self):
        """Reset all shortcuts to defaults."""
        reply = QMessageBox.question(
            self,
            self.lang_manager.tr('dialog_title_success'),
            "Alle Tastenkombinationen auf Standard zurücksetzen?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.shortcut_manager.reset_to_defaults()
            self.load_current_shortcuts()
            QMessageBox.information(
                self,
                self.lang_manager.tr('dialog_title_success'),
                self.lang_manager.tr('message_shortcut_reset')
            )
            
    def accept(self):
        """Apply shortcuts and close dialog."""
        self.apply_shortcuts()
        super().accept()


# -------------------------------------------------------------------
#                         MAIN APPLICATION
# -------------------------------------------------------------------

class TimencApp(QMainWindow):
    
    def __init__(self, lang_manager: LanguageManager, file_to_open: Optional[str] = None):
        super().__init__()
        self.thread = None
        self.worker = None
        self.lang_manager = lang_manager
        self.settings = QSettings("Timenc", "TimencApp")
        self.shortcut_manager = ShortcutManager(self.settings)

        self.setWindowTitle(self.lang_manager.tr('app_title', version=APP_VERSION))
        self.setGeometry(100, 100, 1100, 750)
        self.setMinimumSize(900, 650)

        # Central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QHBoxLayout(central_widget)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)

        # Create UI components
        self._create_nav_ui()
        self._create_content_ui()

        main_layout.addWidget(self.nav_widget)
        main_layout.addWidget(self.stacked_widget)

        main_layout.setStretch(0, 2)
        main_layout.setStretch(1, 7)

        # Status bar with progress
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setMaximumWidth(200)
        self.status_bar.addPermanentWidget(self.progress_bar)
        
        self.set_status(self.lang_manager.tr('status_ready', version=APP_VERSION))

        # Connect signals
        self.enc_input.file_dropped.connect(self._autosuggest_encrypt_output)
        self.enc_input.textChanged.connect(self._autosuggest_encrypt_output)
        self.dec_input.file_dropped.connect(self._autosuggest_decrypt_output)
        self.dec_input.textChanged.connect(self._autosuggest_decrypt_output)
        
        # Password strength indicators - ONLY for encryption
        self.enc_pwd.textChanged.connect(self._update_enc_password_strength)

        # Keyboard shortcuts
        self._setup_shortcuts()

        # Navigate to default page
        self._navigate(0, self.nav_encrypt_btn)
        
        # Handle command line file
        if file_to_open:
            if os.path.isfile(file_to_open) and file_to_open.endswith(".timenc"):
                self.dec_input.setText(file_to_open)
                self._autosuggest_decrypt_output()
                self._navigate(1, self.nav_decrypt_btn)

        # CHECK FOR UPDATES (Timer starts after 3 seconds to not block UI load)
        QTimer.singleShot(3000, self._check_updates_silently)

    def _check_updates_silently(self):
        """Checks for updates without blocking main thread excessively or showing errors."""
        try:
            latest_v, url = get_latest_release_info()
            if latest_v and _parse_version(latest_v) > _parse_version(APP_VERSION):
                self._show_update_dialog(latest_v, url)
        except Exception:
            pass

    def _show_update_dialog(self, version, url):
        """Shows the popup for a found update."""
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(self.lang_manager.tr('update_available_title'))
        msg_box.setText(self.lang_manager.tr('update_available_msg', version=version))
        msg_box.setIcon(QMessageBox.Icon.Information)
        
        # Buttons
        btn_download = msg_box.addButton(self.lang_manager.tr('button_download'), QMessageBox.ButtonRole.AcceptRole)
        msg_box.addButton(self.lang_manager.tr('button_later'), QMessageBox.ButtonRole.RejectRole)
        
        msg_box.exec()
        
        if msg_box.clickedButton() == btn_download:
            webbrowser.open(url)

    def _setup_shortcuts(self):
        """Setup keyboard shortcuts from shortcut manager."""
        # Clear existing shortcuts
        for shortcut in getattr(self, '_shortcuts', []):
            if shortcut:
                try:
                    shortcut.setEnabled(False)
                except:
                    pass
        
        self._shortcuts = []
        
        # Create shortcuts from manager
        shortcuts_config = {
            'encrypt_tab': lambda: self._navigate(0, self.nav_encrypt_btn),
            'decrypt_tab': lambda: self._navigate(1, self.nav_decrypt_btn),
            'settings_tab': lambda: self._navigate(2, self.nav_settings_btn),
            'open_file': self._shortcut_open_file,
            'save_as': self._shortcut_save_as,
            'quit': self.close,
            'show_help': self._shortcut_show_help,
            'reset_all': self._shortcut_reset_all,
            'apply': self._shortcut_apply
        }
        
        for key, callback in shortcuts_config.items():
            shortcut_str = self.shortcut_manager.get_shortcut(key)
            if shortcut_str:
                try:
                    shortcut = QShortcut(QKeySequence(shortcut_str), self)
                    shortcut.activated.connect(callback)
                    self._shortcuts.append(shortcut)
                except Exception as e:
                    print(f"Error setting shortcut {key}: {e}")
    
    def _shortcut_open_file(self):
        """Handle open file shortcut."""
        current_page = self.stacked_widget.currentIndex()
        if current_page == 0:  # Encrypt tab
            self._choose_encrypt_input()
        elif current_page == 1:  # Decrypt tab
            self._choose_decrypt_input()
    
    def _shortcut_save_as(self):
        """Handle save as shortcut."""
        current_page = self.stacked_widget.currentIndex()
        if current_page == 0:  # Encrypt tab
            self._choose_encrypt_output()
    
    def _shortcut_show_help(self):
        """Show help dialog."""
        shortcuts_text = []
        all_shortcuts = self.shortcut_manager.get_all_shortcuts()
        
        # Sort for consistent display
        sorted_items = sorted(all_shortcuts.items())
        
        for key, shortcut in sorted_items:
            if shortcut:
                display_name = self.lang_manager.tr(key)  # FIX: Direkte Übersetzung
                shortcuts_text.append(f"<b>{display_name}:</b> {shortcut}")
        
        QMessageBox.information(
            self,
            "Keyboard Shortcuts",
            "<br>".join(shortcuts_text)
        )
    
    def _shortcut_reset_all(self):
        """Reset all fields in current tab."""
        current_page = self.stacked_widget.currentIndex()
        if current_page == 0:  # Encrypt tab
            self.enc_input.clear()
            self.enc_output.clear()
            self.enc_pwd.clear()
            self.enc_keyfile.clear()
        elif current_page == 1:  # Decrypt tab
            self.dec_input.clear()
            self.dec_output.clear()
            self.dec_pwd.clear()
            self.dec_keyfile.clear()
    
    def _shortcut_apply(self):
        """Apply current action (encrypt/decrypt)."""
        current_page = self.stacked_widget.currentIndex()
        if current_page == 0:  # Encrypt tab
            self._run_encrypt()
        elif current_page == 1:  # Decrypt tab
            self._run_decrypt()

    def _create_nav_ui(self):
        self.nav_widget = QWidget()
        self.nav_widget.setObjectName("NavWidget")
        self.nav_widget.setMaximumWidth(260)
        
        nav_layout = QVBoxLayout(self.nav_widget)
        nav_layout.setContentsMargins(0, 0, 0, 15)
        nav_layout.setSpacing(4)

        title = QLabel("Timenc")
        title.setObjectName("Header")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        nav_layout.addWidget(title)

        self.nav_encrypt_btn = QPushButton(self.lang_manager.tr('nav_encrypt'))
        self.nav_encrypt_btn.setObjectName("NavButton")
        self.nav_encrypt_btn.setCheckable(True)

        self.nav_decrypt_btn = QPushButton(self.lang_manager.tr('nav_decrypt'))
        self.nav_decrypt_btn.setObjectName("NavButton")
        self.nav_decrypt_btn.setCheckable(True)

        self.nav_settings_btn = QPushButton(self.lang_manager.tr('nav_settings'))
        self.nav_settings_btn.setObjectName("NavButton")
        self.nav_settings_btn.setCheckable(True)

        self.nav_encrypt_btn.clicked.connect(lambda: self._navigate(0, self.nav_encrypt_btn))
        self.nav_decrypt_btn.clicked.connect(lambda: self._navigate(1, self.nav_decrypt_btn))
        self.nav_settings_btn.clicked.connect(lambda: self._navigate(2, self.nav_settings_btn))

        nav_layout.addWidget(self.nav_encrypt_btn)
        nav_layout.addWidget(self.nav_decrypt_btn)
        nav_layout.addStretch()
        nav_layout.addWidget(self.nav_settings_btn)

    def _create_content_ui(self):
        self.stacked_widget = QStackedWidget()

        self.encrypt_page = QWidget()
        self.decrypt_page = QWidget()
        self.settings_page = QWidget()
        
        self._create_encrypt_ui(self.encrypt_page)
        self._create_decrypt_ui(self.decrypt_page)
        self._create_settings_ui(self.settings_page)

        self.stacked_widget.addWidget(self.encrypt_page)
        self.stacked_widget.addWidget(self.decrypt_page)
        self.stacked_widget.addWidget(self.settings_page)

    def _navigate(self, index: int, btn: QPushButton):
        self.stacked_widget.setCurrentIndex(index)
        self.nav_encrypt_btn.setChecked(False)
        self.nav_decrypt_btn.setChecked(False)
        self.nav_settings_btn.setChecked(False)
        btn.setChecked(True)

    def _create_encrypt_ui(self, parent_widget: QWidget):
        layout = QVBoxLayout(parent_widget)
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(20)

        page_title = QLabel(self.lang_manager.tr('nav_encrypt'))
        page_title.setObjectName("PageHeader")
        layout.addWidget(page_title)

        container = QFrame()
        container.setObjectName("TabContainer")
        container_layout = QFormLayout(container)
        container_layout.setSpacing(18)
        container_layout.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)

        # Input
        self.enc_input = DropLineEdit(self.lang_manager.tr('placeholder_drop_file_folder'))
        enc_input_btn = QPushButton(self.lang_manager.tr('button_browse'))
        enc_input_btn.clicked.connect(self._choose_encrypt_input)
        
        enc_input_layout = QHBoxLayout()
        enc_input_layout.addWidget(self.enc_input)
        enc_input_layout.addWidget(enc_input_btn)
        container_layout.addRow(QLabel(self.lang_manager.tr('label_file_folder')), enc_input_layout)

        # Output
        self.enc_output = QLineEdit()
        self.enc_output.setPlaceholderText(self.lang_manager.tr('placeholder_output_file'))
        enc_output_btn = QPushButton(self.lang_manager.tr('button_save_as'))
        enc_output_btn.clicked.connect(self._choose_encrypt_output)
        
        enc_output_layout = QHBoxLayout()
        enc_output_layout.addWidget(self.enc_output)
        enc_output_layout.addWidget(enc_output_btn)
        container_layout.addRow(QLabel(self.lang_manager.tr('label_output_file')), enc_output_layout)

        # Password with strength indicator
        pwd_container = QVBoxLayout()
        pwd_container.setSpacing(8)
        
        self.enc_pwd = QLineEdit()
        self.enc_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.enc_pwd_toggle_btn = QPushButton(self.lang_manager.tr('button_show'))
        self.enc_pwd_toggle_btn.setObjectName("TogglePasswordButton")
        self.enc_pwd_toggle_btn.setCheckable(True)
        self.enc_pwd_toggle_btn.toggled.connect(self._toggle_password_visibility)
        
        enc_pwd_layout = QHBoxLayout()
        enc_pwd_layout.addWidget(self.enc_pwd)
        enc_pwd_layout.addWidget(self.enc_pwd_toggle_btn)
        pwd_container.addLayout(enc_pwd_layout)
        
        # Password strength bar
        self.enc_pwd_strength_bar = QProgressBar()
        self.enc_pwd_strength_bar.setObjectName("PasswordStrength")
        self.enc_pwd_strength_bar.setTextVisible(False)
        self.enc_pwd_strength_bar.setMaximum(100)
        self.enc_pwd_strength_bar.setValue(0)
        self.enc_pwd_strength_bar.setMaximumHeight(6)
        pwd_container.addWidget(self.enc_pwd_strength_bar)
        
        self.enc_pwd_strength_label = QLabel("")
        self.enc_pwd_strength_label.setObjectName("SubHeader")
        pwd_container.addWidget(self.enc_pwd_strength_label)
        
        container_layout.addRow(QLabel(self.lang_manager.tr('label_password')), pwd_container)

        # Keyfile
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
        layout.addStretch()

        self.enc_button = QPushButton(self.lang_manager.tr('button_encrypt'))
        self.enc_button.setObjectName("ActionButton")
        self.enc_button.clicked.connect(self._run_encrypt)
        layout.addWidget(self.enc_button)

    def _create_decrypt_ui(self, parent_widget: QWidget):
        layout = QVBoxLayout(parent_widget)
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(20)

        page_title = QLabel(self.lang_manager.tr('nav_decrypt'))
        page_title.setObjectName("PageHeader")
        layout.addWidget(page_title)

        container = QFrame()
        container.setObjectName("TabContainer")
        container_layout = QFormLayout(container)
        container_layout.setSpacing(18)
        container_layout.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)

        # Input
        self.dec_input = DropLineEdit(self.lang_manager.tr('placeholder_drop_timenc'))
        dec_input_btn = QPushButton(self.lang_manager.tr('button_browse'))
        dec_input_btn.clicked.connect(self._choose_decrypt_input)
        
        dec_input_layout = QHBoxLayout()
        dec_input_layout.addWidget(self.dec_input)
        dec_input_layout.addWidget(dec_input_btn)
        container_layout.addRow(QLabel(self.lang_manager.tr('label_timenc_file')), dec_input_layout)

        # Output
        self.dec_output = QLineEdit()
        self.dec_output.setPlaceholderText(self.lang_manager.tr('placeholder_output_folder'))
        dec_output_btn = QPushButton(self.lang_manager.tr('button_select_folder'))
        dec_output_btn.clicked.connect(self._choose_decrypt_output)

        dec_output_layout = QHBoxLayout()
        dec_output_layout.addWidget(self.dec_output)
        dec_output_layout.addWidget(dec_output_btn)
        container_layout.addRow(QLabel(self.lang_manager.tr('label_output_folder')), dec_output_layout)

        # Password input - NO strength indicator for decryption
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

        # Keyfile
        self.dec_keyfile = DropLineEdit(self.lang_manager.tr('placeholder_drop_keyfile'))
        dec_keyfile_select_btn = QPushButton(self.lang_manager.tr('button_select'))
        dec_keyfile_select_btn.clicked.connect(partial(self._choose_keyfile, self.dec_keyfile))

        dec_keyfile_layout = QHBoxLayout()
        dec_keyfile_layout.addWidget(self.dec_keyfile)
        dec_keyfile_layout.addWidget(dec_keyfile_select_btn)
        container_layout.addRow(QLabel(self.lang_manager.tr('label_keyfile')), dec_keyfile_layout)

        layout.addWidget(container)
        layout.addStretch()

        self.dec_button = QPushButton(self.lang_manager.tr('button_decrypt'))
        self.dec_button.setObjectName("ActionButton")
        self.dec_button.clicked.connect(self._run_decrypt)
        layout.addWidget(self.dec_button)

    def _create_settings_ui(self, parent_widget: QWidget):
        layout = QVBoxLayout(parent_widget)
        layout.setContentsMargins(30, 25, 30, 25)
        layout.setSpacing(20)

        page_title = QLabel(self.lang_manager.tr('nav_settings'))
        page_title.setObjectName("PageHeader")
        layout.addWidget(page_title)

        container = QFrame()
        container.setObjectName("TabContainer")
        container_layout = QVBoxLayout(container)
        container_layout.setSpacing(25)

        # General settings group
        general_group = QGroupBox(self.lang_manager.tr('settings_general'))
        general_layout = QFormLayout(general_group)
        
        self.lang_combo = QComboBox()
        self.lang_combo.addItem(self.lang_manager.tr('label_lang_de'), "de")
        self.lang_combo.addItem(self.lang_manager.tr('label_lang_en'), "en")
        
        current_lang_code = self.lang_manager.current_lang
        index = self.lang_combo.findData(current_lang_code)
        if index != -1:
            self.lang_combo.setCurrentIndex(index)
            
        self.lang_combo.currentIndexChanged.connect(self._on_language_change)
        general_layout.addRow(QLabel(self.lang_manager.tr('label_language')), self.lang_combo)

        self.lang_info_label = QLabel(self.lang_manager.tr('label_restart_info'))
        self.lang_info_label.setObjectName("SubHeader")
        self.lang_info_label.setWordWrap(True)
        general_layout.addRow(self.lang_info_label)
        
        container_layout.addWidget(general_group)

        # Shortcuts group
        shortcuts_group = QGroupBox(self.lang_manager.tr('settings_shortcuts'))
        shortcuts_layout = QVBoxLayout(shortcuts_group)
        shortcuts_layout.setSpacing(12)
        
        # Create scrollable list for current shortcuts
        shortcuts_scroll = QScrollArea()
        shortcuts_scroll.setWidgetResizable(True)
        shortcuts_scroll.setFrameShape(QFrame.Shape.NoFrame)
        shortcuts_scroll.setMaximumHeight(200)
        
        # Shortcut list container
        shortcut_container = QWidget()
        shortcut_container_layout = QVBoxLayout(shortcut_container)
        shortcut_container_layout.setContentsMargins(0, 0, 0, 0)
        
        # Display current shortcuts in a modern list view
        self.shortcuts_list_widget = QListWidget()
        self.shortcuts_list_widget.setObjectName("ShortcutDisplayList")
        self.shortcuts_list_widget.setAlternatingRowColors(True)
        self.shortcuts_list_widget.setFrameShape(QFrame.Shape.NoFrame)
        self._refresh_shortcuts_display()
        
        shortcut_container_layout.addWidget(self.shortcuts_list_widget)
        shortcuts_scroll.setWidget(shortcut_container)
        shortcuts_layout.addWidget(shortcuts_scroll)
        
        # Customize button
        self.customize_shortcuts_btn = QPushButton(self.lang_manager.tr('button_customize_shortcuts'))
        self.customize_shortcuts_btn.setObjectName("ShortcutDialogButton")
        self.customize_shortcuts_btn.clicked.connect(self._show_shortcuts_dialog)
        shortcuts_layout.addWidget(self.customize_shortcuts_btn)
        
        container_layout.addWidget(shortcuts_group)
        
        layout.addWidget(container)
        layout.addStretch()

    def _refresh_shortcuts_display(self):
        """Refresh the shortcuts list display in settings."""
        self.shortcuts_list_widget.clear()
        all_shortcuts = self.shortcut_manager.get_all_shortcuts()
        
        # Sort for consistent display
        sorted_items = sorted(all_shortcuts.items())
        
        for key, shortcut in sorted_items:
            if shortcut:  # Only show if shortcut is set
                display_name = self.lang_manager.tr(key)  # FIX: Direkte Übersetzung
                # Format with arrow separator
                item_text = f"{display_name} → {shortcut}"
                item = QListWidgetItem(item_text)
                item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsSelectable)
                self.shortcuts_list_widget.addItem(item)

    def _show_shortcuts_dialog(self):
        """Show the shortcuts customization dialog."""
        dialog = ShortcutsDialog(self.shortcut_manager, self.lang_manager, self)
        if dialog.exec():
            # Re-setup shortcuts after changes
            self._setup_shortcuts()
            # Refresh the display in settings
            self._refresh_shortcuts_display()

    def _on_language_change(self, index: int):
        lang_code = self.lang_combo.itemData(index)
        self.settings.setValue("language", lang_code)

    def _update_enc_password_strength(self):
        password = self.enc_pwd.text()
        strength, label = check_password_strength(password)
        
        self.enc_pwd_strength_bar.setValue(strength)
        
        if label == "weak":
            self.enc_pwd_strength_bar.setObjectName("WeakPassword")
            self.enc_pwd_strength_label.setText(f"🔴 {self.lang_manager.tr('pwd_strength_weak')}")
        elif label == "medium":
            self.enc_pwd_strength_bar.setObjectName("MediumPassword")
            self.enc_pwd_strength_label.setText(f"🟡 {self.lang_manager.tr('pwd_strength_medium')}")
        elif label == "strong":
            self.enc_pwd_strength_bar.setObjectName("StrongPassword")
            self.enc_pwd_strength_label.setText(f"🟢 {self.lang_manager.tr('pwd_strength_strong')}")
        elif label == "very_strong":
            self.enc_pwd_strength_bar.setObjectName("VeryStrongPassword")
            self.enc_pwd_strength_label.setText(f"🟢 {self.lang_manager.tr('pwd_strength_very_strong')}")
        else:
            self.enc_pwd_strength_label.setText("")
        
        self.enc_pwd_strength_bar.setStyle(self.enc_pwd_strength_bar.style())

    def _choose_encrypt_input(self):
        path, _ = QFileDialog.getOpenFileName(self, self.lang_manager.tr('dialog_choose_enc_input_file'))
        if not path:
            path = QFileDialog.getExistingDirectory(self, self.lang_manager.tr('dialog_choose_enc_input_folder'))
        
        if path:
            self.enc_input.setText(path)
            self._autosuggest_encrypt_output()

    def _choose_encrypt_output(self):
        default_name = self._get_suggested_enc_output() or self.lang_manager.tr('default_enc_filename')
        path, _ = QFileDialog.getSaveFileName(self, self.lang_manager.tr('dialog_save_enc_output'),
                                              default_name, self.lang_manager.tr('dialog_timenc_files'))
        if path:
            self.enc_output.setText(path)

    def _choose_decrypt_input(self):
        filter = f"{self.lang_manager.tr('dialog_timenc_files')};;{self.lang_manager.tr('dialog_all_files')}"
        path, _ = QFileDialog.getOpenFileName(self, self.lang_manager.tr('dialog_choose_dec_input'),
                                              filter=filter)
        if path:
            self.dec_input.setText(path)
            self._autosuggest_decrypt_output()

    def _choose_decrypt_output(self):
        path = QFileDialog.getExistingDirectory(self, self.lang_manager.tr('dialog_choose_dec_output'))
        if path:
            self.dec_output.setText(path)

    def _choose_keyfile(self, target_line_edit: QLineEdit):
        path, _ = QFileDialog.getOpenFileName(self, self.lang_manager.tr('dialog_choose_keyfile'))
        if path:
            target_line_edit.setText(path)

    def _generate_keyfile(self, target_line_edit: QLineEdit):
        path, _ = QFileDialog.getSaveFileName(self, self.lang_manager.tr('dialog_save_keyfile'), "timenc.keyfile")
        if not path:
            return
        
        try:
            self.run_task(generate_keyfile, path, tr_func=self.lang_manager.tr)
            target_line_edit.setText(path)
        except Exception as e:
            self._on_task_error(self.lang_manager.tr('error_generate_keyfile', error=str(e)))

    def _toggle_password_visibility(self, checked: bool):
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

    def _get_suggested_enc_output(self) -> str:
        in_path_str = self.enc_input.text().strip()
        if not in_path_str:
            return ""
        
        p = Path(in_path_str)
        if not p.exists():
             return f"{p.name}.timenc"

        if p.is_dir():
            return str(p.parent / f"{p.name}.timenc")
        else:
            return str(p.parent / f"{p.stem}.timenc")

    def _autosuggest_encrypt_output(self):
        if not self.enc_output.text().strip():
            suggestion = self._get_suggested_enc_output()
            if suggestion:
                self.enc_output.setText(suggestion)

    def _autosuggest_decrypt_output(self):
        in_path_str = self.dec_input.text().strip()
        if not in_path_str or not self.dec_output.text().strip():
            p = Path(in_path_str)
            if p.is_file():
                self.dec_output.setText(str(p.parent))
            elif p.is_dir():
                self.dec_output.setText(str(p))

    def _run_encrypt(self):
        input_path = self.enc_input.text().strip()
        output_file = self.enc_output.text().strip()
        password = self.enc_pwd.text()
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
            tr_func=self.lang_manager.tr
        )

    def _run_decrypt(self):
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
            tr_func=self.lang_manager.tr
        )

    def run_task(self, func, *args, **kwargs):
        # Überprüfe, ob ein Thread läuft, aber sicher vor C++ Objekt Fehlern
        if hasattr(self, 'thread') and self.thread is not None:
            try:
                # Versuche zu prüfen, ob der Thread läuft
                if self.thread.isRunning():
                    return  # Ein Thread läuft bereits, also nichts tun
            except RuntimeError:
                self.thread = None
                self.worker = None
        
        self.set_status(self.lang_manager.tr('status_processing'))
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 0)  # Indeterminate
        self.enc_button.setEnabled(False)
        self.dec_button.setEnabled(False)

        self.thread = QThread()
        self.worker = Worker(func, *args, **kwargs)
        self.worker.moveToThread(self.thread)

        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self._on_task_finished)
        self.worker.error.connect(self._on_task_error)
        
        # Aufräumen nach Abschluss
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        self.thread.finished.connect(self._cleanup_thread)

        self.thread.start()

    def _cleanup_thread(self):
        """Setze Thread und Worker Referenzen zurück"""
        self.thread = None
        self.worker = None

    def set_status(self, message: str, timeout: int = 0):
        if timeout > 0:
            self.status_bar.showMessage(message, timeout)
        else:
            self.status_bar.showMessage(message)

    def _on_task_error(self, message: str):
        self.progress_bar.setVisible(False)
        self.set_status(self.lang_manager.tr('status_error', message=message))
        self._show_error_dialog(message)
        self.enc_button.setEnabled(True)
        self.dec_button.setEnabled(True)
        # Stelle sicher, dass der Thread beendet wird
        if self.thread and hasattr(self.thread, 'isRunning'):
            try:
                if self.thread.isRunning():
                    self.thread.quit()
                    self.thread.wait(100)
            except RuntimeError:
                pass
        self._cleanup_thread()

    def _on_task_finished(self, message: str):
        self.progress_bar.setVisible(False)
        self.set_status(self.lang_manager.tr('status_success', message=message))
        self._show_success_notification(message)
        self.enc_button.setEnabled(True)
        self.dec_button.setEnabled(True)

    def _show_error_dialog(self, message: str):
        QMessageBox.critical(self, self.lang_manager.tr('dialog_title_error'),
                             self.lang_manager.tr('dialog_error_prefix', message=message))

    def _show_info_dialog(self, message: str):
        QMessageBox.information(self, self.lang_manager.tr('dialog_title_success'), message)

    def _show_success_notification(self, message: str):
        """Show a modern success notification instead of blocking dialog."""
        msg_box = QMessageBox(self)
        msg_box.setWindowTitle(self.lang_manager.tr('dialog_title_success'))
        msg_box.setText(message)
        msg_box.setIcon(QMessageBox.Icon.Information)
        msg_box.setStandardButtons(QMessageBox.StandardButton.Ok)
        
        # Auto-close after 5 seconds
        QTimer.singleShot(5000, msg_box.accept)
        msg_box.exec()


def main():
    app = QApplication(sys.argv)
    
    app.setOrganizationName("Timenc")
    app.setApplicationName("TimencApp")

    settings = QSettings()
    lang_code = settings.value("language", "de")
    
    lang_manager = LanguageManager(lang_code)

    app.setStyleSheet(APP_STYLESHEET)

    file_to_open = None
    if len(sys.argv) > 1:
        path_arg = sys.argv[1]
        if os.path.isfile(path_arg):
             file_to_open = path_arg

    window = TimencApp(lang_manager, file_to_open=file_to_open)
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
