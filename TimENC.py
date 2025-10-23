# app.py (Single-File-Version)
from __future__ import annotations
import os
import sys
import struct
import tempfile
import tarfile
import secrets
from pathlib import Path
from typing import Tuple, Optional
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from argon2.low_level import hash_secret_raw, Type
import stat
import errno
from functools import partial

# Importiere Qt-Komponenten
try:
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QTabWidget, QLabel, QLineEdit, QPushButton, QFormLayout,
        QFileDialog, QMessageBox, QStatusBar, QFrame
    )
    from PySide6.QtCore import QThread, QObject, Signal, Slot, Qt
    from PySide6.QtGui import QDragEnterEvent, QDropEvent
except ImportError:
    print("Fehler: PySide6 nicht gefunden.")
    print("Bitte installiere es mit: pip install PySide6")
    sys.exit(1)


# -------------------------------------------------------------------
#
#                         TIMENC KERNLOGIK
#
# -------------------------------------------------------------------

# ---------------------------
# Core crypto / file helpers
# ---------------------------
MAGIC = b"TIMENC"
VERSION = 2
APP_VERSION = "1.0.0"  # Application version

# --- Hardened Argon2 defaults ---
ARGON2_TIME = 4
ARGON2_MEMORY_KIB = 131072  # 128 MiB
ARGON2_PARALLELISM = 4
KEY_LEN = 32
SALT_SIZE = 16
NONCE_SIZE = 12

def derive_key(password: bytes, salt: bytes, time_cost: int, memory_kib: int, parallelism: int, keyfile_bytes: Optional[bytes] = None) -> bytes:
    """
    Derive a key using Argon2id. If keyfile_bytes is provided, it is mixed into the password.
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

def _pack_u16(n: int) -> bytes: return struct.pack(">H", n)
def _unpack_u16(b: bytes) -> int: return struct.unpack(">H", b)[0]
def _pack_u32(n: int) -> bytes: return struct.pack(">I", n)
def _unpack_u32(b: bytes) -> int: return struct.unpack(">I", b)[0]

# ---------------------------
# Safe atomic write helpers
# ---------------------------
def atomic_write_bytes(final_path: Path, data: bytes, mode: int = 0o600) -> None:
    """
    Atomically write bytes to final_path: write into a temporary file in same directory,
    set secure permissions, fsync, then os.replace to final path.
    Raises FileExistsError if final_path already exists.
    """
    final_dir = final_path.parent
    final_dir.mkdir(parents=True, exist_ok=True)
    if final_path.exists():
        raise FileExistsError(f"Zieldatei existiert bereits: {final_path}")
    # create temp in same directory to allow atomic os.replace on same FS
    fd, tmp = tempfile.mkstemp(dir=str(final_dir))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(final_path))
    finally:
        # cleanup if replace failed and tmp still exists
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
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
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
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as f:
            fileobj.seek(0)
            while True:
                chunk = fileobj.read(65536)
                if not chunk:
                    break
                f.write(chunk)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, str(final_path))
    finally:
        try:
            if os.path.exists(tmp):
                os.unlink(tmp)
        except Exception:
            pass

# ---------------------------
# Tar helpers (creation + safe extract)
# ---------------------------
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
        # do not dereference symlinks - include them as links
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
    abs_directory = os.path.abspath(directory)
    abs_target = os.path.abspath(target)
    try:
        return os.path.commonpath([abs_directory]) == os.path.commonpath([abs_directory, abs_target])
    except Exception:
        return False

def safe_extract(tar: tarfile.TarFile, path: str = ".") -> None:
    """
    Extract tar file safely, preventing path traversal (Tar-Slip).
    """
    for member in tar.getmembers():
        member_path = os.path.join(path, member.name)
        if not _is_within_directory(path, member_path):
            raise Exception("Unzulässiger Pfad in Archiv (Path Traversal)")
    tar.extractall(path=path)

# ---------------------------
# Secure delete (best-effort)
# ---------------------------
def secure_delete(path: Path):
    """
    Overwrite file contents blockwise and unlink. Note: not guaranteed on SSDs/filesystems with snapshots.
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

# ---------------------------
# Encrypt / Decrypt
# ---------------------------
def encrypt(input_path: str, output_file: str, password: str, keyfile_path: Optional[str] = None) -> str:
    inp = Path(input_path)
    if not inp.exists():
        raise FileNotFoundError(f"Eingabe nicht gefunden: {input_path}")
    file_to_encrypt, tmp_created = _make_tar_if_needed(inp)
    original_name = file_to_encrypt.name
    is_dir = 1 if tmp_created else 0
    try:
        # read plaintext as bytes (be mindful: this loads into RAM)
        data = file_to_encrypt.read_bytes()
        salt = os.urandom(SALT_SIZE)
        keyfile_bytes = None
        if keyfile_path:
            keyfile_bytes = Path(keyfile_path).read_bytes()
        # derive key
        key = derive_key(password.encode("utf-8"), salt, ARGON2_TIME, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, keyfile_bytes)
        # make mutable for zeroize
        key_ba = bytearray(key)
        # prepare nonce
        nonce = os.urandom(NONCE_SIZE)

        # prepare header bytes (everything written BEFORE ciphertext) - this will be AAD
        header = bytearray()
        header += MAGIC
        header += bytes([VERSION])
        header += bytes([is_dir])
        name_bytes = original_name.encode("utf-8")
        if len(name_bytes) > 65535:
            raise ValueError("Dateiname zu lang")
        header += _pack_u16(len(name_bytes))
        header += name_bytes
        header += salt
        header += _pack_u32(ARGON2_TIME)
        header += _pack_u32(ARGON2_MEMORY_KIB)
        header += bytes([ARGON2_PARALLELISM])
        header += nonce

        try:
            aead = ChaCha20Poly1305(bytes(key_ba))
            # encrypt using header as AAD
            ciphertext = aead.encrypt(nonce, data, bytes(header))
        finally:
            # zeroize key
            for i in range(len(key_ba)):
                key_ba[i] = 0
            del key_ba

        # build final bytes to write: header + ciphertext
        final_bytes = bytes(header) + ciphertext

        outp = Path(output_file)
        # Atomic write, refuse to overwrite existing file to avoid accidental data loss
        atomic_write_bytes(outp, final_bytes, mode=0o600)
        return f"Verschlüsselt: {output_file}"
    finally:
        if tmp_created:
            try:
                secure_delete(file_to_encrypt)
            except Exception:
                pass
        # attempt to zeroize plaintext if possible
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

def decrypt(input_file: str, out_dir: str, password: str, keyfile_path: Optional[str] = None) -> str:
    enc = Path(input_file)
    if not enc.exists():
        raise FileNotFoundError(f"Eingabedatei nicht gefunden: {input_file}")
    data = enc.read_bytes()
    pos = 0
    if data[: len(MAGIC)] != MAGIC:
        raise ValueError("Keine TIMENC-Datei")
    pos += len(MAGIC)
    version = data[pos]; pos += 1
    original_name = None
    is_dir = 0
    if version >= 2:
        is_dir = data[pos]; pos += 1
        name_len = _unpack_u16(data[pos:pos+2]); pos += 2
        original_name = data[pos:pos+name_len].decode("utf-8"); pos += name_len
    salt = data[pos : pos + SALT_SIZE]; pos += SALT_SIZE
    time_cost = _unpack_u32(data[pos : pos + 4]); pos += 4
    memory_kib = _unpack_u32(data[pos : pos + 4]); pos += 4
    parallelism = data[pos]; pos += 1
    nonce = data[pos : pos + NONCE_SIZE]; pos += NONCE_SIZE

    # reconstruct header bytes (exactly the bytes used as AAD)
    header_bytes = data[:pos]
    ciphertext = data[pos:]
    keyfile_bytes = None
    if keyfile_path:
        keyfile_bytes = Path(keyfile_path).read_bytes()

    key = derive_key(password.encode("utf-8"), salt, time_cost, memory_kib, parallelism, keyfile_bytes)
    key_ba = bytearray(key)
    try:
        aead = ChaCha20Poly1305(bytes(key_ba))
        try:
            plaintext = aead.decrypt(nonce, ciphertext, bytes(header_bytes))
        except Exception:
            # generic message so as not to reveal whether password or file was wrong
            raise ValueError("Entschlüsselung fehlgeschlagen - falsches Passwort/Keyfile oder manipulierte Datei")
    finally:
        for i in range(len(key_ba)):
            key_ba[i] = 0
        del key_ba

    outp = Path(out_dir)
    outp.mkdir(parents=True, exist_ok=True)

    # write plaintext to temp file then place or extract safely
    fd, tmp = tempfile.mkstemp()
    os.close(fd)
    tmp_path = Path(tmp)
    try:
        tmp_path.write_bytes(plaintext)
        # try to zeroize plaintext copy asap
        try:
            if isinstance(plaintext, bytes):
                ba = bytearray(plaintext)
                for i in range(len(ba)):
                    ba[i] = 0
                del ba
        except Exception:
            pass

        if version >= 2 and is_dir == 1:
            # safe extract
            with tarfile.open(str(tmp_path), "r") as tar:
                safe_extract(tar, str(outp))
            return f"Entschlüsselt und extrahiert nach: {outp}"
        elif version >= 2 and original_name:
            target = outp / original_name
            # atomic write, but allow overwrite if file not present -> prevent accidental overwrite
            if target.exists():
                raise FileExistsError(f"Zieldatei existiert bereits: {target}")
            atomic_write_bytes(target, tmp_path.read_bytes(), mode=0o600)
            return f"Entschlüsselt: {target}"
        else:
            # guess: if tmp_path is a tar, extract, else write as 'decrypted'
            try:
                if tarfile.is_tarfile(str(tmp_path)):
                    with tarfile.open(str(tmp_path), "r") as tar:
                        safe_extract(tar, str(outp))
                    return f"Entschlüsselt und extrahiert nach: {outp}"
            except Exception:
                # fall through to writing raw
                pass
            target = outp / "decrypted"
            if target.exists():
                raise FileExistsError(f"Zieldatei existiert bereits: {target}")
            atomic_write_bytes(target, tmp_path.read_bytes(), mode=0o600)
            return f"Entschlüsselt: {target}"
    finally:
        try:
            secure_delete(tmp_path)
        except Exception:
            pass

# ---------------------------
# Keyfile generation (secure)
# ---------------------------
def generate_keyfile(path: str, size: int = 32) -> str:
    key_material = secrets.token_bytes(size)
    # create file securely, refuse overwrite
    p = Path(path)
    if p.exists():
        raise FileExistsError(f"Keyfile existiert bereits: {path}")
    # use O_EXCL to avoid races when creating
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(str(p), flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(key_material)
            f.flush()
            os.fsync(f.fileno())
    finally:
        # zeroize key_material if possible
        try:
            km = bytearray(key_material)
            for i in range(len(km)):
                km[i] = 0
            del km
        except Exception:
            pass
    return f"Keyfile erstellt: {path} ({size} Bytes)"


# -------------------------------------------------------------------
#
#                         TIMENC GUI (PySide6)
#
# -------------------------------------------------------------------

# --- Bitwarden-inspiriertes QSS (Stylesheet) ---
# Ein dunkles Thema, das an das Bitwarden-Design angelehnt ist
APP_STYLESHEET = """
QWidget {
    background-color: #1A1A1A; /* Dunkler Hintergrund */
    color: #E0E0E0; /* Heller Text */
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    font-size: 14px;
}

QMainWindow {
    background-color: #121212; /* Noch dunklerer Haupt-Hintergrund */
}

QTabWidget::pane {
    border: none;
    background-color: #1E1E1E; /* Hintergrund des Tab-Inhalts */
    border-radius: 8px;
}

QTabBar::tab {
    background: #1E1E1E;
    color: #AAAAAA;
    padding: 12px 24px;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
    font-weight: bold;
    min-width: 150px;
}

QTabBar::tab:selected {
    background: #2B2B2B; /* Aktiver Tab etwas heller */
    color: #FFFFFF;
}

QTabBar::tab:hover {
    background: #333333;
}

/* Haupt-Container-Boxen in den Tabs */
QFrame#TabContainer {
    background-color: #2B2B2B;
    border-radius: 8px;
    padding: 10px;
}

QLabel {
    background-color: transparent;
}

QLabel#Header {
    font-size: 24px;
    font-weight: bold;
    color: #FFFFFF;
    padding-bottom: 5px;
}

QLabel#SubHeader {
    font-size: 13px;
    color: #AAAAAA;
    padding-bottom: 15px;
}

QLineEdit {
    background-color: #333333;
    border: 1px solid #444444;
    border-radius: 5px;
    padding: 10px;
    color: #E0E0E0;
}

QLineEdit:focus {
    border: 1px solid #007ACC; /* Blauer Akzent bei Fokus */
}

QPushButton {
    background-color: #444444;
    color: #E0E0E0;
    border: none;
    padding: 10px 16px;
    border-radius: 5px;
    font-weight: bold;
}

QPushButton:hover {
    background-color: #555555;
}

/* Der Haupt-Aktionsbutton (Blau) */
QPushButton#ActionButton {
    background-color: #007ACC;
    color: white;
    font-size: 16px;
    padding: 12px;
}

QPushButton#ActionButton:hover {
    background-color: #005FA3;
}

/* Button zum Anzeigen des Passworts */
QPushButton#TogglePasswordButton {
    background-color: #333333;
    color: #AAAAAA;
    padding: 8px;
}
QPushButton#TogglePasswordButton:hover {
    background-color: #444444;
}

QStatusBar {
    color: #AAAAAA;
}

QStatusBar::item {
    border: none;
}
"""

# --- Worker-Thread für Krypto-Operationen ---
# Verhindert das Einfrieren der GUI
class Worker(QObject):
    """
    Führt eine Funktion in einem separaten Thread aus.
    """
    finished = Signal(str)  # Signal bei Erfolg (mit Nachricht)
    error = Signal(str)     # Signal bei Fehler (mit Fehlermeldung)

    def __init__(self, func, *args, **kwargs):
        super().__init__()
        self.func = func
        self.args = args
        self.kwargs = kwargs

    @Slot()
    def run(self):
        """Führt die Funktion aus und sendet Signale."""
        try:
            # HINWEIS: self.func ist jetzt z.B. die 'encrypt'-Funktion
            # die weiter oben in dieser Datei definiert ist.
            result_message = self.func(*self.args, **self.kwargs)
            self.finished.emit(result_message)
        except Exception as e:
            self.error.emit(str(e))


# --- Drag-and-Drop-Eingabefeld ---
class DropLineEdit(QLineEdit):
    """
    Ein QLineEdit, das Drag-and-Drop von Dateien/Ordnern akzeptiert.
    """
    file_dropped = Signal(str) # Signal, wenn eine Datei gedroppt wurde

    def __init__(self, placeholder_text="", parent=None):
        super().__init__(parent)
        self.setPlaceholderText(placeholder_text)
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event: QDragEnterEvent):
        """Akzeptiert das Event, wenn es URLs (Dateipfade) enthält."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent):
        """Verarbeitet das Drop-Event und setzt den Text des Feldes."""
        if event.mimeData().hasUrls():
            # Nimm nur den ersten Pfad, falls mehrere gedroppt wurden
            url = event.mimeData().urls()[0]
            path = url.toLocalFile()
            self.setText(path)
            self.file_dropped.emit(path) # Signal senden
            event.acceptProposedAction()
        else:
            event.ignore()

# --- Hauptfenster der Anwendung ---
class TimencApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.thread = None # Thread-Management
        self.worker = None # Worker-Management

        # APP_VERSION ist jetzt eine globale Variable von oben
        self.setWindowTitle(f"Timenc {APP_VERSION} - Sichere Verschlüsselung")
        self.setGeometry(100, 100, 800, 650) # Feste Größe
        self.setMinimumSize(700, 600)

        # Zentrales Widget und Hauptlayout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)

        # 1. Header
        self._create_header(main_layout)

        # 2. Tab-Widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # 3. Tabs erstellen
        self.encrypt_tab = QWidget()
        self.decrypt_tab = QWidget()

        self.tabs.addTab(self.encrypt_tab, "🔒 Verschlüsseln")
        self.tabs.addTab(self.decrypt_tab, "🔓 Entschlüsseln")

        # UI für jeden Tab erstellen
        self._create_encrypt_ui()
        self._create_decrypt_ui()

        # 4. Statusleiste
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        self.set_status(f"✅ Bereit — {APP_VERSION}") # APP_VERSION global

        # Autosuggest-Logik verbinden
        self.enc_input.file_dropped.connect(self._autosuggest_encrypt_output)
        self.enc_input.textChanged.connect(self._autosuggest_encrypt_output)
        self.dec_input.file_dropped.connect(self._autosuggest_decrypt_output)
        self.dec_input.textChanged.connect(self._autosuggest_decrypt_output)

    def _create_header(self, layout: QVBoxLayout):
        """Erstellt den Titel und Untertitel."""
        title = QLabel("Timenc")
        title.setObjectName("Header")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        subtitle = QLabel(f"Sichere Dateiverschlüsselung mit Passwort und Keyfile")
        subtitle.setObjectName("SubHeader")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(title)
        layout.addWidget(subtitle)

    def _create_encrypt_ui(self):
        """Erstellt die UI für den "Verschlüsseln"-Tab."""
        layout = QVBoxLayout(self.encrypt_tab)
        layout.setContentsMargins(15, 15, 15, 15)

        # Container für bessere Optik
        container = QFrame()
        container.setObjectName("TabContainer")
        container_layout = QFormLayout(container)
        container_layout.setSpacing(15)
        container_layout.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)

        # 1. Eingabe (Datei/Ordner)
        self.enc_input = DropLineEdit("Datei oder Ordner hierher ziehen...")
        enc_input_btn = QPushButton("Durchsuchen...")
        enc_input_btn.clicked.connect(self._choose_encrypt_input)
        
        enc_input_layout = QHBoxLayout()
        enc_input_layout.addWidget(self.enc_input)
        enc_input_layout.addWidget(enc_input_btn)
        container_layout.addRow(QLabel("📁 Datei / Ordner:"), enc_input_layout)

        # 2. Ausgabe (Datei)
        self.enc_output = QLineEdit()
        self.enc_output.setPlaceholderText("Zieldatei (z.B. geheim.timenc)")
        enc_output_btn = QPushButton("Speichern unter...")
        enc_output_btn.clicked.connect(self._choose_encrypt_output)
        
        enc_output_layout = QHBoxLayout()
        enc_output_layout.addWidget(self.enc_output)
        enc_output_layout.addWidget(enc_output_btn)
        container_layout.addRow(QLabel("💾 Ausgabedatei:"), enc_output_layout)

        # 3. Passwort
        self.enc_pwd = QLineEdit()
        self.enc_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.enc_pwd_toggle_btn = QPushButton("Anzeigen")
        self.enc_pwd_toggle_btn.setObjectName("TogglePasswordButton")
        self.enc_pwd_toggle_btn.setCheckable(True)
        self.enc_pwd_toggle_btn.toggled.connect(self._toggle_password_visibility)
        
        enc_pwd_layout = QHBoxLayout()
        enc_pwd_layout.addWidget(self.enc_pwd)
        enc_pwd_layout.addWidget(self.enc_pwd_toggle_btn)
        container_layout.addRow(QLabel("🔑 Passwort:"), enc_pwd_layout)

        # 4. Keyfile
        self.enc_keyfile = DropLineEdit("Keyfile hierher ziehen (optional)...")
        enc_keyfile_select_btn = QPushButton("Wählen...")
        enc_keyfile_gen_btn = QPushButton("Generieren...")
        enc_keyfile_select_btn.clicked.connect(partial(self._choose_keyfile, self.enc_keyfile))
        enc_keyfile_gen_btn.clicked.connect(partial(self._generate_keyfile, self.enc_keyfile))

        enc_keyfile_layout = QHBoxLayout()
        enc_keyfile_layout.addWidget(self.enc_keyfile)
        enc_keyfile_layout.addWidget(enc_keyfile_select_btn)
        enc_keyfile_layout.addWidget(enc_keyfile_gen_btn)
        container_layout.addRow(QLabel("🗝️ Keyfile (Optional):"), enc_keyfile_layout)

        layout.addWidget(container)
        layout.addStretch() # Platzhalter nach unten

        # 5. Aktions-Button
        self.enc_button = QPushButton("🚀 Verschlüsseln")
        self.enc_button.setObjectName("ActionButton")
        self.enc_button.clicked.connect(self._run_encrypt)
        layout.addWidget(self.enc_button)

    def _create_decrypt_ui(self):
        """Erstellt die UI für den "Entschlüsseln"-Tab."""
        layout = QVBoxLayout(self.decrypt_tab)
        layout.setContentsMargins(15, 15, 15, 15)

        container = QFrame()
        container.setObjectName("TabContainer")
        container_layout = QFormLayout(container)
        container_layout.setSpacing(15)
        container_layout.setFieldGrowthPolicy(QFormLayout.FieldGrowthPolicy.AllNonFixedFieldsGrow)

        # 1. Eingabe (Datei)
        self.dec_input = DropLineEdit("Verschlüsselte .timenc Datei hierher ziehen...")
        dec_input_btn = QPushButton("Durchsuchen...")
        dec_input_btn.clicked.connect(self._choose_decrypt_input)
        
        dec_input_layout = QHBoxLayout()
        dec_input_layout.addWidget(self.dec_input)
        dec_input_layout.addWidget(dec_input_btn)
        container_layout.addRow(QLabel("📄 .timenc Datei:"), dec_input_layout)

        # 2. Ausgabe (Ordner)
        self.dec_output = QLineEdit()
        self.dec_output.setPlaceholderText("Zielordner für entschlüsselte Dateien")
        dec_output_btn = QPushButton("Ordner wählen...")
        dec_output_btn.clicked.connect(self._choose_decrypt_output)

        dec_output_layout = QHBoxLayout()
        dec_output_layout.addWidget(self.dec_output)
        dec_output_layout.addWidget(dec_output_btn)
        container_layout.addRow(QLabel("📂 Zielordner:"), dec_output_layout)

        # 3. Passwort
        self.dec_pwd = QLineEdit()
        self.dec_pwd.setEchoMode(QLineEdit.EchoMode.Password)
        self.dec_pwd_toggle_btn = QPushButton("Anzeigen")
        self.dec_pwd_toggle_btn.setObjectName("TogglePasswordButton")
        self.dec_pwd_toggle_btn.setCheckable(True)
        self.dec_pwd_toggle_btn.toggled.connect(self._toggle_password_visibility)

        dec_pwd_layout = QHBoxLayout()
        dec_pwd_layout.addWidget(self.dec_pwd)
        dec_pwd_layout.addWidget(self.dec_pwd_toggle_btn)
        container_layout.addRow(QLabel("🔑 Passwort:"), dec_pwd_layout)

        # 4. Keyfile
        self.dec_keyfile = DropLineEdit("Keyfile hierher ziehen (optional)...")
        dec_keyfile_select_btn = QPushButton("Wählen...")
        dec_keyfile_gen_btn = QPushButton("Generieren...")
        dec_keyfile_select_btn.clicked.connect(partial(self._choose_keyfile, self.dec_keyfile))
        dec_keyfile_gen_btn.clicked.connect(partial(self._generate_keyfile, self.dec_keyfile))

        dec_keyfile_layout = QHBoxLayout()
        dec_keyfile_layout.addWidget(self.dec_keyfile)
        dec_keyfile_layout.addWidget(dec_keyfile_select_btn)
        dec_keyfile_layout.addWidget(dec_keyfile_gen_btn)
        container_layout.addRow(QLabel("🗝️ Keyfile (Optional):"), dec_keyfile_layout)

        layout.addWidget(container)
        layout.addStretch()

        # 5. Aktions-Button
        self.dec_button = QPushButton("🚀 Entschlüsseln")
        self.dec_button.setObjectName("ActionButton")
        self.dec_button.clicked.connect(self._run_decrypt)
        layout.addWidget(self.dec_button)

    # --- UI-Interaktions-Handler ---

    def _choose_encrypt_input(self):
        """Wählt eine Datei ODER einen Ordner (mit Fallback, wie im Original)."""
        path, _ = QFileDialog.getOpenFileName(self, "Datei zum Verschlüsseln auswählen")
        if not path:
            path = QFileDialog.getExistingDirectory(self, "Ordner zum Verschlüsseln auswählen")
        
        if path:
            self.enc_input.setText(path)
            self._autosuggest_encrypt_output()

    def _choose_encrypt_output(self):
        """Wählt eine Zieldatei zum Speichern."""
        default_name = self._get_suggested_enc_output() or "verschluesselt.timenc"
        path, _ = QFileDialog.getSaveFileName(self, "Verschlüsselte Datei speichern als",
                                              default_name, "TIMENC Dateien (*.timenc)")
        if path:
            self.enc_output.setText(path)

    def _choose_decrypt_input(self):
        """Wählt eine .timenc-Datei zum Entschlüsseln."""
        path, _ = QFileDialog.getOpenFileName(self, "Verschlüsselte Datei auswählen",
                                              filter="TIMENC Dateien (*.timenc);;Alle Dateien (*.*)")
        if path:
            self.dec_input.setText(path)
            self._autosuggest_decrypt_output()

    def _choose_decrypt_output(self):
        """Wählt einen Zielordner für die entschlüsselten Dateien."""
        path = QFileDialog.getExistingDirectory(self, "Zielordner auswählen")
        if path:
            self.dec_output.setText(path)

    def _choose_keyfile(self, target_line_edit: QLineEdit):
        """Wählt ein Keyfile für das angegebene Feld."""
        path, _ = QFileDialog.getOpenFileName(self, "Keyfile auswählen")
        if path:
            target_line_edit.setText(path)

    def _generate_keyfile(self, target_line_edit: QLineEdit):
        """Generiert ein neues Keyfile und trägt es ins Feld ein."""
        path, _ = QFileDialog.getSaveFileName(self, "Neues Keyfile speichern als", "timenc.keyfile")
        if not path:
            return
        
        try:
            # generate_keyfile ist global definiert
            self.run_task(generate_keyfile, path)
            target_line_edit.setText(path) # Bei Erfolg setzen
        except Exception as e:
            self._on_task_error(f"Fehler bei Keyfile-Erstellung: {e}")

    def _toggle_password_visibility(self, checked: bool):
        """Schaltet die Sichtbarkeit des Passworts um."""
        # Finde heraus, welcher Button gedrückt wurde
        sender = self.sender()
        if sender == self.enc_pwd_toggle_btn:
            target_edit = self.enc_pwd
        elif sender == self.dec_pwd_toggle_btn:
            target_edit = self.dec_pwd
        else:
            return

        if checked:
            target_edit.setEchoMode(QLineEdit.EchoMode.Normal)
            sender.setText("Verbergen")
        else:
            target_edit.setEchoMode(QLineEdit.EchoMode.Password)
            sender.setText("Anzeigen")

    # --- Autosuggest-Logik ---

    def _get_suggested_enc_output(self) -> str:
        """Schlägt einen Ausgabenamen basierend auf der Eingabe vor."""
        in_path_str = self.enc_input.text().strip()
        if not in_path_str:
            return ""
        
        p = Path(in_path_str)
        if not p.exists(): # Pfad vielleicht noch unvollständig
             return f"{p.name}.timenc"

        if p.is_dir():
            return str(p.parent / f"{p.name}.timenc")
        else:
            return str(p.parent / f"{p.stem}.timenc")

    def _autosuggest_encrypt_output(self):
        """Füllt das Ausgabefeld, wenn es leer ist."""
        if not self.enc_output.text().strip():
            suggestion = self._get_suggested_enc_output()
            if suggestion:
                self.enc_output.setText(suggestion)

    def _autosuggest_decrypt_output(self):
        """Schlägt den Ordner der Eingabedatei als Ausgabeordner vor."""
        in_path_str = self.dec_input.text().strip()
        if not in_path_str or not self.dec_output.text().strip():
            p = Path(in_path_str)
            if p.is_file():
                self.dec_output.setText(str(p.parent))
            elif p.is_dir(): # Sollte nicht passieren, aber sicher ist sicher
                self.dec_output.setText(str(p))

    # --- Krypto-Aktions-Handler (mit Threading) ---

    def _run_encrypt(self):
        """Startet den Verschlüsselungs-Thread."""
        input_path = self.enc_input.text().strip()
        output_file = self.enc_output.text().strip()
        password = self.enc_pwd.text() # .strip() könnte gewollt sein
        keyfile_path = self.enc_keyfile.text().strip() or None

        if not input_path or not output_file or not password:
            self.show_error("Validierung fehlgeschlagen", "Eingabepfad, Ausgabepfad und Passwort sind erforderlich.")
            return

        # encrypt ist global definiert
        self.run_task(encrypt, input_path, output_file, password, keyfile_path)

    def _run_decrypt(self):
        """Startet den Entschlüsselungs-Thread."""
        input_file = self.dec_input.text().strip()
        out_dir = self.dec_output.text().strip()
        password = self.dec_pwd.text()
        keyfile_path = self.dec_keyfile.text().strip() or None

        if not input_file or not out_dir or not password:
            self.show_error("Validierung fehlgeschlagen", "Eingabedatei, Zielordner und Passwort sind erforderlich.")
            return
            
        # decrypt ist global definiert
        self.run_task(decrypt, input_file, out_dir, password, keyfile_path)

    def run_task(self, func, *args, **kwargs):
        """Hilfsfunktion zum Starten einer Aufgabe im Worker-Thread."""
        if self.thread is not None and self.thread.isRunning():
            self.show_error("Beschäftigt", "Bitte warten Sie, bis die aktuelle Operation abgeschlossen ist.")
            return

        # UI deaktivieren
        self.set_ui_enabled(False)
        self.set_status(f"⏳ Arbeite... (Argon2 KDF läuft)")

        # Thread und Worker erstellen
        self.thread = QThread()
        self.worker = Worker(func, *args, **kwargs) # func ist z.B. die globale 'encrypt'-Funktion
        self.worker.moveToThread(self.thread)

        # Signale verbinden
        self.thread.started.connect(self.worker.run)
        self.worker.finished.connect(self._on_task_finished)
        self.worker.error.connect(self._on_task_error)
        
        # Aufräumen nach Abschluss
        self.worker.finished.connect(self.thread.quit)
        self.worker.finished.connect(self.worker.deleteLater)
        self.thread.finished.connect(self.thread.deleteLater)
        
        # *** HIER IST DER FIX EINGEFÜGT ***
        self.thread.finished.connect(self._cleanup_thread)

        # Start
        self.thread.start()

    def _on_task_finished(self, message: str):
        """Wird aufgerufen, wenn der Worker erfolgreich war."""
        self.set_status(f"✅ Erfolg: {message}")
        self.set_ui_enabled(True)
        QMessageBox.information(self, "Erfolg", message)

    def _on_task_error(self, error_message: str):
        """Wird aufgerufen, wenn der Worker einen Fehler hatte."""
        self.set_status(f"❌ Fehler: {error_message}")
        self.set_ui_enabled(True)
        self.show_error("Operation fehlgeschlagen", error_message)

    # *** HIER IST DER FIX EINGEFÜGT ***
    def _cleanup_thread(self):
        """Setzt die Thread-Referenzen zurück, nachdem sie beendet wurden."""
        self.thread = None
        self.worker = None

    def set_ui_enabled(self, enabled: bool):
        """Aktiviert oder deaktiviert die Haupt-Buttons und Tabs."""
        self.enc_button.setEnabled(enabled)
        self.dec_button.setEnabled(enabled)
        self.tabs.setEnabled(enabled)
        if enabled:
            self.enc_button.setText("🚀 Verschlüsseln")
            self.dec_button.setText("🚀 Entschlüsseln")
        else:
            self.enc_button.setText("⏳ Verschlüssle...")
            self.dec_button.setText("⏳ Entschlüssle...")

    # --- Hilfsfunktionen ---

    def set_status(self, message: str, timeout: int = 5000):
        """Setzt die Nachricht in der Statusleiste."""
        self.status_bar.showMessage(message, timeout)

    def show_error(self, title: str, message: str):
        """Zeigt eine standardisierte Fehlermeldung."""
        QMessageBox.critical(self, title, message)

    def closeEvent(self, event):
        """Stellt sicher, dass der Thread beendet wird, wenn das Fenster geschlossen wird."""
        if self.thread is not None and self.thread.isRunning():
            self.thread.quit()
            self.thread.wait(1000) # Warte max 1 Sekunde
        event.accept()


# --- Anwendung starten ---
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(APP_STYLESHEET) # Style anwenden

    window = TimencApp()
    window.show()

    sys.exit(app.exec())
