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

# ---------------------------
# Core crypto / file helpers
# ---------------------------
MAGIC = b"TIMENC"
VERSION = 2
ARGON2_TIME = 3
ARGON2_MEMORY_KIB = 65536
ARGON2_PARALLELISM = 4
KEY_LEN = 32
SALT_SIZE = 16
NONCE_SIZE = 12

def derive_key(password: bytes, salt: bytes, time_cost: int, memory_kib: int, parallelism: int, keyfile_bytes: Optional[bytes] = None) -> bytes:
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

def _make_tar_if_needed(path: Path) -> Tuple[Path, bool]:
    if path.is_file():
        return path, False
    fd, tmp = tempfile.mkstemp(suffix=".tar")
    os.close(fd)
    try:
        with tarfile.open(tmp, "w") as tar:
            tar.add(str(path), arcname=path.name)
    except Exception:
        try:
            os.remove(tmp)
        except Exception:
            pass
        raise
    return Path(tmp), True

def secure_delete(path: Path):
    try:
        length = path.stat().st_size
        with open(path, "r+b") as f:
            f.seek(0)
            f.write(os.urandom(length))
            f.flush()
            os.fsync(f.fileno())
    except Exception:
        pass
    try:
        path.unlink()
    except Exception:
        pass

def encrypt(input_path: str, output_file: str, password: str, keyfile_path: Optional[str] = None) -> str:
    inp = Path(input_path)
    if not inp.exists():
        raise FileNotFoundError(f"Eingabe nicht gefunden: {input_path}")
    file_to_encrypt, tmp_created = _make_tar_if_needed(inp)
    original_name = file_to_encrypt.name
    is_dir = 1 if tmp_created else 0
    try:
        data = file_to_encrypt.read_bytes()
        salt = os.urandom(SALT_SIZE)
        keyfile_bytes = None
        if keyfile_path:
            keyfile_bytes = Path(keyfile_path).read_bytes()
        key = derive_key(password.encode("utf-8"), salt, ARGON2_TIME, ARGON2_MEMORY_KIB, ARGON2_PARALLELISM, keyfile_bytes)
        aead = ChaCha20Poly1305(key)
        nonce = os.urandom(NONCE_SIZE)
        ciphertext = aead.encrypt(nonce, data, None)
        with open(output_file, "wb") as f:
            f.write(MAGIC)
            f.write(bytes([VERSION]))
            f.write(bytes([is_dir]))
            name_bytes = original_name.encode("utf-8")
            if len(name_bytes) > 65535:
                raise ValueError("Dateiname zu lang")
            f.write(_pack_u16(len(name_bytes)))
            f.write(name_bytes)
            f.write(salt)
            f.write(_pack_u32(ARGON2_TIME))
            f.write(_pack_u32(ARGON2_MEMORY_KIB))
            f.write(bytes([ARGON2_PARALLELISM]))
            f.write(nonce)
            f.write(ciphertext)
        return f"Verschlüsselt: {output_file}"
    finally:
        if tmp_created:
            try:
                secure_delete(file_to_encrypt)
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
    ciphertext = data[pos:]
    keyfile_bytes = None
    if keyfile_path:
        keyfile_bytes = Path(keyfile_path).read_bytes()
    key = derive_key(password.encode("utf-8"), salt, time_cost, memory_kib, parallelism, keyfile_bytes)
    aead = ChaCha20Poly1305(key)
    try:
        plaintext = aead.decrypt(nonce, ciphertext, None)
    except Exception:
        raise ValueError("Entschlüsselung fehlgeschlagen - falsches Passwort/Keyfile")
    outp = Path(out_dir)
    outp.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp()
    os.close(fd)
    tmp_path = Path(tmp)
    try:
        tmp_path.write_bytes(plaintext)
        if version >= 2 and is_dir == 1:
            with tarfile.open(str(tmp_path), "r") as tar:
                tar.extractall(path=str(outp))
            return f"Entschlüsselt und extrahiert nach: {outp}"
        elif version >= 2 and original_name:
            target = outp / original_name
            target.write_bytes(plaintext)
            return f"Entschlüsselt: {target}"
        else:
            if tarfile.is_tarfile(str(tmp_path)):
                with tarfile.open(str(tmp_path), "r") as tar:
                    tar.extractall(path=str(outp))
                return f"Entschlüsselt und extrahiert nach: {outp}"
            else:
                target = outp / "decrypted"
                target.write_bytes(plaintext)
                return f"Entschlüsselt: {target}"
    finally:
        try:
            secure_delete(tmp_path)
        except Exception:
            pass

def generate_keyfile(path: str, size: int = 32) -> str:
    key_material = secrets.token_bytes(size)
    Path(path).write_bytes(key_material)
    return f"Keyfile erstellt: {path} ({size} Bytes)"

# ---------------------------
# GUI (CustomTkinter)
# ---------------------------
try:
    import customtkinter as ctk
    from tkinter import filedialog, messagebox
    import tkinter as tk
    try:
        from tkinterdnd2 import DND_FILES, TkinterDnD
        DND_AVAILABLE = True
    except Exception:
        DND_AVAILABLE = False
        TkinterDnD = None
except ImportError:
    ctk = None
    DND_AVAILABLE = False

class ModernTimencGUI:
    def __init__(self):
        if ctk is None:
            raise RuntimeError("CustomTkinter nicht verfügbar")
        # Appearance
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")

        # Root window: less wide, taller
        if DND_AVAILABLE and TkinterDnD:
            self.root = TkinterDnD.Tk()
        else:
            self.root = ctk.CTk()
        self.root.title("Timenc - Sichere Verschlüsselung")
        self.root.geometry("820x720")        # weniger breit, dafür höher
        self.root.minsize(760, 640)

        # background to avoid white edges
        self.main_bg = "#111213"
        try:
            self.root.configure(bg=self.main_bg)
        except Exception:
            pass

        self._force_dark_title_bar()

        # Layout: centered, fixed content width for nicer column
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_columnconfigure(1, weight=0)
        self.root.grid_columnconfigure(2, weight=1)
        self.root.grid_rowconfigure(0, weight=1)

        content_width = 720  # narrower content column
        content_frame = ctk.CTkFrame(self.root, width=content_width, fg_color=self.main_bg, corner_radius=12)
        content_frame.grid(row=0, column=1, sticky="nsew", pady=12)
        content_frame.grid_propagate(False)
        content_frame.grid_columnconfigure(0, weight=1)
        content_frame.grid_rowconfigure(2, weight=1)

        # Header (clean)
        header = ctk.CTkFrame(content_frame, fg_color="transparent")
        header.grid(row=0, column=0, sticky="ew", padx=12, pady=(10,4))
        header.grid_columnconfigure(0, weight=1)
        title = ctk.CTkLabel(header, text="🔒 Timenc — Sichere Dateiverschlüsselung", font=ctk.CTkFont(size=20, weight="bold"))
        title.grid(row=0, column=0, sticky="w")
        subtitle = ctk.CTkLabel(header, text="Verschlüsseln und entschlüsseln Sie Dateien sicher mit Passwort und Keyfile", font=ctk.CTkFont(size=12), text_color="gray")
        subtitle.grid(row=1, column=0, sticky="w", pady=(6,0))

        # Tabview (slim)
        self.tabview = ctk.CTkTabview(content_frame, width=content_width-20, corner_radius=10, fg_color="#0b0b0c")
        self.tabview.grid(row=1, column=0, padx=12, pady=(8,10), sticky="nsew")
        self.encrypt_tab = self.tabview.add("🔒 Verschlüsseln")
        self.decrypt_tab = self.tabview.add("🔓 Entschlüsseln")

        # build UI
        self._build_encrypt_tab(content_width-36)
        self._build_decrypt_tab(content_width-36)

        # status bar
        status = ctk.CTkFrame(content_frame, fg_color="#0b0b0c", corner_radius=8, height=38)
        status.grid(row=2, column=0, padx=12, pady=(0,12), sticky="ew")
        status.grid_propagate(False)
        self.status_label = ctk.CTkLabel(status, text="✅ Bereit — Dateien per Drag & Drop in Eingabefelder", font=ctk.CTkFont(size=11), text_color="lightblue")
        self.status_label.grid(row=0, column=0, sticky="w", padx=10, pady=6)

    def _force_dark_title_bar(self):
        try:
            if sys.platform == "win32":
                import ctypes
                set_window_attribute = ctypes.windll.dwmapi.DwmSetWindowAttribute
                hwnd = ctypes.windll.user32.GetParent(self.root.winfo_id())
                value = ctypes.c_int(2)
                set_window_attribute(hwnd, 20, ctypes.byref(value), ctypes.sizeof(value))
        except Exception:
            pass

    # -----------------------
    # Encrypt tab (wider entries)
    # -----------------------
    def _build_encrypt_tab(self, inner_width: int):
        tab = self.encrypt_tab
        tab.grid_columnconfigure(0, weight=1)
        padx = 12
        pady = 8

        area = ctk.CTkFrame(tab, fg_color="#151516", corner_radius=10)
        area.grid(row=0, column=0, sticky="ew", padx=padx, pady=(pady,10))
        area.grid_columnconfigure(0, weight=1)

        lbl = ctk.CTkLabel(area, text="📁 Datei / Ordner zum Verschlüsseln", font=ctk.CTkFont(size=13, weight="bold"))
        lbl.grid(row=0, column=0, sticky="w", padx=12, pady=(10,2))
        sub = ctk.CTkLabel(area, text="⤵️ Ziehen Sie eine Datei oder einen Ordner hierher", font=ctk.CTkFont(size=10), text_color="lightblue")
        sub.grid(row=1, column=0, sticky="w", padx=12, pady=(0,8))

        inrow = ctk.CTkFrame(area, fg_color="transparent")
        inrow.grid(row=2, column=0, sticky="ew", padx=12, pady=(0,12))
        inrow.grid_columnconfigure(0, weight=1)
        # make input field a bit larger
        self.encrypt_input_entry = ctk.CTkEntry(inrow, placeholder_text="Pfad zur Datei oder zum Ordner...", height=50, fg_color="#2a2a2b")
        self.encrypt_input_entry.grid(row=0, column=0, sticky="ew", padx=(0,8))
        ctk.CTkButton(inrow, text="Durchsuchen", width=120, height=42, command=self.choose_encrypt_input).grid(row=0, column=1)

        opts = ctk.CTkFrame(tab, fg_color="transparent")
        opts.grid(row=1, column=0, sticky="ew", padx=padx, pady=(2,10))
        opts.grid_columnconfigure(0, weight=1)

        # Ausgabedatei (wider)
        outlbl = ctk.CTkLabel(opts, text="💾 Ausgabedatei:", font=ctk.CTkFont(size=11, weight="bold"))
        outlbl.grid(row=0, column=0, sticky="w", padx=8, pady=(6,2))
        outrow = ctk.CTkFrame(opts, fg_color="transparent")
        outrow.grid(row=1, column=0, sticky="ew", padx=8)
        outrow.grid_columnconfigure(0, weight=1)
        self.encrypt_output_entry = ctk.CTkEntry(outrow, height=44)
        self.encrypt_output_entry.grid(row=0, column=0, sticky="ew", padx=(0,8))
        ctk.CTkButton(outrow, text="Durchsuchen", width=120, height=40, command=self.choose_encrypt_output).grid(row=0, column=1)

        # Password (label for toggle: "Passwort anzeigen")
        pwlbl = ctk.CTkLabel(opts, text="🔑 Passwort:", font=ctk.CTkFont(size=11, weight="bold"))
        pwlbl.grid(row=2, column=0, sticky="w", padx=8, pady=(8,2))
        pwrow = ctk.CTkFrame(opts, fg_color="transparent")
        pwrow.grid(row=3, column=0, sticky="ew", padx=8)
        pwrow.grid_columnconfigure(0, weight=1)
        self.encrypt_pwd_entry = ctk.CTkEntry(pwrow, show="•", height=44, placeholder_text="Passwort eingeben...")
        self.encrypt_pwd_entry.grid(row=0, column=0, sticky="ew", padx=(0,8))
        # change button text to "Passwort anzeigen" / "Passwort verbergen"
        self.encrypt_pwd_toggle = ctk.CTkButton(pwrow, text="Passwort anzeigen", width=150, height=40, command=lambda: self.toggle_password(self.encrypt_pwd_entry, self.encrypt_pwd_toggle))
        self.encrypt_pwd_toggle.grid(row=0, column=1)

        # Keyfile
        kflbl = ctk.CTkLabel(opts, text="🗝️ Keyfile (optional):", font=ctk.CTkFont(size=11, weight="bold"))
        kflbl.grid(row=4, column=0, sticky="w", padx=8, pady=(8,2))
        kfrow = ctk.CTkFrame(opts, fg_color="transparent")
        kfrow.grid(row=5, column=0, sticky="ew", padx=8, pady=(0,6))
        kfrow.grid_columnconfigure(0, weight=1)
        self.encrypt_keyfile_entry = ctk.CTkEntry(kfrow, placeholder_text="Pfad zum Keyfile...", height=40)
        self.encrypt_keyfile_entry.grid(row=0, column=0, sticky="ew", padx=(0,8))
        kfbtns = ctk.CTkFrame(kfrow, fg_color="transparent")
        kfbtns.grid(row=0, column=1)
        ctk.CTkButton(kfbtns, text="Wählen", width=100, height=36, command=lambda: self.choose_keyfile(self.encrypt_keyfile_entry)).grid(row=0, column=0, padx=(0,6))
        ctk.CTkButton(kfbtns, text="Generieren", width=110, height=36, command=lambda: self.generate_keyfile(self.encrypt_keyfile_entry)).grid(row=0, column=1)

        # Action button (bigger)
        action = ctk.CTkFrame(tab, fg_color="transparent")
        action.grid(row=2, column=0, sticky="e", padx=padx, pady=(6,12))
        self.encrypt_btn = ctk.CTkButton(action, text="🚀 Verschlüsseln", command=self.gui_encrypt, height=46, width=220, fg_color="#1f6aa5", hover_color="#144870")
        self.encrypt_btn.grid(row=0, column=0)

        # DnD
        if DND_AVAILABLE:
            self.encrypt_input_entry.drop_target_register(DND_FILES)
            self.encrypt_input_entry.dnd_bind('<<Drop>>', lambda e: self._on_drop_encrypt_input(e))
            self.encrypt_keyfile_entry.drop_target_register(DND_FILES)
            self.encrypt_keyfile_entry.dnd_bind('<<Drop>>', lambda e: self._on_drop_keyfile(e, self.encrypt_keyfile_entry))

        # events
        self.encrypt_input_entry.bind("<FocusOut>", lambda e: self._autosuggest_encrypt_output())
        self.encrypt_input_entry.bind("<KeyRelease>", lambda e: self._autosuggest_encrypt_output())

    # -----------------------
    # Decrypt tab
    # -----------------------
    def _build_decrypt_tab(self, inner_width: int):
        tab = self.decrypt_tab
        tab.grid_columnconfigure(0, weight=1)
        padx = 12
        pady = 8

        area = ctk.CTkFrame(tab, fg_color="#151516", corner_radius=10)
        area.grid(row=0, column=0, sticky="ew", padx=padx, pady=(pady,10))
        area.grid_columnconfigure(0, weight=1)

        lbl = ctk.CTkLabel(area, text="📄 Datei zum Entschlüsseln", font=ctk.CTkFont(size=13, weight="bold"))
        lbl.grid(row=0, column=0, sticky="w", padx=12, pady=(10,2))
        sub = ctk.CTkLabel(area, text="⤵️ Ziehen Sie die verschlüsselte Datei hierher", font=ctk.CTkFont(size=10), text_color="lightblue")
        sub.grid(row=1, column=0, sticky="w", padx=12, pady=(0,8))

        inrow = ctk.CTkFrame(area, fg_color="transparent")
        inrow.grid(row=2, column=0, sticky="ew", padx=12, pady=(0,12))
        inrow.grid_columnconfigure(0, weight=1)
        self.decrypt_input_entry = ctk.CTkEntry(inrow, placeholder_text="Pfad zur verschlüsselten Datei...", height=50, fg_color="#2a2a2b")
        self.decrypt_input_entry.grid(row=0, column=0, sticky="ew", padx=(0,8))
        ctk.CTkButton(inrow, text="Durchsuchen", width=120, height=42, command=self.choose_decrypt_input).grid(row=0, column=1)

        opts = ctk.CTkFrame(tab, fg_color="transparent")
        opts.grid(row=1, column=0, sticky="ew", padx=padx, pady=(2,10))
        opts.grid_columnconfigure(0, weight=1)

        outlbl = ctk.CTkLabel(opts, text="📂 Zielordner:", font=ctk.CTkFont(size=11, weight="bold"))
        outlbl.grid(row=0, column=0, sticky="w", padx=8, pady=(6,2))
        outrow = ctk.CTkFrame(opts, fg_color="transparent")
        outrow.grid(row=1, column=0, sticky="ew", padx=8)
        outrow.grid_columnconfigure(0, weight=1)
        self.decrypt_output_entry = ctk.CTkEntry(outrow, height=44, placeholder_text="Ordner für entschlüsselte Dateien...")
        self.decrypt_output_entry.grid(row=0, column=0, sticky="ew", padx=(0,8))
        ctk.CTkButton(outrow, text="Durchsuchen", width=120, height=40, command=self.choose_decrypt_output).grid(row=0, column=1)

        pwlbl = ctk.CTkLabel(opts, text="🔑 Passwort:", font=ctk.CTkFont(size=11, weight="bold"))
        pwlbl.grid(row=2, column=0, sticky="w", padx=8, pady=(8,2))
        pwrow = ctk.CTkFrame(opts, fg_color="transparent")
        pwrow.grid(row=3, column=0, sticky="ew", padx=8)
        pwrow.grid_columnconfigure(0, weight=1)
        self.decrypt_pwd_entry = ctk.CTkEntry(pwrow, show="•", height=44, placeholder_text="Passwort eingeben...")
        self.decrypt_pwd_entry.grid(row=0, column=0, sticky="ew", padx=(0,8))
        # same "Passwort anzeigen" label
        self.decrypt_pwd_toggle = ctk.CTkButton(pwrow, text="Passwort anzeigen", width=150, height=40, command=lambda: self.toggle_password(self.decrypt_pwd_entry, self.decrypt_pwd_toggle))
        self.decrypt_pwd_toggle.grid(row=0, column=1)

        kflbl = ctk.CTkLabel(opts, text="🗝️ Keyfile (optional):", font=ctk.CTkFont(size=11, weight="bold"))
        kflbl.grid(row=4, column=0, sticky="w", padx=8, pady=(8,2))
        kfrow = ctk.CTkFrame(opts, fg_color="transparent")
        kfrow.grid(row=5, column=0, sticky="ew", padx=8, pady=(0,6))
        kfrow.grid_columnconfigure(0, weight=1)
        self.decrypt_keyfile_entry = ctk.CTkEntry(kfrow, placeholder_text="Pfad zum Keyfile...", height=40)
        self.decrypt_keyfile_entry.grid(row=0, column=0, sticky="ew", padx=(0,8))
        kfbtns = ctk.CTkFrame(kfrow, fg_color="transparent")
        kfbtns.grid(row=0, column=1)
        ctk.CTkButton(kfbtns, text="Wählen", width=100, height=36, command=lambda: self.choose_keyfile(self.decrypt_keyfile_entry)).grid(row=0, column=0, padx=(0,6))
        ctk.CTkButton(kfbtns, text="Generieren", width=110, height=36, command=lambda: self.generate_keyfile(self.decrypt_keyfile_entry)).grid(row=0, column=1)

        action = ctk.CTkFrame(tab, fg_color="transparent")
        action.grid(row=2, column=0, sticky="e", padx=padx, pady=(6,12))
        self.decrypt_btn = ctk.CTkButton(action, text="🚀 Entschlüsseln", command=self.gui_decrypt, height=46, width=220, fg_color="#1f6aa5", hover_color="#144870")
        self.decrypt_btn.grid(row=0, column=0)

        if DND_AVAILABLE:
            self.decrypt_input_entry.drop_target_register(DND_FILES)
            self.decrypt_input_entry.dnd_bind('<<Drop>>', lambda e: self._on_drop_decrypt_input(e))
            self.decrypt_keyfile_entry.drop_target_register(DND_FILES)
            self.decrypt_keyfile_entry.dnd_bind('<<Drop>>', lambda e: self._on_drop_keyfile(e, self.decrypt_keyfile_entry))

        self.decrypt_input_entry.bind("<FocusOut>", lambda e: self._autosuggest_decrypt_output())
        self.decrypt_input_entry.bind("<KeyRelease>", lambda e: self._autosuggest_decrypt_output())

    # -----------------------
    # Drag & drop handlers
    # -----------------------
    def _on_drop_encrypt_input(self, event):
        paths = self._parse_dnd_event(event.data)
        if paths:
            path = paths[0]
            self.encrypt_input_entry.delete(0, tk.END)
            self.encrypt_input_entry.insert(0, path)
            self._autosuggest_encrypt_output()
            self.set_status(f"✅ Eingabe ausgewählt: {Path(path).name}")

    def _on_drop_decrypt_input(self, event):
        paths = self._parse_dnd_event(event.data)
        if paths:
            path = paths[0]
            if not path.lower().endswith('.timenc'):
                self.set_status("❌ Fehler: Nur .timenc Dateien können entschlüsselt werden!")
                messagebox.showerror("Falscher Dateityp", "Bitte wählen Sie eine .timenc Datei aus!")
                return
            self.decrypt_input_entry.delete(0, tk.END)
            self.decrypt_input_entry.insert(0, path)
            self._autosuggest_decrypt_output()
            self.set_status(f"✅ Verschlüsselte Datei ausgewählt: {Path(path).name}")

    def _on_drop_keyfile(self, event, entry_widget):
        paths = self._parse_dnd_event(event.data)
        if paths:
            path = paths[0]
            entry_widget.delete(0, tk.END)
            entry_widget.insert(0, path)
            self.set_status(f"✅ Keyfile ausgewählt: {Path(path).name}")

    def _parse_dnd_event(self, data: str):
        if not data:
            return []
        paths = []
        for path in data.split():
            clean_path = path.strip('{}')
            if clean_path:
                paths.append(clean_path)
        return paths

    # -----------------------
    # Interactions & helpers
    # -----------------------
    def toggle_password(self, entry, toggle_btn):
        """Toggle show/hide and update text to German labels requested."""
        current_show = entry.cget('show')
        if current_show == '•':
            entry.configure(show='')
            toggle_btn.configure(text="Passwort verbergen")
        else:
            entry.configure(show='•')
            toggle_btn.configure(text="Passwort anzeigen")

    def choose_encrypt_input(self):
        path = filedialog.askopenfilename(title="Datei zum Verschlüsseln auswählen")
        if not path:
            path = filedialog.askdirectory(title="Ordner zum Verschlüsseln auswählen")
        if path:
            self.encrypt_input_entry.delete(0, tk.END)
            self.encrypt_input_entry.insert(0, path)
            self._autosuggest_encrypt_output()
            self.set_status(f"✅ Eingabe ausgewählt: {Path(path).name}")

    def choose_encrypt_output(self):
        current_input = self.encrypt_input_entry.get().strip()
        default_name = "verschluesselt.timenc"
        if current_input:
            p = Path(current_input)
            if p.exists():
                if p.is_dir():
                    default_name = f"{p.name}.timenc"
                else:
                    default_name = f"{p.stem}.timenc"
        out = filedialog.asksaveasfilename(title="Verschlüsselte Datei speichern als", defaultextension=".timenc", filetypes=[("TIMENC Dateien", "*.timenc")], initialfile=default_name)
        if out:
            self.encrypt_output_entry.delete(0, tk.END)
            self.encrypt_output_entry.insert(0, out)

    def choose_decrypt_input(self):
        path = filedialog.askopenfilename(title="Verschlüsselte Datei auswählen", filetypes=[("TIMENC Dateien", "*.timenc"), ("Alle Dateien", "*.*")])
        if path:
            self.decrypt_input_entry.delete(0, tk.END)
            self.decrypt_input_entry.insert(0, path)
            self._autosuggest_decrypt_output()
            self.set_status(f"✅ Verschlüsselte Datei ausgewählt: {Path(path).name}")

    def choose_decrypt_output(self):
        out = filedialog.askdirectory(title="Zielordner für entschlüsselte Dateien auswählen")
        if out:
            self.decrypt_output_entry.delete(0, tk.END)
            self.decrypt_output_entry.insert(0, out)

    def choose_keyfile(self, entry):
        path = filedialog.askopenfilename(title="Keyfile auswählen", filetypes=[("Keyfiles", "*.bin"), ("Alle Dateien", "*.*")])
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)
            self.set_status(f"✅ Keyfile ausgewählt: {Path(path).name}")

    def generate_keyfile(self, entry):
        path = filedialog.asksaveasfilename(title="Keyfile speichern als", defaultextension=".bin", filetypes=[("Keyfiles", "*.bin"), ("Alle Dateien", "*.*")])
        if path:
            try:
                result = generate_keyfile(path)
                entry.delete(0, tk.END)
                entry.insert(0, path)
                messagebox.showinfo("Keyfile erstellt", result)
                self.set_status("✅ Keyfile erfolgreich generiert")
            except Exception as e:
                messagebox.showerror("Fehler", f"Keyfile konnte nicht erstellt werden: {e}")
                self.set_status("❌ Fehler beim Generieren des Keyfiles")

    def _autosuggest_encrypt_output(self):
        inp = self.encrypt_input_entry.get().strip()
        cur_out = self.encrypt_output_entry.get().strip()
        if not inp or cur_out:
            return
        p = Path(inp)
        if p.exists():
            if p.is_dir():
                suggested = str(p.parent / f"{p.name}.timenc")
            else:
                suggested = str(p.parent / f"{p.stem}.timenc")
            self.encrypt_output_entry.delete(0, tk.END)
            self.encrypt_output_entry.insert(0, suggested)

    def _autosuggest_decrypt_output(self):
        inp = self.decrypt_input_entry.get().strip()
        cur_out = self.decrypt_output_entry.get().strip()
        if not inp or cur_out:
            return
        p = Path(inp)
        if p.exists() and p.is_file():
            suggested = str(p.parent / f"{p.stem}_entschluesselt")
            self.decrypt_output_entry.delete(0, tk.END)
            self.decrypt_output_entry.insert(0, suggested)

    # -----------------------
    # Actions
    # -----------------------
    def gui_encrypt(self):
        if not self.validate_encrypt_inputs():
            return
        try:
            self.set_status("⏳ Verschlüssele...")
            self.encrypt_btn.configure(state="disabled", text="Verschlüssele...")
            self.root.update()
            result = encrypt(self.encrypt_input_entry.get().strip(), self.encrypt_output_entry.get().strip(), self.encrypt_pwd_entry.get(), self.encrypt_keyfile_entry.get().strip() or None)
            messagebox.showinfo("Erfolg", result)
            self.set_status("✅ Verschlüsselung erfolgreich")
            self.encrypt_pwd_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Fehler", f"Verschlüsselung fehlgeschlagen: {e}")
            self.set_status("❌ Fehler bei der Verschlüsselung")
        finally:
            self.encrypt_btn.configure(state="normal", text="🚀 Verschlüsseln")

    def gui_decrypt(self):
        if not self.validate_decrypt_inputs():
            return
        try:
            self.set_status("⏳ Entschlüssele...")
            self.decrypt_btn.configure(state="disabled", text="Entschlüssele...")
            self.root.update()
            result = decrypt(self.decrypt_input_entry.get().strip(), self.decrypt_output_entry.get().strip(), self.decrypt_pwd_entry.get(), self.decrypt_keyfile_entry.get().strip() or None)
            messagebox.showinfo("Erfolg", result)
            self.set_status("✅ Entschlüsselung erfolgreich")
            self.decrypt_pwd_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Fehler", f"Entschlüsselung fehlgeschlagen: {e}")
            self.set_status("❌ Fehler bei der Entschlüsselung")
        finally:
            self.decrypt_btn.configure(state="normal", text="🚀 Entschlüsseln")

    # -----------------------
    # Validation + misc
    # -----------------------
    def validate_encrypt_inputs(self) -> bool:
        inp = self.encrypt_input_entry.get().strip()
        out = self.encrypt_output_entry.get().strip()
        pwd = self.encrypt_pwd_entry.get()
        if not inp:
            messagebox.showerror("Fehler", "Bitte Eingabepfad angeben")
            return False
        if not Path(inp).exists():
            messagebox.showerror("Fehler", "Eingabepfad existiert nicht")
            return False
        if not out:
            messagebox.showerror("Fehler", "Bitte Ausgabepfad angeben")
            return False
        if not pwd:
            messagebox.showerror("Fehler", "Bitte Passwort eingeben")
            return False
        return True

    def validate_decrypt_inputs(self) -> bool:
        inp = self.decrypt_input_entry.get().strip()
        out = self.decrypt_output_entry.get().strip()
        pwd = self.decrypt_pwd_entry.get()
        if not inp:
            messagebox.showerror("Fehler", "Bitte Eingabedatei angeben")
            return False
        if not Path(inp).exists():
            messagebox.showerror("Fehler", "Eingabedatei existiert nicht")
            return False
        if not out:
            messagebox.showerror("Fehler", "Bitte Zielordner angeben")
            return False
        if not pwd:
            messagebox.showerror("Fehler", "Bitte Passwort eingeben")
            return False
        if not inp.lower().endswith('.timenc'):
            messagebox.showerror("Fehler", "Die Eingabedatei muss eine .timenc Datei sein")
            return False
        return True

    def set_status(self, text: str):
        self.status_label.configure(text=text)

    def run(self):
        self.root.mainloop()

# -----------------------
# Entrypoint
# -----------------------
if __name__ == "__main__":
    if ctk is None:
        print("Fehler: CustomTkinter ist nicht verfügbar. Bitte installieren: pip install customtkinter tkinterdnd2")
        sys.exit(1)
    try:
        app = ModernTimencGUI()
        app.run()
    except Exception as e:
        print(f"Fehler beim Starten der Anwendung: {e}")
        sys.exit(1)
