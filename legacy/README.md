# Legacy (Python Version)

Dieser Ordner enthält den originalen Python-Code von TimENC v1.x.

## Dateien

- `timenc.py` - Hauptanwendung (Python mit PySide6)
- `requirements.txt` - Python-Abhängigkeiten
- `TimENC.spec` - PyInstaller Konfiguration
- `TimENC.desktop` - Linux Desktop-Entry
- `.github/workflows/release-build.yml` - Alter GitHub Actions Workflow

## Verwendung (nicht mehr empfohlen)

```bash
# Dependencies installieren
pip install -r requirements.txt

# Anwendung starten
python timenc.py

# Oder mit PyInstaller bauen
pyinstaller TimENC.spec
```

## ⚠️ Deprecated

Diese Version wird nicht mehr aktiv entwickelt. 
Bitte verwende die neue Rust-Version (v2.0+) für:
- Bessere Performance
- Kleinere Binärdateien (~10MB statt ~100MB)
- Memory Safety durch Rust
- Gleiche Verschlüsselung (v2/v3 kompatibel)
