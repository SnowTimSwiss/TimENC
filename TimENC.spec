# -*- mode: python ; coding: utf-8 -*-
import sys
import os

block_cipher = None

# Hidden imports for PySide6 - these are Qt modules that PyInstaller might miss
hiddenimports = [
    'PySide6.QtCore',
    'PySide6.QtGui',
    'PySide6.QtWidgets',
    'PySide6.QtNetwork',
    'cryptography',
    'cryptography.hazmat',
    'cryptography.hazmat.primitives',
    'cryptography.hazmat.primitives.ciphers',
    'cryptography.hazmat.primitives.ciphers.aead',
    'argon2',
    'argon2.low_level',
]

a = Analysis(
    ['timenc.py'],
    pathex=[],
    binaries=[],
    datas=[
        ('Images/TimENC-Icon.png', 'Images'),
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='TimENC',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # GUI application, no console
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='Images/TimENC-Icon.ico' if sys.platform == 'win32' else ('Images/TimENC-Icon.icns' if sys.platform == 'darwin' else None)
)

if sys.platform == 'darwin':
    app = BUNDLE(
        exe,
        name='TimENC.app',
        icon='Images/TimENC-Icon.icns',
        bundle_identifier='com.snowtimswiss.timenc',
        info_plist={
            'CFBundleName': 'TimENC',
            'CFBundleDisplayName': 'TimENC',
            'CFBundleIdentifier': 'com.snowtimswiss.timenc',
            'CFBundleVersion': '1.2.1',
            'CFBundleShortVersionString': '1.2.1',
            'NSHighResolutionCapable': 'True',
        },
    )
