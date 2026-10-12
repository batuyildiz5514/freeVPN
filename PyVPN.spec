# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_all

block_cipher = None

datas = [
    ('wintun.dll', '.'),
    ('pyvpn.ico', '.'),
]
binaries = [
    ('wintun.dll', '.'),
]

# Collect all assets for GUI and tray libraries
datas_ctk, binaries_ctk, hiddenimports_ctk = collect_all('customtkinter')
datas += datas_ctk
binaries += binaries_ctk

datas_pst, binaries_pst, hiddenimports_pst = collect_all('pystray')
datas += datas_pst
binaries += binaries_pst

datas_crypto, binaries_crypto, hiddenimports_crypto = collect_all('cryptography')
datas += datas_crypto
binaries += binaries_crypto

hiddenimports = [
    'customtkinter',
    'pystray',
    'PIL',
    'PIL.Image',
    'PIL.ImageDraw',
    'cryptography',
    'cryptography.hazmat.primitives.ciphers.aead',
    'ctypes',
    'ctypes.wintypes',
] + hiddenimports_ctk + hiddenimports_pst + hiddenimports_crypto

a = Analysis(
    ['main.py'],
    pathex=['.'],
    binaries=binaries,
    datas=datas,
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
    name='PyVPN',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
    icon=['pyvpn.ico'],
)
