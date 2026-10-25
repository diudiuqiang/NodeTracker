# -*- mode: python ; coding: utf-8 -*-

import os

# v1.9.2：v2rayN 安装路径会变，sing-box 内核按需打包（存在才打，避免打包失败）
_KERNEL_CANDIDATES = [
    r"C:\v2rayN-windows-64\bin\sing_box\sing-box.exe",
    r"C:\v2rayN-With-Core\bin\sing_box\sing-box.exe",
]
_binaries = []
for _kc in _KERNEL_CANDIDATES:
    if os.path.exists(_kc):
        _binaries.append((_kc, '.'))
        break

a = Analysis(
    ['node_stability_tracker.py'],
    pathex=[],
    binaries=_binaries,
    datas=[('app_icon.ico', '.')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='NodeTracker',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    icon='app_icon.ico',
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
