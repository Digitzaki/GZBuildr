# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['GZBuildr.py'],
    pathex=[],
    binaries=[],
    datas=[('gz.ico', '.'), ('Data Tools', 'Data Tools'), ('PRX_Tools', 'PRX_Tools'), ('gste_script_tool_v3.py', '.'), ('pvm_script_tool.py', '.'), ('edf_dump_codec.py', '.')],
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
    name='GZBuildr',
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
    icon=['gz.ico'],
)
