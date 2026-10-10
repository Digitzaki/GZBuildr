"""
Pipeworks Bundle Parser
- Developed by Digitzaki
A GUI tool for parsing, extracting, and rebuilding GameCube/PS2 bundle files.

Features:
- Parse BDG/CMG/CMP/BDL/VOL bundle files and display contents
- Extract individual files by type
- Rebuild BDG/CMG/CMP/BDL/VOL files with modified content
- Drag-and-drop support
- Supports Pipeworks format (BDG/CMG/CMP/CLP/CLF/BDP/BDL/BSF) and .VOL format (experimental)
- Block size alignment restrictions, adjustable during rebuild.

To enable drag-and-drop functionality, install:
    pip install tkinterdnd2

If not installed, you can still use the Browse button to select files.
"""
import ctypes

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(2)  # Per-monitor DPI aware
except Exception:
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass

import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox, simpledialog
import struct
import math
import os
import shutil
import zipfile
import tempfile
import json
import base64
import re
import sys
import importlib.util
import subprocess
import difflib
import threading
import webbrowser
from xml.dom import minidom
from datetime import datetime, timezone
from pathlib import Path

try:
    from update_checker import APP_VERSION, REPOSITORY_URL, check_for_updates
    HAS_UPDATE_CHECKER = True
except Exception:
    APP_VERSION = "3.5.0"
    REPOSITORY_URL = "https://github.com/Digitzaki/GZBuildr"
    check_for_updates = None
    HAS_UPDATE_CHECKER = False

try:
    from PIL import Image, ImageTk
    HAS_PIL = True
except Exception:
    Image = None
    ImageTk = None
    HAS_PIL = False

try:
    import ttkbootstrap
    HAS_TTKBOOTSTRAP = True
except Exception:
    ttkbootstrap = None
    HAS_TTKBOOTSTRAP = False


APP_USER_MODEL_ID = "GZBuildr.BundleManager"
APP_THEME_MODE = "dark"
APP_THEME = "darkly"
APP_BG = "#222222"
APP_TEXT_BG = "#111827"
APP_TEXT_FG = "#e5e7eb"
APP_TEXT_SELECT_BG = "#375a7f"
APP_TEXT_SELECT_FG = "#ffffff"
APP_BORDER = "#4b5563"
APP_BUTTON_BG = "#2f3640"
APP_BUTTON_ACTIVE_BG = "#3b4350"
APP_SCROLLBAR_BG = "#2f3640"
APP_SCROLLBAR_ACTIVE_BG = "#4b5563"
APP_SETTINGS_FILENAME = "settings.json"
# Automatic startup checks stay silent unless a release or same-version
# mini-fix exists. Manual checks from Settings still display every result.
UPDATE_CHECK_SHOW_ALL_RESULTS = False


THEME_PALETTES = {
    "dark": {
        "ttkbootstrap": "darkly",
        "bg": "#222222",
        "text_bg": "#111827",
        "text_fg": "#e5e7eb",
        "select_bg": "#375a7f",
        "select_fg": "#ffffff",
        "border": "#4b5563",
        "button_bg": "#2f3640",
        "button_active_bg": "#3b4350",
        "scrollbar_bg": "#2f3640",
        "scrollbar_active_bg": "#4b5563",
    },
    "light": {
        "ttkbootstrap": "flatly",
        "bg": "#f5f5f5",
        "text_bg": "#f7f7f8",
        "text_fg": "#111827",
        "select_bg": "#8ec5ff",
        "select_fg": "#000000",
        "border": "#9ca3af",
        "button_bg": "#f3f4f6",
        "button_active_bg": "#e5e7eb",
        "scrollbar_bg": "#d1d5db",
        "scrollbar_active_bg": "#9ca3af",
    },
}


def get_documents_dir():
    documents = Path.home() / "Documents"
    return documents if documents.exists() else Path.home()


def get_app_data_dir():
    return get_documents_dir() / "GZBuildr"


def get_logs_dir():
    return get_app_data_dir() / "logs"


def get_temp_dir():
    return get_app_data_dir() / "temp"


def safe_path_name(value):
    safe = ''.join(ch if ch not in '<>:"/\\|?*' and ord(ch) >= 32 else '_' for ch in str(value))
    return safe.strip() or "item"


def get_settings_path():
    return get_app_data_dir() / APP_SETTINGS_FILENAME


def ensure_app_dirs():
    for folder in (get_app_data_dir(), get_logs_dir(), get_temp_dir()):
        folder.mkdir(parents=True, exist_ok=True)


def default_app_settings():
    return {
        "last_input_path": "",
        "last_input_mode": "",
        "last_bundle_selection": "",
        "theme_mode": "dark",
        "alignment_presets": {},
        "rebuild_replacement_dirs": {},
    }


def load_app_settings():
    settings = default_app_settings()
    path = get_settings_path()
    try:
        if path.exists():
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                settings.update(loaded)
                if not isinstance(settings.get("alignment_presets"), dict):
                    settings["alignment_presets"] = {}
    except Exception:
        pass
    return settings


def save_app_settings(settings):
    try:
        ensure_app_dirs()
        get_settings_path().write_text(json.dumps(settings, indent=2), encoding="utf-8")
    except Exception:
        pass


def append_app_log(text):
    try:
        ensure_app_dirs()
        log_path = get_logs_dir() / f"GZBuildr_{datetime.now().strftime('%Y%m%d')}.log"
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_path.open("a", encoding="utf-8").write(f"[{timestamp}] {text.rstrip()}\n")
    except Exception:
        pass


def clear_app_temp_contents():
    """Remove files created under Documents/GZBuildr/temp."""
    ensure_app_dirs()
    temp_dir = get_temp_dir()
    for child in temp_dir.iterdir():
        try:
            if child.is_dir():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)
        except Exception:
            pass


def open_folder(path):
    ensure_app_dirs()
    folder = Path(path)
    folder.mkdir(parents=True, exist_ok=True)
    try:
        if sys.platform == "win32":
            os.startfile(str(folder))
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(folder)])
        else:
            subprocess.Popen(["xdg-open", str(folder)])
    except Exception as exc:
        messagebox.showerror("Open Folder", f"Could not open folder:\n{folder}\n\n{exc}")

try:
    from gste_script_tool_v3 import decompile_bsf, read_tokens, format_source, lex_source, compile_tokens, DEFAULT_SOURCE_NAME
    HAS_GSTE_SCRIPT_TOOL = True
except Exception:
    HAS_GSTE_SCRIPT_TOOL = False
    decompile_bsf = None
    read_tokens = None
    format_source = None
    lex_source = None
    compile_tokens = None
    DEFAULT_SOURCE_NAME = "game.scr"

try:
    from edf_dump_codec import dump_to_editable, editable_to_dump, load_field_names
    HAS_EDF_CODEC = True
except Exception:
    HAS_EDF_CODEC = False
    dump_to_editable = None
    editable_to_dump = None
    load_field_names = None

try:
    from pvm_script_tool import is_pwk_vm_module, parse_pvm, pvm_to_editable, editable_to_pvm
    HAS_PVM_SCRIPT_TOOL = True
except Exception:
    HAS_PVM_SCRIPT_TOOL = False
    is_pwk_vm_module = None
    pvm_to_editable = None
    editable_to_pvm = None
    parse_pvm = None

try:
    from loc_text_tool import loc_to_editable, editable_to_loc
    HAS_LOC_TEXT_TOOL = True
except Exception:
    HAS_LOC_TEXT_TOOL = False
    loc_to_editable = None
    editable_to_loc = None


def _load_prx_value_editor():
    candidates = [
        Path(sys.executable).resolve().parent / "PRX_Tools" / "prx_value_editor.py",
        Path(__file__).resolve().parent / "PRX_Tools" / "prx_value_editor.py",
        Path(resource_path(os.path.join("PRX_Tools", "prx_value_editor.py"))),
        Path(resource_path("prx_value_editor.py")),
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            spec = importlib.util.spec_from_file_location("gzbuildr_prx_value_editor", candidate)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
        except Exception:
            continue
    return None


TOOL_LOAD_ERRORS = {}


def _record_tool_load_error(tool_name, candidate, exc):
    TOOL_LOAD_ERRORS.setdefault(tool_name, []).append(f"{candidate}: {exc}")


def _load_character_data_tool():
    candidates = [
        Path(sys.executable).resolve().parent / "Data Tools" / "character_data_txt_tool.py",
        Path(__file__).resolve().parent / "Data Tools" / "character_data_txt_tool.py",
        Path(resource_path(os.path.join("Data Tools", "character_data_txt_tool.py"))),
        Path(resource_path("character_data_txt_tool.py")),
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            spec = importlib.util.spec_from_file_location("gzbuildr_character_data_txt_tool", candidate)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
        except Exception as exc:
            _record_tool_load_error("character_data", candidate, exc)
            continue
    return None


def _load_monster_data_tool():
    candidates = [
        Path(sys.executable).resolve().parent / "Data Tools" / "monster_data_txt_tool.py",
        Path(__file__).resolve().parent / "Data Tools" / "monster_data_txt_tool.py",
        Path(resource_path(os.path.join("Data Tools", "monster_data_txt_tool.py"))),
        Path(resource_path("monster_data_txt_tool.py")),
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            spec = importlib.util.spec_from_file_location("gzbuildr_monster_data_txt_tool", candidate)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
        except Exception as exc:
            _record_tool_load_error("monster_data", candidate, exc)
            continue
    return None


def _load_palette_text_tool():
    candidates = [
        Path(sys.executable).resolve().parent / "Data Tools" / "palette_text_tool.py",
        Path(__file__).resolve().parent / "Data Tools" / "palette_text_tool.py",
        Path(resource_path(os.path.join("Data Tools", "palette_text_tool.py"))),
        Path(resource_path("palette_text_tool.py")),
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            spec = importlib.util.spec_from_file_location("gzbuildr_palette_text_tool", candidate)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
        except Exception as exc:
            _record_tool_load_error("palette", candidate, exc)
    return None


def _load_static_mesh_viewer():
    candidates = [
        Path(sys.executable).resolve().parent / "Data Tools" / "static_mesh_viewer.py",
        Path(__file__).resolve().parent / "Data Tools" / "static_mesh_viewer.py",
        Path(resource_path(os.path.join("Data Tools", "static_mesh_viewer.py"))),
        Path(resource_path("static_mesh_viewer.py")),
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            spec = importlib.util.spec_from_file_location("gzbuildr_static_mesh_viewer", candidate)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
        except Exception as exc:
            _record_tool_load_error("static_mesh", candidate, exc)
    return None


def _load_gamecube_static_mesh():
    candidates = [
        Path(sys.executable).resolve().parent / "Data Tools" / "gamecube_static_mesh.py",
        Path(__file__).resolve().parent / "Data Tools" / "gamecube_static_mesh.py",
        Path(resource_path(os.path.join("Data Tools", "gamecube_static_mesh.py"))),
        Path(resource_path("gamecube_static_mesh.py")),
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            spec = importlib.util.spec_from_file_location("gzbuildr_gamecube_static_mesh", candidate)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
        except Exception as exc:
            _record_tool_load_error("gamecube_static_mesh", candidate, exc)
    return None


def _load_ps2_static_mesh():
    candidates = [
        Path(sys.executable).resolve().parent / "Data Tools" / "ps2_static_mesh.py",
        Path(__file__).resolve().parent / "Data Tools" / "ps2_static_mesh.py",
        Path(resource_path(os.path.join("Data Tools", "ps2_static_mesh.py"))),
        Path(resource_path("ps2_static_mesh.py")),
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            spec = importlib.util.spec_from_file_location("gzbuildr_ps2_static_mesh", candidate)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
        except Exception as exc:
            _record_tool_load_error("ps2_static_mesh", candidate, exc)
    return None


def _load_cmg_data_tool():
    candidates = [
        Path(sys.executable).resolve().parent / "Data Tools" / "cmg_data_txt_tool.py",
        Path(__file__).resolve().parent / "Data Tools" / "cmg_data_txt_tool.py",
        Path(resource_path(os.path.join("Data Tools", "cmg_data_txt_tool.py"))),
        Path(resource_path("cmg_data_txt_tool.py")),
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            spec = importlib.util.spec_from_file_location("gzbuildr_cmg_data_txt_tool", candidate)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
        except Exception as exc:
            _record_tool_load_error("cmg_data", candidate, exc)
            continue
    return None


def _load_skeleton_type3_tool():
    candidates = [
        Path(sys.executable).resolve().parent / "Data Tools" / "skeleton_type3_txt_tool.py",
        Path(__file__).resolve().parent / "Data Tools" / "skeleton_type3_txt_tool.py",
        Path(resource_path(os.path.join("Data Tools", "skeleton_type3_txt_tool.py"))),
        Path(resource_path("skeleton_type3_txt_tool.py")),
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            spec = importlib.util.spec_from_file_location("gzbuildr_skeleton_type3_txt_tool", candidate)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
        except Exception as exc:
            _record_tool_load_error("skeleton_type3", candidate, exc)
            continue
    return None


def _load_level_data_tool():
    candidates = [
        Path(sys.executable).resolve().parent / "Data Tools" / "level_data_txt_tool.py",
        Path(__file__).resolve().parent / "Data Tools" / "level_data_txt_tool.py",
        Path(resource_path(os.path.join("Data Tools", "level_data_txt_tool.py"))),
        Path(resource_path("level_data_txt_tool.py")),
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            spec = importlib.util.spec_from_file_location("gzbuildr_level_data_txt_tool", candidate)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
        except Exception as exc:
            _record_tool_load_error("level_data", candidate, exc)
            continue
    return None


def _load_material_text_tool():
    candidates = [
        Path(sys.executable).resolve().parent / "Data Tools" / "material_text_tool.py",
        Path(__file__).resolve().parent / "Data Tools" / "material_text_tool.py",
        Path(resource_path(os.path.join("Data Tools", "material_text_tool.py"))),
        Path(resource_path("material_text_tool.py")),
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            spec = importlib.util.spec_from_file_location("gzbuildr_material_text_tool", candidate)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
        except Exception as exc:
            _record_tool_load_error("material", candidate, exc)
            continue
    return None


def _load_fdf_text_tool():
    candidates = [
        Path(sys.executable).resolve().parent / "Data Tools" / "fdf_text_tool.py",
        Path(__file__).resolve().parent / "Data Tools" / "fdf_text_tool.py",
        Path(resource_path(os.path.join("Data Tools", "fdf_text_tool.py"))),
        Path(resource_path("fdf_text_tool.py")),
    ]
    for candidate in candidates:
        if not candidate.exists():
            continue
        try:
            spec = importlib.util.spec_from_file_location("gzbuildr_fdf_text_tool", candidate)
            if spec is None or spec.loader is None:
                continue
            module = importlib.util.module_from_spec(spec)
            sys.modules[spec.name] = module
            spec.loader.exec_module(module)
            return module
        except Exception as exc:
            _record_tool_load_error("fdf", candidate, exc)
    return None


def resource_path(relative_path):
    base_path = getattr(sys, '_MEIPASS', os.path.abspath(os.path.dirname(__file__)))
    return os.path.join(base_path, relative_path)


def set_windows_app_identity():
    if sys.platform != "win32":
        return
    try:
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
    except Exception:
        pass


def set_dark_title_bar(window, dark=None):
    if sys.platform != "win32":
        return
    if dark is None:
        dark = APP_THEME_MODE == "dark"

    def apply():
        try:
            window.update_idletasks()
            hwnd = ctypes.windll.user32.GetParent(window.winfo_id()) or window.winfo_id()
            value = ctypes.c_int(1 if dark else 0)
            for attribute in (20, 19):
                result = ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    ctypes.c_void_p(hwnd),
                    ctypes.c_int(attribute),
                    ctypes.byref(value),
                    ctypes.sizeof(value),
                )
                if result == 0:
                    break
        except Exception:
            pass

    try:
        window.after(50, apply)
    except Exception:
        apply()


def set_window_icon(window):
    icon_path = resource_path("gz.ico")
    if os.path.exists(icon_path):
        try:
            window.iconbitmap(icon_path)
        except tk.TclError:
            pass
    set_dark_title_bar(window)


def set_theme_palette(mode):
    global APP_THEME_MODE, APP_THEME, APP_BG, APP_TEXT_BG, APP_TEXT_FG
    global APP_TEXT_SELECT_BG, APP_TEXT_SELECT_FG, APP_BORDER
    global APP_BUTTON_BG, APP_BUTTON_ACTIVE_BG, APP_SCROLLBAR_BG, APP_SCROLLBAR_ACTIVE_BG

    if mode not in THEME_PALETTES:
        mode = "light"
    palette = THEME_PALETTES[mode]
    APP_THEME_MODE = mode
    APP_THEME = palette["ttkbootstrap"]
    APP_BG = palette["bg"]
    APP_TEXT_BG = palette["text_bg"]
    APP_TEXT_FG = palette["text_fg"]
    APP_TEXT_SELECT_BG = palette["select_bg"]
    APP_TEXT_SELECT_FG = palette["select_fg"]
    APP_BORDER = palette["border"]
    APP_BUTTON_BG = palette["button_bg"]
    APP_BUTTON_ACTIVE_BG = palette["button_active_bg"]
    APP_SCROLLBAR_BG = palette["scrollbar_bg"]
    APP_SCROLLBAR_ACTIVE_BG = palette["scrollbar_active_bg"]


def configure_app_theme(root, mode=None):
    set_theme_palette(mode or APP_THEME_MODE)
    if HAS_TTKBOOTSTRAP:
        try:
            ttkbootstrap.Style().theme_use(APP_THEME)
        except Exception:
            pass
    try:
        style = ttk.Style(root)
        if not HAS_TTKBOOTSTRAP:
            style.theme_use('clam')
        style.configure('.', background=APP_BG, foreground=APP_TEXT_FG, fieldbackground=APP_TEXT_BG)
        style.configure('TFrame', background=APP_BG)
        style.configure('TLabelframe', background=APP_BG, foreground=APP_TEXT_FG)
        style.configure('TLabelframe.Label', background=APP_BG, foreground=APP_TEXT_FG)
        style.configure('TLabel', background=APP_BG, foreground=APP_TEXT_FG)
        try:
            style.layout('GZ.TButton', style.layout('TButton'))
        except Exception:
            pass
        style.configure(
            'GZ.TButton',
            background=APP_BUTTON_BG,
            foreground=APP_TEXT_FG,
            bordercolor=APP_BORDER,
            lightcolor=APP_BORDER,
            darkcolor=APP_BORDER,
            focuscolor=APP_BORDER,
            borderwidth=1,
            relief=tk.SOLID,
            padding=(8, 4),
        )
        style.map(
            'GZ.TButton',
            background=[('active', APP_BUTTON_ACTIVE_BG), ('pressed', APP_SCROLLBAR_ACTIVE_BG)],
            relief=[('pressed', tk.SUNKEN), ('!pressed', tk.SOLID)],
        )
        style.configure('TCheckbutton', background=APP_BG, foreground=APP_TEXT_FG)
        style.configure('TEntry', fieldbackground=APP_TEXT_BG, foreground=APP_TEXT_FG)
        style.configure('TCombobox', fieldbackground=APP_TEXT_BG, foreground=APP_TEXT_FG)
        style.configure(
            'Vertical.TScrollbar',
            background=APP_SCROLLBAR_BG,
            darkcolor=APP_SCROLLBAR_BG,
            lightcolor=APP_SCROLLBAR_BG,
            troughcolor=APP_TEXT_BG,
            bordercolor=APP_BORDER,
            arrowcolor=APP_TEXT_FG,
            relief=tk.FLAT,
            width=18,
            arrowsize=16,
        )
        style.map(
            'Vertical.TScrollbar',
            background=[('active', APP_SCROLLBAR_ACTIVE_BG), ('pressed', APP_SCROLLBAR_ACTIVE_BG)],
        )
        style.configure(
            'Horizontal.TScrollbar',
            background=APP_SCROLLBAR_BG,
            darkcolor=APP_SCROLLBAR_BG,
            lightcolor=APP_SCROLLBAR_BG,
            troughcolor=APP_TEXT_BG,
            bordercolor=APP_BORDER,
            arrowcolor=APP_TEXT_FG,
            relief=tk.FLAT,
            width=18,
            arrowsize=16,
        )
    except Exception:
        pass
    try:
        root.configure(bg=APP_BG)
    except Exception:
        pass


def apply_button_outline(widget):
    try:
        if widget.winfo_class() == "TButton":
            widget.configure(style='GZ.TButton')
    except Exception:
        pass
    try:
        children = widget.winfo_children()
    except Exception:
        children = []
    for child in children:
        apply_button_outline(child)


def style_text_widget(widget):
    try:
        widget.configure(
            bg=APP_TEXT_BG,
            fg=APP_TEXT_FG,
            insertbackground=APP_TEXT_FG,
            selectbackground=APP_TEXT_SELECT_BG,
            selectforeground=APP_TEXT_SELECT_FG,
            highlightbackground=APP_BORDER,
            highlightcolor=APP_BORDER,
        )
    except Exception:
        pass


def apply_runtime_theme(widget):
    try:
        cls = widget.winfo_class()
    except Exception:
        cls = ""

    try:
        if cls in ("Text",):
            style_text_widget(widget)
        elif cls in ("Canvas", "Frame", "Toplevel", "Tk"):
            widget.configure(bg=APP_BG)
        elif cls in ("Entry",):
            widget.configure(
                bg=APP_TEXT_BG,
                fg=APP_TEXT_FG,
                insertbackground=APP_TEXT_FG,
                selectbackground=APP_TEXT_SELECT_BG,
                selectforeground=APP_TEXT_SELECT_FG,
            )
        elif cls in ("Button",):
            widget.configure(
                bg=APP_BUTTON_BG,
                fg=APP_TEXT_FG,
                activebackground=APP_BUTTON_ACTIVE_BG,
                activeforeground=APP_TEXT_FG,
            )
    except Exception:
        pass

    try:
        children = widget.winfo_children()
    except Exception:
        children = []
    for child in children:
        apply_runtime_theme(child)


def create_dark_scrolled_text(parent, show_horizontal=False, show_diff_marker=False, **kwargs):
    container = ttk.Frame(parent)
    container.columnconfigure(0, weight=1)
    container.rowconfigure(0, weight=1)

    text = tk.Text(container, **kwargs)
    style_text_widget(text)

    diff_marker = None
    if show_diff_marker:
        diff_marker = tk.Canvas(
            container,
            width=8,
            bg=APP_TEXT_BG,
            highlightthickness=0,
            bd=0,
            takefocus=0,
            cursor="hand2",
        )
    yscroll = ttk.Scrollbar(container, orient=tk.VERTICAL, command=text.yview, style='Vertical.TScrollbar')

    def _set_yview(first, last):
        yscroll.set(first, last)
        callback = getattr(text, "_diff_marker_scroll_callback", None)
        if callback:
            callback()
        syntax_callback = getattr(text, "_syntax_scroll_callback", None)
        if syntax_callback:
            syntax_callback()

    text.configure(yscrollcommand=_set_yview)
    text._diff_marker_canvas = diff_marker

    text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
    scrollbar_column = 1
    if diff_marker is not None:
        diff_marker.grid(row=0, column=1, sticky=(tk.N, tk.S), padx=(2, 0))
        scrollbar_column = 2
    yscroll.grid(row=0, column=scrollbar_column, sticky=(tk.N, tk.S))
    if show_horizontal:
        xscroll = ttk.Scrollbar(container, orient=tk.HORIZONTAL, command=text.xview, style='Horizontal.TScrollbar')
        text.configure(xscrollcommand=xscroll.set)
        xscroll.grid(row=1, column=0, sticky=(tk.W, tk.E))

    return container, text


def _themed_message_dialog(kind, title, message, parent=None, buttons=("OK",), default=None):
    parent = parent or tk._default_root
    if parent is None:
        return None

    result = {"value": default if default is not None else buttons[0]}
    window = tk.Toplevel(parent)
    set_window_icon(window)
    window.title(title)
    window.transient(parent)
    window.resizable(False, False)
    window.grab_set()

    frame = ttk.Frame(window, padding=14)
    frame.pack(fill=tk.BOTH, expand=True)

    body = ttk.Frame(frame)
    body.pack(fill=tk.BOTH, expand=True)

    symbol_map = {
        "info": "i",
        "warning": "!",
        "error": "X",
        "question": "?",
    }
    symbol = tk.Label(
        body,
        text=symbol_map.get(kind, "i"),
        width=2,
        height=1,
        font=("TkDefaultFont", 18, "bold"),
        bg=APP_TEXT_SELECT_BG,
        fg=APP_TEXT_SELECT_FG,
        relief=tk.FLAT,
    )
    symbol.pack(side=tk.LEFT, padx=(0, 14), anchor=tk.N)

    label = ttk.Label(body, text=str(message), justify=tk.LEFT, wraplength=420)
    label.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, anchor=tk.N)

    button_row = ttk.Frame(frame)
    button_row.pack(fill=tk.X, pady=(14, 0))

    def choose(value):
        result["value"] = value
        window.destroy()

    for button_text, value in buttons:
        ttk.Button(button_row, text=button_text, command=lambda v=value: choose(v), width=10).pack(side=tk.RIGHT, padx=(6, 0))

    window.protocol("WM_DELETE_WINDOW", lambda: choose(default))
    apply_runtime_theme(window)
    apply_button_outline(window)
    window.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() - window.winfo_width()) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - window.winfo_height()) // 2
    window.geometry(f"+{max(0, x)}+{max(0, y)}")
    window.wait_window()
    return result["value"]


def _show_themed_info(title, message, **kwargs):
    return _themed_message_dialog("info", title, message, kwargs.get("parent"), [("OK", "ok")], "ok")


def _show_themed_warning(title, message, **kwargs):
    return _themed_message_dialog("warning", title, message, kwargs.get("parent"), [("OK", "ok")], "ok")


def _show_themed_error(title, message, **kwargs):
    return _themed_message_dialog("error", title, message, kwargs.get("parent"), [("OK", "ok")], "ok")


def _ask_themed_yesno(title, message, **kwargs):
    return bool(_themed_message_dialog("question", title, message, kwargs.get("parent"), [("No", False), ("Yes", True)], False))


def _ask_themed_yesnocancel(title, message, **kwargs):
    return _themed_message_dialog(
        "question",
        title,
        message,
        kwargs.get("parent"),
        [("Cancel", None), ("No", False), ("Yes", True)],
        None,
    )


messagebox.showinfo = _show_themed_info
messagebox.showwarning = _show_themed_warning
messagebox.showerror = _show_themed_error
messagebox.askyesno = _ask_themed_yesno
messagebox.askyesnocancel = _ask_themed_yesnocancel


PRX_VALUE_EDITOR = _load_prx_value_editor()
HAS_PRX_TOOLS = PRX_VALUE_EDITOR is not None
CHARACTER_DATA_TOOL = _load_character_data_tool()
HAS_CHARACTER_DATA_TOOL = CHARACTER_DATA_TOOL is not None
MONSTER_DATA_TOOL = _load_monster_data_tool()
HAS_MONSTER_DATA_TOOL = MONSTER_DATA_TOOL is not None
PALETTE_TEXT_TOOL = _load_palette_text_tool()
HAS_PALETTE_TEXT_TOOL = PALETTE_TEXT_TOOL is not None
GAMECUBE_STATIC_MESH = _load_gamecube_static_mesh()
PS2_STATIC_MESH = _load_ps2_static_mesh()
STATIC_MESH_VIEWER = _load_static_mesh_viewer()
HAS_STATIC_MESH_VIEWER = STATIC_MESH_VIEWER is not None
CMG_DATA_TOOL = _load_cmg_data_tool()
HAS_CMG_DATA_TOOL = CMG_DATA_TOOL is not None
SKELETON_TYPE3_TOOL = _load_skeleton_type3_tool()
HAS_SKELETON_TYPE3_TOOL = SKELETON_TYPE3_TOOL is not None
LEVEL_DATA_TOOL = _load_level_data_tool()
HAS_LEVEL_DATA_TOOL = LEVEL_DATA_TOOL is not None
MATERIAL_TEXT_TOOL = _load_material_text_tool()
HAS_MATERIAL_TEXT_TOOL = MATERIAL_TEXT_TOOL is not None
FDF_TEXT_TOOL = _load_fdf_text_tool()
HAS_FDF_TEXT_TOOL = FDF_TEXT_TOOL is not None


def _dialog(parent, dialog_fn, **kwargs):
    host = tk.Toplevel(parent)
    host.withdraw()
    host.attributes('-topmost', True)
    try:
        result = dialog_fn(parent=host, **kwargs)
    finally:
        host.destroy()
    return result


# Try to import drag-and-drop library
HAS_DND = False

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    pass


SUPPORTED_BUNDLE_EXTENSIONS = (
    '.bdg', '.cmg', '.cmp', '.clp', '.clf', '.bdp', '.bdl', '.bsf',
    '.vol', '.ccg', '.cmf', '.ccf', '.zip', '.txt', '.ifc', '.ifl', '.xfg', '.prx', '.edf', '.pvm', '.loc'
)
EDITABLE_ENTRY_EXTENSIONS = ('.bsf', '.txt', '.ifc', '.ifl', '.xfg', '.prx', '.edf', '.pvm', '.loc')
CHARACTER_DATA_ENTRY_NAME = "2/character_data"
MONSTER_DATA_ENTRY_NAME = "2/000monster_data"
CMG_MONSTER_DATA_RE = re.compile(r"^2/monster_data\d*$")


class PipeworksParser:
    def __init__(self, filepath):
        self.filepath = filepath
        self.file_data = None
        self.is_big_endian = False
        self.bundle_type = None  # 'pipeworks' or 'vol'
        self.string_offset = 0
        self.file_count = 0
        self.metadata_offset = 0
        self.main_data_offset = 0
        self.resource_data_offset = 0

    def read_bytes(self, offset, size):
        """Read bytes from file at specific offset"""
        return self.file_data[offset:offset + size]

    def read_long(self, offset):
        """Read 4-byte long (endianness based on file)"""
        endian = '>' if self.is_big_endian else '<'
        return struct.unpack(f'{endian}I', self.read_bytes(offset, 4))[0]

    def read_short(self, offset):
        """Read 2-byte short (endianness based on file)"""
        endian = '>' if self.is_big_endian else '<'
        return struct.unpack(f'{endian}H', self.read_bytes(offset, 2))[0]

    def read_byte(self, offset):
        """Read 1-byte"""
        return self.file_data[offset]

    def read_long_little(self, offset):
        """Read 4-byte little-endian long (for string table)"""
        return struct.unpack('<I', self.read_bytes(offset, 4))[0]

    def read_string(self, offset):
        """Read null-terminated string and clean it"""
        end = offset
        while end < len(self.file_data) and self.file_data[end] != 0:
            end += 1
        # Decode and strip control characters and extended ASCII
        raw_string = self.file_data[offset:end].decode('ascii', errors='ignore')
        # Keep only printable ASCII characters (32-126) and strip whitespace
        cleaned = ''.join(c for c in raw_string if 32 <= ord(c) <= 126)
        return cleaned.strip()

    def detect_file_type_from_extension(self, filename):
        """Detect file type from filename extension for VOL files"""
        ext = filename.lower().split('.')[-1] if '.' in filename else ''

        # Map common extensions to file types
        extension_map = {
            'cmp': 0,   # Static Mesh (compressed)
            'bdg': 0,   # Static Mesh bundle
            'cmg': 0,   # Static Mesh bundle
            'mesh': 0,  # Static Mesh
            'skel': 1,  # Skeleton
            'skl': 1,   # Skeleton
            'anim': 4,  # Animation
            'ani': 4,   # Animation
            'mat': 6,   # Material
            'dds': 9,   # Texture
            'tga': 9,   # Texture
            'png': 9,   # Texture
            'tex': 9,   # Texture
            'pvm': 9,   # Texture (PVM archive)
            'pal': 13,  # Palette
            'pwk': 16,  # PWK File
            'edf': 20,  # Particle
            'prx': 22,  # PRX File
            'loc': 23,  # Localization
            'txt': 23,  # Localization
            'zip': 24,  # Archive
            'mic': 25,  # Audio (MIC format)
            'bdp': 26,  # BDP File
            'pss': 27,  # Video (PSS format)
            'bsf': 28,  # BSF File (PS2)
            'clp': 29,  # CLP File (PS2)
            'clf': 29,  # CLF File (Xbox)
        }

        return extension_map.get(ext, 255)  # 255 = Unknown

    def _infer_new_file_type(self, filename, source_path=None, vol=False):
        """Infer a bundle file type for a newly inserted file."""
        if not vol and source_path:
            parent = os.path.basename(os.path.dirname(source_path))
            if parent.isdigit():
                value = int(parent)
                if 0 <= value <= 255:
                    return value

        if not vol:
            ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
            pipeworks_extension_map = {
                'cmp': 0,
                'bdg': 0,
                'cmg': 0,
                'mesh': 0,
                'skel': 1,
                'skl': 1,
                'anim': 4,
                'ani': 4,
                'mat': 6,
                'dds': 9,
                'tga': 9,
                'png': 9,
                'tex': 9,
                'pvm': 9,
                'pal': 13,
                'pwk': 16,
                'edf': 20,
                'prx': 22,
                'loc': 23,
                'zip': 24,
                'mic': 25,
                'bdp': 26,
                'pss': 27,
                'bsf': 28,
                'clp': 29,
                'clf': 29,
            }
            return pipeworks_extension_map.get(ext, 255)

        return self.detect_file_type_from_extension(filename)

    def _warn_unknown_new_file_type(self, filename, file_type):
        if file_type == 255:
            print(f"  Warning: Could not confidently infer type for new file '{filename}', using Unknown (255)")

    def _normalize_new_file_spec(self, item):
        if isinstance(item, dict):
            path = item.get('path') or item.get('source_path')
            insert_index = item.get('insert_index')
        else:
            path = item
            insert_index = None
        return path, insert_index

    def _make_new_file_records(self, new_file_paths, existing_names=None, vol=False):
        """Create normalized records for files being inserted into a rebuild."""
        records = []
        seen = set()
        existing = {name.lower() for name in (existing_names or [])}

        for item in new_file_paths or []:
            path, insert_index = self._normalize_new_file_spec(item)
            if not path or not os.path.isfile(path):
                print(f"  Warning: New file skipped, not found: {path}")
                continue

            full_path = os.path.abspath(path)
            if full_path.lower() in seen:
                continue
            seen.add(full_path.lower())

            filename = os.path.basename(full_path).replace('|', '_')
            file_type = self._infer_new_file_type(filename, full_path, vol)
            self._warn_unknown_new_file_type(filename, file_type)
            if not vol and file_type == 255:
                print(f"  Warning: New Pipeworks file skipped because its type is unknown: {filename}")
                continue
            stored_name = filename if vol else f"{file_type}/{filename}"

            if stored_name.lower() in existing:
                print(f"  Warning: New file skipped because '{stored_name}' already exists in bundle")
                continue
            existing.add(stored_name.lower())

            records.append({
                'source_path': full_path,
                'filename': filename,
                'stored_name': stored_name,
                'file_type': file_type,
                'insert_index': insert_index,
            })

        return records

    def _metadata_template_for_type(self, file_type, metadata_by_type):
        template = metadata_by_type.get(file_type)
        if template is None:
            template = bytearray(0x10)
            template[8:12] = b'\x00\x01\x00\x00'
        else:
            template = bytearray(template)
        if len(template) < 0x10:
            template.extend(b'\x00' * (0x10 - len(template)))
        return template[:0x10]

    def _patch_embedded_index_references(self, data, remap, endian, file_num, file_name):
        """Patch aligned raw 16/32-bit Name ID references in type-2 style binary data."""
        if not remap:
            return data, []
        patched = bytearray(data)
        changes = []
        occupied = set()
        max_index = max(remap.values()) if remap else 0

        for pos in range(0, max(0, len(patched) - 3), 4):
            value = struct.unpack_from(f'{endian}I', patched, pos)[0]
            if value in remap and remap[value] != value and remap[value] <= max_index:
                struct.pack_into(f'{endian}I', patched, pos, remap[value])
                occupied.update(range(pos, pos + 4))
                changes.append((file_num, file_name, pos, 32, value, remap[value]))

        for pos in range(0, max(0, len(patched) - 1), 2):
            if pos in occupied or (pos + 1) in occupied:
                continue
            value = struct.unpack_from(f'{endian}H', patched, pos)[0]
            if value in remap and remap[value] != value and remap[value] <= 0xFFFF:
                struct.pack_into(f'{endian}H', patched, pos, remap[value])
                changes.append((file_num, file_name, pos, 16, value, remap[value]))

        return bytes(patched), changes

    def _read_pipeworks_string_entries(self):
        string_count, offsets, _first_string_offset, _string_data = self._read_pipeworks_string_table()
        strings = []
        for offset in offsets:
            string_pos = self.string_offset + offset
            string_end = string_pos
            while string_end < len(self.file_data) and self.file_data[string_end] != 0:
                string_end += 1
            strings.append(bytes(self.file_data[string_pos:string_end]))
        return strings

    @staticmethod
    def _summarize_index_remap(remap):
        shifted_ranges = []
        range_start = None
        previous_old = None
        range_delta = None
        for old_index, new_index in sorted(remap.items()):
            delta = new_index - old_index
            if delta:
                if range_start is None:
                    range_start = old_index
                    range_delta = delta
                elif delta != range_delta or previous_old is None or old_index != previous_old + 1:
                    shifted_ranges.append((range_start, previous_old, range_delta))
                    range_start = old_index
                    range_delta = delta
                previous_old = old_index
            elif range_start is not None:
                shifted_ranges.append((range_start, previous_old, range_delta))
                range_start = None
                previous_old = None
                range_delta = None
        if range_start is not None:
            shifted_ranges.append((range_start, previous_old, range_delta))
        return shifted_ranges

    def _plan_name_id_insertions(self, new_records):
        original_strings = self._read_pipeworks_string_entries()
        string_count = len(original_strings)
        indexed_records = []
        append_records = []

        for add_order, record in enumerate(new_records):
            record['file_num'] = self.file_count + add_order
            insert_index = record.get('insert_index')
            if insert_index is None:
                append_records.append((add_order, record))
            else:
                if insert_index < 0 or insert_index > string_count:
                    raise ValueError(
                        f"Insert index {insert_index} for {record['filename']} is outside Name ID range 0..{string_count}"
                    )
                indexed_records.append((insert_index, add_order, record))

        final_items = [{'old_string_id': idx, 'bytes': value} for idx, value in enumerate(original_strings)]
        inserted_before = 0
        for insert_index, _add_order, record in sorted(indexed_records, key=lambda item: (item[0], item[1])):
            final_items.insert(insert_index + inserted_before, {'record': record})
            inserted_before += 1
        for _add_order, record in append_records:
            final_items.append({'record': record})

        remap = {}
        new_file_indexes = {}
        for new_string_id, item in enumerate(final_items):
            if 'old_string_id' in item:
                remap[item['old_string_id']] = new_string_id
            else:
                record = item['record']
                record['string_id'] = new_string_id
                new_file_indexes[record['filename']] = new_string_id

        return final_items, remap, new_file_indexes, self._summarize_index_remap(remap)

    def _build_pipeworks_header_for_name_id_insertions(self, new_records, endian):
        """Build an expanded Pipeworks header while inserting new names into string-table IDs."""
        old_count = self.file_count
        new_count = old_count + len(new_records)
        toc_start = 0x78
        old_toc_end = toc_start + (old_count * 0x12)
        new_toc_end = toc_start + (new_count * 0x12)

        prefix = bytearray(self.file_data[:toc_start])
        original_toc = bytearray(self.file_data[toc_start:old_toc_end])
        original_metadata = bytearray(self.file_data[self.metadata_offset:self.metadata_offset + (old_count * 0x10)])

        final_string_items, remap, new_file_indexes, shifted_ranges = self._plan_name_id_insertions(new_records)

        new_string_table = bytearray()
        new_string_table.extend(struct.pack('<I', len(final_string_items)))
        offset_table_size = 4 + (4 * len(final_string_items))
        string_payload = bytearray()
        for item in final_string_items:
            if 'record' in item:
                value = item['record']['filename'].encode('ascii', errors='replace')
            else:
                value = item['bytes']
            new_string_table.extend(struct.pack('<I', offset_table_size + len(string_payload)))
            string_payload.extend(value + b'\x00')
        new_string_table.extend(string_payload)

        new_toc = bytearray(original_toc)
        for record in sorted(new_records, key=lambda item: item['file_num']):
            new_toc.extend(struct.pack(f'{endian}H', record['file_num']))
            new_toc.extend(b'\x00' * 16)

        new_metadata = bytearray()
        metadata_by_type = {}
        for i in range(old_count):
            entry = bytearray(original_metadata[i * 0x10:(i + 1) * 0x10])
            if len(entry) < 0x10:
                entry.extend(b'\x00' * (0x10 - len(entry)))
            entry = entry[:0x10]
            file_type = entry[2]
            metadata_by_type.setdefault(file_type, bytes(entry))
            old_string_id = struct.unpack_from(f'{endian}I', entry, 4)[0]
            struct.pack_into(f'{endian}H', entry, 0, i)
            struct.pack_into(f'{endian}I', entry, 4, remap.get(old_string_id, old_string_id))
            new_metadata.extend(entry)

        for record in sorted(new_records, key=lambda item: item['file_num']):
            template = self._metadata_template_for_type(record['file_type'], metadata_by_type)
            struct.pack_into(f'{endian}H', template, 0, record['file_num'])
            template[2] = record['file_type']
            struct.pack_into(f'{endian}I', template, 4, record['string_id'])
            new_metadata.extend(template)

        header_gap_offsets = []
        for offset_pos in range(0x3C, 0x60, 4):
            value = self.read_long(offset_pos)
            if old_toc_end <= value < self.string_offset:
                header_gap_offsets.append((offset_pos, value))

        first_gap_table = min((value for _, value in header_gap_offsets), default=self.string_offset)
        table_shift = 0
        if new_toc_end > first_gap_table:
            table_shift = new_toc_end - first_gap_table
            if table_shift % 16:
                table_shift += 16 - (table_shift % 16)

        moved_table_start = first_gap_table + table_shift
        padding_after_toc = max(0, moved_table_start - new_toc_end)
        gap_after_toc = bytearray(b'\xFF' * padding_after_toc)
        gap_after_toc.extend(self.file_data[first_gap_table:self.string_offset])

        new_string_offset = self.string_offset + table_shift
        new_metadata_offset = new_string_offset + len(new_string_table)
        pre_metadata_padding = (16 - (new_metadata_offset % 16)) % 16
        new_metadata_offset += pre_metadata_padding

        new_main_data_offset = new_metadata_offset + len(new_metadata)
        metadata_padding = (16 - (new_main_data_offset % 16)) % 16
        new_main_data_offset += metadata_padding

        header_and_toc = bytearray()
        header_and_toc.extend(prefix)
        header_and_toc.extend(new_toc)
        header_and_toc.extend(gap_after_toc)
        header_and_toc.extend(new_string_table)
        if pre_metadata_padding:
            header_and_toc.extend(b'\x00' * pre_metadata_padding)
        header_and_toc.extend(new_metadata)
        if metadata_padding:
            header_and_toc.extend(b'\x00' * metadata_padding)

        struct.pack_into(f'{endian}I', header_and_toc, 0x34, new_string_offset)
        for offset_pos, value in header_gap_offsets:
            struct.pack_into(f'{endian}I', header_and_toc, offset_pos, value + table_shift)
        struct.pack_into(f'{endian}H', header_and_toc, 0x62, new_count)
        struct.pack_into(f'{endian}I', header_and_toc, 0x64, new_metadata_offset)
        struct.pack_into(f'{endian}I', header_and_toc, 0x68, new_main_data_offset)

        return header_and_toc, new_count, new_main_data_offset, remap, new_file_indexes, shifted_ranges

    def _read_pipeworks_string_table(self):
        """Return string count, offsets, and raw string bytes from the Pipeworks string table."""
        string_count = struct.unpack('<I', self.file_data[self.string_offset:self.string_offset + 4])[0]
        offsets = [
            struct.unpack('<I', self.file_data[self.string_offset + 4 + (i * 4):self.string_offset + 8 + (i * 4)])[0]
            for i in range(string_count)
        ]
        first_string_offset = min(offsets) if offsets else 4
        string_data_start = self.string_offset + first_string_offset
        string_data = bytearray(self.file_data[string_data_start:self.metadata_offset])
        return string_count, offsets, first_string_offset, string_data

    @staticmethod
    def _replacement_with_match_case(match_text, replacement_text):
        if match_text.isupper():
            return replacement_text.upper()
        if match_text.islower():
            return replacement_text.lower()
        return replacement_text

    @classmethod
    def _apply_rename_rules_to_text(cls, text, rename_rules):
        updated = text
        for find_text, replace_text, ignore_case in rename_rules or []:
            if not find_text:
                continue
            if ignore_case:
                updated = re.sub(
                    re.escape(find_text),
                    lambda match: cls._replacement_with_match_case(match.group(0), replace_text),
                    updated,
                    flags=re.IGNORECASE
                )
            else:
                updated = updated.replace(find_text, replace_text)
        return updated

    def _apply_rename_rules_to_string_bytes(self, raw_bytes, rename_rules, preserve_pipe_suffix=False):
        if not rename_rules:
            return raw_bytes
        prefix_len = 0
        while prefix_len < len(raw_bytes) and raw_bytes[prefix_len] < 32:
            prefix_len += 1
        prefix = raw_bytes[:prefix_len]
        text = raw_bytes[prefix_len:].decode('ascii', errors='replace')
        if preserve_pipe_suffix and '|' in text:
            left, right = text.split('|', 1)
            updated = f"{self._apply_rename_rules_to_text(left, rename_rules)}|{right}"
        else:
            updated = self._apply_rename_rules_to_text(text, rename_rules)
        return prefix + updated.encode('ascii', errors='replace')

    @staticmethod
    def _merge_replacement_name_with_raw_string(original_bytes, replacement_name, preserve_pipe_suffix=False):
        prefix_len = 0
        while prefix_len < len(original_bytes) and original_bytes[prefix_len] < 32:
            prefix_len += 1
        prefix = original_bytes[:prefix_len]
        original_text = original_bytes[prefix_len:].decode('ascii', errors='replace')
        replacement_text = replacement_name

        if preserve_pipe_suffix and '|' in original_text:
            _original_left, original_right = original_text.split('|', 1)
            if '|' in replacement_text:
                replacement_left, _replacement_right = replacement_text.split('|', 1)
            elif '_' in replacement_text:
                replacement_left, _replacement_right = replacement_text.rsplit('_', 1)
            else:
                replacement_left = replacement_text
            replacement_text = f"{replacement_left}|{original_right}"
        elif '|' in original_text and '|' not in replacement_text:
            pipe_count = original_text.count('|')
            if pipe_count == 1 and '_' in replacement_text:
                left, right = replacement_text.rsplit('_', 1)
                replacement_text = f"{left}|{right}"

        return prefix + replacement_text.encode('ascii', errors='replace')

    def _patch_fixed_strings_with_rename_rules(self, data, rename_rules):
        """Apply rename rules inside fixed-size ASCII strings without changing data size."""
        if not rename_rules:
            return data, 0, []
        patched = bytearray(data)
        changes = 0
        warnings = []
        for find_text, replace_text, ignore_case in rename_rules:
            if not find_text:
                continue
            flags = re.IGNORECASE if ignore_case else 0
            pattern = re.compile(re.escape(find_text).encode('ascii', errors='replace'), flags)
            pos = 0
            while True:
                match = pattern.search(bytes(patched), pos)
                if not match:
                    break
                start, end = match.span()
                field_start = start
                while field_start > 0 and 32 <= patched[field_start - 1] <= 126:
                    field_start -= 1
                field_end = end
                while field_end < len(patched) and patched[field_end] != 0:
                    field_end += 1
                old_field = bytes(patched[field_start:field_end])
                try:
                    old_text = old_field.decode('ascii')
                except UnicodeDecodeError:
                    pos = end
                    continue
                new_text = self._apply_rename_rules_to_text(old_text, rename_rules)
                new_bytes = new_text.encode('ascii', errors='replace')
                if len(new_bytes) <= len(old_field):
                    patched[field_start:field_start + len(old_field)] = new_bytes + (b'\x00' * (len(old_field) - len(new_bytes)))
                    changes += 1
                    pos = field_start + len(old_field)
                else:
                    warnings.append(f"Skipped fixed string '{old_text}' -> '{new_text}' because it would grow.")
                    pos = end
        return bytes(patched), changes, warnings

    def _build_pipeworks_header_for_insertions(self, new_records, endian):
        """Build an expanded Pipeworks header/TOC/metadata/string prefix."""
        old_count = self.file_count
        new_count = old_count + len(new_records)
        toc_start = 0x78
        old_toc_end = toc_start + (old_count * 0x12)

        prefix = bytearray(self.file_data[:toc_start])
        original_toc = bytearray(self.file_data[toc_start:old_toc_end])
        original_gap = bytearray(self.file_data[old_toc_end:self.string_offset])
        original_metadata = bytearray(self.file_data[self.metadata_offset:self.metadata_offset + (old_count * 0x10)])

        string_count, offsets, first_string_offset, string_data = self._read_pipeworks_string_table()
        added_string_count = len(new_records)
        offset_shift = added_string_count * 4
        new_offsets = [offset + offset_shift for offset in offsets]

        appended_string_data = bytearray()
        for record in new_records:
            new_offsets.append(first_string_offset + offset_shift + len(string_data) + len(appended_string_data))
            appended_string_data.extend(record['filename'].encode('ascii', errors='replace') + b'\x00')

        new_string_table = bytearray()
        new_string_table.extend(struct.pack('<I', string_count + added_string_count))
        for offset in new_offsets:
            new_string_table.extend(struct.pack('<I', offset))
        new_string_table.extend(string_data)
        new_string_table.extend(appended_string_data)

        new_toc = bytearray(original_toc)
        for idx, record in enumerate(new_records):
            file_num = old_count + idx
            new_toc.extend(struct.pack(f'{endian}H', file_num))
            new_toc.extend(b'\x00' * 16)
            record['file_num'] = file_num
            record['string_id'] = string_count + idx

        new_metadata = bytearray(original_metadata)
        for record in new_records:
            file_num = record['file_num']
            string_id = record['string_id']
            file_type = record['file_type']

            template = None
            for i in range(old_count):
                entry = original_metadata[i * 0x10:(i + 1) * 0x10]
                if len(entry) == 0x10 and entry[2] == file_type:
                    template = bytearray(entry)
                    break
            if template is None:
                template = bytearray(0x10)
                template[8:12] = b'\x00\x01\x00\x00'

            struct.pack_into(f'{endian}H', template, 0, file_num)
            template[2] = file_type
            struct.pack_into(f'{endian}I', template, 4, string_id)
            new_metadata.extend(template)

        header_gap_offsets = []
        for offset_pos in range(0x3C, 0x60, 4):
            value = self.read_long(offset_pos)
            if old_toc_end <= value < self.string_offset:
                header_gap_offsets.append((offset_pos, value))

        first_gap_table = min((value for _, value in header_gap_offsets), default=self.string_offset)
        initial_gap_padding = max(0, first_gap_table - old_toc_end)
        added_toc_size = len(new_records) * 0x12
        table_shift = added_toc_size
        if table_shift % 16:
            table_shift += 16 - (table_shift % 16)

        moved_table_start = first_gap_table + table_shift
        padding_after_toc = max(0, moved_table_start - (old_toc_end + added_toc_size))
        gap_after_toc = bytearray(b'\xFF' * padding_after_toc)
        gap_after_toc.extend(self.file_data[first_gap_table:self.string_offset])

        new_string_offset = self.string_offset + table_shift

        new_metadata_offset = new_string_offset + len(new_string_table)
        pre_metadata_padding = (16 - (new_metadata_offset % 16)) % 16
        new_metadata_offset += pre_metadata_padding

        new_main_data_offset = new_metadata_offset + len(new_metadata)
        metadata_padding = (16 - (new_main_data_offset % 16)) % 16
        new_main_data_offset += metadata_padding

        header_and_toc = bytearray()
        header_and_toc.extend(prefix)
        header_and_toc.extend(new_toc)
        header_and_toc.extend(gap_after_toc)
        header_and_toc.extend(new_string_table)
        if pre_metadata_padding:
            header_and_toc.extend(b'\x00' * pre_metadata_padding)
        header_and_toc.extend(new_metadata)
        if metadata_padding:
            header_and_toc.extend(b'\x00' * metadata_padding)

        struct.pack_into(f'{endian}I', header_and_toc, 0x34, new_string_offset)
        for offset_pos, value in header_gap_offsets:
            struct.pack_into(f'{endian}I', header_and_toc, offset_pos, value + table_shift)
        struct.pack_into(f'{endian}H', header_and_toc, 0x62, new_count)
        struct.pack_into(f'{endian}I', header_and_toc, 0x64, new_metadata_offset)
        struct.pack_into(f'{endian}I', header_and_toc, 0x68, new_main_data_offset)

        return header_and_toc, new_count, new_main_data_offset

    def _build_pipeworks_header_for_entry_edits(self, final_entries, endian, preserve_metadata_count=False, rename_rules=None):
        """Build a Pipeworks header/TOC/metadata/string prefix for an edited entry list."""
        new_count = self.file_count if preserve_metadata_count else len(final_entries)
        toc_start = 0x78
        old_toc_end = toc_start + (self.file_count * 0x12)
        new_toc_end = toc_start + (new_count * 0x12)

        prefix = bytearray(self.file_data[:toc_start])
        string_count, offsets, _first_string_offset, _string_data = self._read_pipeworks_string_table()

        appended_entries = [entry for entry in final_entries if entry.get('append_string')]
        replacement_strings = {
            entry['string_id']: entry['filename']
            for entry in final_entries
            if entry.get('replace_string')
        }
        string_id_types = {}
        for entry in final_entries:
            string_id_types.setdefault(entry['string_id'], set()).add(entry.get('file_type'))
        original_strings = []
        original_string_bytes = []
        for idx, offset in enumerate(offsets):
            string_pos = self.string_offset + offset
            string_end = string_pos
            while string_end < len(self.file_data) and self.file_data[string_end] != 0:
                string_end += 1
            original_bytes = bytes(self.file_data[string_pos:string_end])
            original_string_bytes.append(original_bytes)
            if idx in replacement_strings:
                preserve_pipe_suffix = self.bundle_type == 'pipeworks' and 17 in string_id_types.get(idx, set())
                if rename_rules:
                    original_strings.append(self._apply_rename_rules_to_string_bytes(original_bytes, rename_rules, preserve_pipe_suffix))
                else:
                    original_strings.append(self._merge_replacement_name_with_raw_string(original_bytes, replacement_strings[idx], preserve_pipe_suffix))
            else:
                original_strings.append(original_bytes)

        for idx, entry in enumerate(appended_entries):
            entry['string_id'] = string_count + idx
            original_strings.append(entry['filename'].encode('ascii', errors='replace'))

        extra_string_values = []
        for value in getattr(self, '_extra_string_values', []) or []:
            if value is None:
                continue
            raw_value = str(value).encode('ascii', errors='replace')
            if raw_value and raw_value not in original_strings and raw_value not in extra_string_values:
                extra_string_values.append(raw_value)
        original_strings.extend(extra_string_values)

        new_string_table = bytearray()
        new_string_table.extend(struct.pack('<I', len(original_strings)))
        offset_table_size = 4 + (4 * len(original_strings))
        string_payload = bytearray()
        for value in original_strings:
            new_string_table.extend(struct.pack('<I', offset_table_size + len(string_payload)))
            string_payload.extend(value + b'\x00')
        new_string_table.extend(string_payload)

        preserve_original_layout = (
            preserve_metadata_count and
            not appended_entries and
            new_count == self.file_count and
            len(final_entries) == self.file_count
        )

        if preserve_original_layout:
            new_toc = bytearray(self.file_data[toc_start:old_toc_end])
        else:
            new_toc = bytearray()
        new_metadata = bytearray()
        for idx, entry in enumerate(final_entries):
            file_num = entry.get('file_num', idx)
            entry['file_num'] = file_num
            if preserve_original_layout:
                original_row_offset = toc_start + (idx * 0x12)
                original_file_num = struct.unpack_from(f'{endian}H', self.file_data, original_row_offset)[0]
                if original_file_num != file_num:
                    preserve_original_layout = False
                    new_toc = bytearray()
                    for fallback_entry in final_entries[:idx]:
                        fallback_file_num = fallback_entry.get('file_num', len(new_toc) // 0x12)
                        new_toc.extend(struct.pack(f'{endian}H', fallback_file_num))
                        new_toc.extend(b'\x00' * 16)
                    new_toc.extend(struct.pack(f'{endian}H', file_num))
                    new_toc.extend(b'\x00' * 16)
            else:
                new_toc.extend(struct.pack(f'{endian}H', file_num))
                new_toc.extend(b'\x00' * 16)

            template = bytearray(entry.get('metadata_bytes') or b'\x00' * 0x10)
            if len(template) < 0x10:
                template.extend(b'\x00' * (0x10 - len(template)))
            template = template[:0x10]
            struct.pack_into(f'{endian}H', template, 0, file_num)
            template[2] = entry['file_type']
            struct.pack_into(f'{endian}I', template, 4, entry['string_id'])
            new_metadata.extend(template)

        header_gap_offsets = []
        for offset_pos in range(0x3C, 0x60, 4):
            value = self.read_long(offset_pos)
            if old_toc_end <= value < self.string_offset:
                header_gap_offsets.append((offset_pos, value))

        first_gap_table = min((value for _, value in header_gap_offsets), default=self.string_offset)
        table_shift = 0
        if new_toc_end > first_gap_table:
            table_shift = new_toc_end - first_gap_table
            if table_shift % 16:
                table_shift += 16 - (table_shift % 16)

        moved_table_start = first_gap_table + table_shift
        padding_after_toc = max(0, moved_table_start - new_toc_end)
        gap_after_toc = bytearray(b'\xFF' * padding_after_toc)
        gap_after_toc.extend(self.file_data[first_gap_table:self.string_offset])

        new_string_offset = self.string_offset + table_shift

        if preserve_original_layout and table_shift == 0:
            string_capacity = self.metadata_offset - self.string_offset
            metadata_capacity = self.main_data_offset - self.metadata_offset
            fixed_string_table = bytearray(self.file_data[self.string_offset:self.metadata_offset])
            can_preserve_string_offsets = True
            for idx, new_bytes in enumerate(original_strings[:len(offsets)]):
                old_bytes = original_string_bytes[idx]
                if len(new_bytes) > len(old_bytes):
                    can_preserve_string_offsets = False
                    break
                rel_pos = offsets[idx]
                fixed_string_table[rel_pos:rel_pos + len(old_bytes)] = new_bytes + (b'\x00' * (len(old_bytes) - len(new_bytes)))

            if not extra_string_values and can_preserve_string_offsets and len(new_metadata) <= metadata_capacity:
                header_and_toc = bytearray()
                header_and_toc.extend(prefix)
                header_and_toc.extend(new_toc)
                header_and_toc.extend(self.file_data[old_toc_end:self.string_offset])
                header_and_toc.extend(fixed_string_table)
                header_and_toc.extend(new_metadata)
                header_and_toc.extend(b'\x00' * (metadata_capacity - len(new_metadata)))

                struct.pack_into(f'{endian}I', header_and_toc, 0x34, self.string_offset)
                struct.pack_into(f'{endian}H', header_and_toc, 0x62, new_count)
                struct.pack_into(f'{endian}I', header_and_toc, 0x64, self.metadata_offset)
                struct.pack_into(f'{endian}I', header_and_toc, 0x68, self.main_data_offset)
                return header_and_toc, new_count, self.main_data_offset

            if len(new_string_table) <= string_capacity and len(new_metadata) <= metadata_capacity:
                header_and_toc = bytearray()
                header_and_toc.extend(prefix)
                header_and_toc.extend(new_toc)
                header_and_toc.extend(self.file_data[old_toc_end:self.string_offset])
                header_and_toc.extend(new_string_table)
                header_and_toc.extend(b'\x00' * (string_capacity - len(new_string_table)))
                header_and_toc.extend(new_metadata)
                header_and_toc.extend(b'\x00' * (metadata_capacity - len(new_metadata)))

                struct.pack_into(f'{endian}I', header_and_toc, 0x34, self.string_offset)
                struct.pack_into(f'{endian}H', header_and_toc, 0x62, new_count)
                struct.pack_into(f'{endian}I', header_and_toc, 0x64, self.metadata_offset)
                struct.pack_into(f'{endian}I', header_and_toc, 0x68, self.main_data_offset)
                return header_and_toc, new_count, self.main_data_offset

        new_metadata_offset = new_string_offset + len(new_string_table)
        pre_metadata_padding = (16 - (new_metadata_offset % 16)) % 16
        new_metadata_offset += pre_metadata_padding

        new_main_data_offset = new_metadata_offset + len(new_metadata)
        metadata_padding = (16 - (new_main_data_offset % 16)) % 16
        new_main_data_offset += metadata_padding

        header_and_toc = bytearray()
        header_and_toc.extend(prefix)
        header_and_toc.extend(new_toc)
        header_and_toc.extend(gap_after_toc)
        header_and_toc.extend(new_string_table)
        if pre_metadata_padding:
            header_and_toc.extend(b'\x00' * pre_metadata_padding)
        header_and_toc.extend(new_metadata)
        if metadata_padding:
            header_and_toc.extend(b'\x00' * metadata_padding)

        struct.pack_into(f'{endian}I', header_and_toc, 0x34, new_string_offset)
        for offset_pos, value in header_gap_offsets:
            struct.pack_into(f'{endian}I', header_and_toc, offset_pos, value + table_shift)
        struct.pack_into(f'{endian}H', header_and_toc, 0x62, new_count)
        struct.pack_into(f'{endian}I', header_and_toc, 0x64, new_metadata_offset)
        struct.pack_into(f'{endian}I', header_and_toc, 0x68, new_main_data_offset)

        return header_and_toc, new_count, new_main_data_offset

    def get_file_info(self, file_num):
        """Extract file name and type from metadata and string table"""
        try:
            # Get metadata entry offset (16 bytes per entry)
            metadata_start = self.metadata_offset + (file_num * 0x10)
            entry_offset = metadata_start + 0x2

            # Get file type (1 byte)
            file_type = self.read_byte(entry_offset)

            # Skip 1 byte, then get string ID (4 bytes)
            str_id = self.read_long(entry_offset + 2)

            # Get string from string table
            str_entry = (str_id * 0x4) + 0x4
            str_offset_pos = self.string_offset + str_entry

            # String table is always little-endian
            str_offset = self.read_long_little(str_offset_pos)

            # Calculate final string position
            string_pos = self.string_offset + str_offset

            # Read the string
            name = self.read_string(string_pos)
            if not name:
                name = f"file_{file_num}"

            # Create folder structure based on file type (use decimal, not hex)
            folder_name = str(file_type)
            # Remove pipe character from filename as it causes extraction issues
            clean_name = name.replace('|', '_')
            if file_type == 20 and not clean_name.lower().endswith('.edf'):
                clean_name = f"{clean_name}.edf"
            full_name = f"{folder_name}/{clean_name}"

            # Read full metadata entry (16 bytes) for preservation
            metadata_bytes = self.read_bytes(metadata_start, 0x10)

            return full_name, file_type, metadata_bytes, str_id
        except Exception as e:
            return f"file_{file_num}", 0, None, file_num

    def parse(self):
        """Parse bundle file (Pipeworks or VOL format)"""
        results = []

        try:
            # Read entire file
            with open(self.filepath, 'rb') as f:
                self.file_data = f.read()

            # Check header to determine bundle type
            header = self.file_data[0:4].decode('ascii', errors='ignore')

            if header == "PVOL":
                self.bundle_type = 'vol'
                return self.parse_vol()
            elif self.file_data[0:9].decode('ascii', errors='ignore') == "Pipeworks":
                self.bundle_type = 'pipeworks'
                return self.parse_pipeworks()
            else:
                return [{"error": "Not a valid bundle file (expected 'Pipeworks' or 'PVOL' header)"}]

        except Exception as e:
            return [{"error": f"Error parsing file: {str(e)}"}]

    def parse_from_data(self, data):
        """Parse bundle file from raw bytes (used for ZIP extraction)"""
        try:
            self.file_data = data

            header = self.file_data[0:4].decode('ascii', errors='ignore')

            if header == "PVOL":
                self.bundle_type = 'vol'
                return self.parse_vol()
            elif self.file_data[0:9].decode('ascii', errors='ignore') == "Pipeworks":
                self.bundle_type = 'pipeworks'
                return self.parse_pipeworks()
            else:
                return [{"error": "Not a valid bundle file (expected 'Pipeworks' or 'PVOL' header)"}]

        except Exception as e:
            return [{"error": f"Error parsing file: {str(e)}"}]

    def parse_pipeworks(self):
        """Parse Pipeworks bundle file (BDG/CMG)"""
        results = []

        try:

            # Detect endianness at 0x2C (default little-endian)
            endian_check = struct.unpack('<H', self.file_data[0x2C:0x2E])[0]
            if endian_check == 0:
                self.is_big_endian = True
            # DAMM Xbox BDLs use a zero marker despite retaining a little-endian TOC.
            if os.path.splitext(self.filepath.lower())[1] == '.bdl':
                self.is_big_endian = False

            # Read header values with proper endianness
            self.string_offset = self.read_long(0x34)
            self.file_count = self.read_short(0x62)
            self.metadata_offset = self.read_long(0x64)
            self.main_data_offset = self.read_long(0x68)
            self.resource_data_offset = self.read_long(0x70)

            # Start parsing TOC at 0x78
            toc_offset = 0x78

            for i in range(self.file_count):
                entry_offset = toc_offset + (i * 0x12)

                # Read file entry
                file_num = self.read_short(entry_offset)
                offset = self.read_long(entry_offset + 2)
                size = self.read_long(entry_offset + 6)
                res_offset = self.read_long(entry_offset + 10)
                res_size = self.read_long(entry_offset + 14)

                # Adjust offset
                actual_offset = offset + self.main_data_offset

                # Get file name and type from metadata
                name, file_type, metadata_bytes, string_id = self.get_file_info(file_num)

                results.append({
                    "file_num": file_num,
                    "name": name,
                    "offset": actual_offset,
                    "size": size,
                    "raw_offset": offset,
                    "toc_entry_offset": entry_offset,
                    "is_resource": False,
                    "file_type": file_type,
                    "metadata_bytes": metadata_bytes,
                    "string_id": string_id
                })

                # Add resource entry if it exists
                if res_size > 0:
                    actual_res_offset = res_offset + self.resource_data_offset
                    results.append({
                        "file_num": file_num,
                        "name": f"{name}.resource",
                        "offset": actual_res_offset,
                        "size": res_size,
                        "raw_offset": res_offset,
                        "toc_entry_offset": entry_offset,
                        "is_resource": True,
                        "file_type": file_type,
                        "metadata_bytes": metadata_bytes,
                        "string_id": string_id
                    })

            return results

        except Exception as e:
            return [{"error": f"Error parsing file: {str(e)}"}]

    def parse_vol(self):
        """Parse VOL bundle file (PS2 format) - based on VOL_Extract.BMS"""
        results = []

        try:
            # VOL files are always little-endian (PS2)
            self.is_big_endian = False

            # Read 16-byte header (matching BMS script exactly)
            # 0x00-03: Magic "PVOL"
            # 0x04-07: UNK
            # 0x08-0B: FILES count
            # 0x0C-0F: DATASTART (in BMS, but value meaning unclear)
            unk = struct.unpack('<I', self.file_data[4:8])[0]
            self.file_count = struct.unpack('<I', self.file_data[8:12])[0]
            datastart_field = struct.unpack('<I', self.file_data[12:16])[0]

            # Calculate string table offset (matching BMS exactly)
            # BMS formula: NAMEOFF = (0xC * FILES) + (4 * FILES) + 20
            # This accounts for: 16-byte header + TOC (12 bytes per file) + extra data (4 bytes per file) + 4 bytes
            self.string_offset = (12 * self.file_count) + (4 * self.file_count) + 20

            print(f"\n=== VOL Header ===")
            print(f"File count: {self.file_count}")
            print(f"DATASTART field: 0x{datastart_field:08X} ({datastart_field})")
            print(f"String table offset (calculated): 0x{self.string_offset:08X} ({self.string_offset})")

            # Start parsing TOC at offset 16 (after 16-byte header)
            toc_offset = 16

            # Read TOC entries (matching BMS exactly: OFFSET, SIZE, FID)
            toc_entries = []
            for i in range(self.file_count):
                entry_offset = toc_offset + (i * 0xC)

                file_offset = struct.unpack('<I', self.file_data[entry_offset:entry_offset + 4])[0]
                size = struct.unpack('<I', self.file_data[entry_offset + 4:entry_offset + 8])[0]
                file_id = struct.unpack('<I', self.file_data[entry_offset + 8:entry_offset + 12])[0]

                toc_entries.append({
                    'offset': file_offset,
                    'size': size,
                    'file_id': file_id,
                    'toc_entry_offset': entry_offset,
                    'raw_offset': file_offset
                })

            # Read file names from string table
            name_offset = self.string_offset
            for i, entry in enumerate(toc_entries):
                # Read null-terminated string
                name_end = name_offset
                while name_end < len(self.file_data) and self.file_data[name_end] != 0:
                    name_end += 1

                raw_name = self.file_data[name_offset:name_end].decode('ascii', errors='ignore')

                # Detect file type from extension
                file_type = self.detect_file_type_from_extension(raw_name)

                # Create folder-based structure for VOL files
                # Extract folder path and filename from the original name
                if '/' in raw_name or '\\' in raw_name:
                    # Already has folder structure
                    folder_name = raw_name.replace('\\', '/')
                else:
                    # Group by extension for flat files
                    ext = raw_name.split('.')[-1].upper() if '.' in raw_name else 'MISC'
                    folder_name = f"{ext}/{raw_name}"

                results.append({
                    "file_num": i,
                    "name": folder_name,
                    "offset": entry['offset'],  # Absolute offset for extraction
                    "size": entry['size'],
                    "raw_offset": entry['raw_offset'],  # Relative offset for rebuild
                    "toc_entry_offset": entry['toc_entry_offset'],
                    "is_resource": False,
                    "file_type": file_type,
                    "metadata_bytes": None,
                    "file_id": entry['file_id']
                })

                # Move to next string (skip null terminator)
                name_offset = name_end + 1

            return results

        except Exception as e:
            return [{"error": f"Error parsing VOL file: {str(e)}"}]

    def extract_file(self, file_entry, output_dir):
        """Extract a single file from the bundle"""
        try:
            output_path = os.path.join(output_dir, file_entry['name'])

            # Create folder if it doesn't exist
            folder_path = os.path.dirname(output_path)
            if folder_path and not os.path.exists(folder_path):
                os.makedirs(folder_path)

            offset = file_entry['offset']
            size = file_entry['size']

            file_data = self.read_bytes(offset, size)

            with open(output_path, 'wb') as f:
                f.write(file_data)

            if file_entry.get('is_resource') and file_entry.get('file_type') == 9:
                self._extract_texture_png(file_entry, file_data, output_path)

            return True
        except Exception as e:
            print(f"Error extracting {file_entry['name']}: {e}")
            return False

    def detect_alignment(self, files):
        """Detect alignment by checking gaps between consecutive files"""
        alignments = []
        for i in range(len(files) - 1):
            current = files[i]
            next_file = files[i + 1]

            # Calculate where next file starts vs where current ends
            current_end = current['raw_offset'] + current['size']
            gap = next_file['raw_offset'] - current_end

            if gap > 0:
                # Check common alignments: 16, 32, 64, 128, 2048
                for align in [16, 32, 64, 128, 256, 512, 2048]:
                    if next_file['raw_offset'] % align == 0:
                        alignments.append(align)
                        break

        # Return most common alignment, or 16 as default
        if alignments:
            return max(set(alignments), key=alignments.count)
        return 16

    def detect_alignments_by_type(self, files):
        """Detect likely alignment per file type from padding before each file."""
        common_alignments = [16, 32, 64, 128, 256, 512, 1024, 2048]
        by_type = {}
        sorted_files = sorted(
            [entry for entry in (files or []) if entry.get('size', 0) > 0 and entry.get('raw_offset') is not None],
            key=lambda entry: entry['raw_offset']
        )
        for index in range(len(sorted_files) - 1):
            current = sorted_files[index]
            next_file = sorted_files[index + 1]
            current_end = current['raw_offset'] + current['size']
            next_offset = next_file['raw_offset']
            gap = next_offset - current_end
            if gap <= 0:
                continue
            file_type = next_file.get('file_type')
            if file_type is None:
                continue
            for alignment in common_alignments:
                aligned_end = ((current_end + alignment - 1) // alignment) * alignment
                if aligned_end == next_offset:
                    by_type.setdefault(file_type, []).append(alignment)
                    break

        detected = {}
        for file_type, candidates in by_type.items():
            if candidates:
                detected[file_type] = max(set(candidates), key=lambda item: (candidates.count(item), item))
        return detected

    def read_replacement_file(self, filepath):
        """Read replacement file, handling both binary and hex-encoded text files"""
        with open(filepath, 'rb') as f:
            data = f.read()

        # Check if this is a hex-encoded text file
        # Hex files typically contain only hex chars (0-9, A-F, a-f) and whitespace
        try:
            text_data = data.decode('ascii').strip()
            # Remove all whitespace
            hex_string = ''.join(text_data.split())

            # Check if it's all hex characters
            if all(c in '0123456789ABCDEFabcdef' for c in hex_string):
                # This is a hex-encoded file, convert it to bytes
                print(f"    Detected hex-encoded text file, converting to binary")
                print(f"    Hex string length: {len(hex_string)} chars -> {len(hex_string)//2} bytes")
                return bytes.fromhex(hex_string)
        except (UnicodeDecodeError, ValueError):
            pass

        # Return as-is if not hex-encoded
        return data

    def write_pipeworks_manifest(self, output_dir, entries):
        """Write enough Pipeworks metadata to rebuild this extracted folder later."""
        if self.bundle_type != 'pipeworks':
            return

        main_entries = [e for e in entries if not e.get('is_resource')]
        string_count, offsets, first_string_offset, string_data = self._read_pipeworks_string_table()
        toc_end = 0x78 + (self.file_count * 0x12)

        manifest = {
            "format": "GZBuildr Pipeworks Extract Manifest",
            "version": 1,
            "source_bundle": os.path.basename(self.filepath),
            "endianness": "big" if self.is_big_endian else "little",
            "file_count": self.file_count,
            "header_prefix_b64": base64.b64encode(self.file_data[:0x78]).decode('ascii'),
            "toc_gap_b64": base64.b64encode(self.file_data[toc_end:self.string_offset]).decode('ascii'),
            "string_count": string_count,
            "string_offsets": offsets,
            "first_string_offset": first_string_offset,
            "string_data_b64": base64.b64encode(bytes(string_data)).decode('ascii'),
            "metadata_b64": base64.b64encode(self.file_data[self.metadata_offset:self.metadata_offset + (self.file_count * 0x10)]).decode('ascii'),
            "main_data_b64": base64.b64encode(self.file_data[self.main_data_offset:self.resource_data_offset]).decode('ascii'),
            "original_offsets": {
                "string_offset": self.string_offset,
                "metadata_offset": self.metadata_offset,
                "main_data_offset": self.main_data_offset,
                "main_data_end_raw": self.read_long(0x6C),
                "resource_data_offset": self.resource_data_offset,
            },
            "entries": []
        }

        for entry in sorted(main_entries, key=lambda e: e['file_num']):
            manifest["entries"].append({
                "file_num": entry['file_num'],
                "name": entry['name'],
                "file_type": entry['file_type'],
                "size": entry['size'],
                "raw_offset": entry['raw_offset'],
                "metadata_b64": base64.b64encode(entry.get('metadata_bytes') or b'').decode('ascii'),
            })

        metadata_dir = os.path.join(output_dir, ".gzbuildr")
        os.makedirs(metadata_dir, exist_ok=True)
        if sys.platform == "win32":
            try:
                current_attrs = ctypes.windll.kernel32.GetFileAttributesW(metadata_dir)
                if current_attrs != 0xFFFFFFFF:
                    ctypes.windll.kernel32.SetFileAttributesW(metadata_dir, current_attrs | 0x02)
            except Exception:
                pass
        bundle_name = safe_path_name(Path(self.filepath).stem)
        manifest_path = os.path.join(metadata_dir, f"GZBuildr_{bundle_name}_Log.json")
        with open(manifest_path, 'w', encoding='utf-8') as f:
            json.dump(manifest, f, indent=2)

    def build_pipeworks_from_directory(self, source_dir, output_path, custom_alignments=None):
        """Build a Pipeworks bundle from an extracted folder, using manifest metadata when available."""
        metadata_dir = os.path.join(source_dir, ".gzbuildr")
        named_logs = sorted(Path(metadata_dir).glob("GZBuildr_*_Log.json")) if os.path.isdir(metadata_dir) else []
        manifest_candidates = [
            *(str(path) for path in named_logs),
            os.path.join(metadata_dir, "pipeworks_manifest.json"),
            os.path.join(source_dir, "_gzbuildr_pipeworks_manifest.json"),
        ]
        for manifest_path in manifest_candidates:
            if os.path.exists(manifest_path):
                return self._build_pipeworks_from_manifest(source_dir, output_path, manifest_path, custom_alignments)
        return self._build_pipeworks_from_numeric_folders(source_dir, output_path, custom_alignments)

    def _build_pipeworks_from_manifest(self, source_dir, output_path, manifest_path, custom_alignments=None):
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)

        endian = '>' if manifest.get("endianness") == "big" else '<'
        self.is_big_endian = endian == '>'
        self.filepath = output_path
        self.custom_alignments = custom_alignments or {}

        entries = []
        for item in manifest.get("entries", []):
            rel_name = item["name"]
            file_path = os.path.join(source_dir, *rel_name.replace('\\', '/').split('/'))
            if not os.path.isfile(file_path):
                print(f"Error: Missing extracted file for manifest entry: {rel_name}")
                return False
            entries.append({
                "file_num": item["file_num"],
                "name": rel_name,
                "file_type": item["file_type"],
                "source_path": file_path,
                "original_size": item.get("size"),
                "original_raw_offset": item.get("raw_offset"),
                "metadata": base64.b64decode(item.get("metadata_b64") or ""),
            })

        entries.sort(key=lambda e: e["file_num"])
        if not entries:
            print("Error: Manifest contains no entries")
            return False

        prefix = bytearray(base64.b64decode(manifest["header_prefix_b64"]))
        gap_after_toc = bytearray(base64.b64decode(manifest["toc_gap_b64"]))
        metadata = bytearray(base64.b64decode(manifest["metadata_b64"]))
        string_count = manifest["string_count"]
        string_offsets = manifest["string_offsets"]
        first_string_offset = manifest["first_string_offset"]
        string_data = bytearray(base64.b64decode(manifest["string_data_b64"]))

        file_count = len(entries)
        toc = bytearray()
        file_data = bytearray()
        raw_offsets = {}
        sizes = {}
        detected_alignment = 16
        self.detected_main_alignments_by_type = self.detect_alignments_by_type([
            {
                "file_type": entry["file_type"],
                "raw_offset": entry.get("original_raw_offset"),
                "size": entry.get("original_size") or 1,
            }
            for entry in entries
        ])
        self.detected_resource_alignments_by_type = {}
        original_offsets = manifest.get("original_offsets", {})
        preserve_original_layout = all(
            entry.get("original_size") == os.path.getsize(entry["source_path"])
            and entry.get("original_raw_offset") is not None
            for entry in entries
        )

        if preserve_original_layout:
            original_main_size = original_offsets.get("resource_data_offset", 0) - original_offsets.get("main_data_offset", 0)
            if original_main_size <= 0:
                print("Error: Manifest has invalid original main/resource offsets")
                return False
            if manifest.get("main_data_b64"):
                file_data = bytearray(base64.b64decode(manifest["main_data_b64"]))
                if len(file_data) != original_main_size:
                    print("Warning: Manifest main data block size mismatch; falling back to zero-filled padding")
                    file_data = bytearray(b'\x00' * original_main_size)
            else:
                file_data = bytearray(b'\x00' * original_main_size)
            for entry in entries:
                data = self.read_replacement_file(entry["source_path"])
                raw_offset = entry["original_raw_offset"]
                raw_offsets[entry["file_num"]] = raw_offset
                sizes[entry["file_num"]] = len(data)
                file_data[raw_offset:raw_offset + len(data)] = data
        else:
            for entry in entries:
                data = self.read_replacement_file(entry["source_path"])
                alignment = self.get_alignment_for_type(entry["file_type"], detected_alignment, is_resource=False)
                if file_data:
                    padding = (alignment - (len(file_data) % alignment)) % alignment
                    if padding:
                        file_data.extend(b'\x00' * padding)
                raw_offsets[entry["file_num"]] = len(file_data)
                sizes[entry["file_num"]] = len(data)
                file_data.extend(data)

        for entry in entries:
            file_num = entry["file_num"]
            toc.extend(struct.pack(f'{endian}H', file_num))
            toc.extend(struct.pack(f'{endian}I', raw_offsets[file_num]))
            toc.extend(struct.pack(f'{endian}I', sizes[file_num]))
            toc.extend(struct.pack(f'{endian}I', 0))
            toc.extend(struct.pack(f'{endian}I', 0))

        string_table = bytearray()
        string_table.extend(struct.pack('<I', string_count))
        for offset in string_offsets:
            string_table.extend(struct.pack('<I', offset))
        string_table.extend(string_data)

        header = bytearray()
        header.extend(prefix)
        header.extend(toc)
        header.extend(gap_after_toc)
        string_offset = len(header)
        header.extend(string_table)
        metadata_offset = len(header)
        header.extend(metadata)
        main_data_offset = len(header)
        metadata_padding = (16 - (main_data_offset % 16)) % 16
        if metadata_padding:
            header.extend(b'\x00' * metadata_padding)
            main_data_offset += metadata_padding

        if preserve_original_layout:
            unpadded_main_size = original_offsets.get("main_data_end_raw", len(file_data))
            resource_offset = original_offsets.get("resource_data_offset", main_data_offset + len(file_data))
        else:
            unpadded_main_size = len(file_data)
            main_block_padding = (2048 - (len(file_data) % 2048)) % 2048
            if main_block_padding:
                file_data.extend(b'\x00' * main_block_padding)
            resource_offset = main_data_offset + len(file_data)

        struct.pack_into(f'{endian}I', header, 0x34, string_offset)
        struct.pack_into(f'{endian}H', header, 0x62, file_count)
        struct.pack_into(f'{endian}I', header, 0x64, metadata_offset)
        struct.pack_into(f'{endian}I', header, 0x68, main_data_offset)
        struct.pack_into(f'{endian}I', header, 0x6C, unpadded_main_size)
        struct.pack_into(f'{endian}I', header, 0x70, resource_offset)

        old_resource_offset = manifest.get("original_offsets", {}).get("resource_data_offset")
        if old_resource_offset is not None:
            old_bytes = struct.pack(f'{endian}I', old_resource_offset)
            new_bytes = struct.pack(f'{endian}I', resource_offset)
            for pos in range(0, max(0, string_offset - 3)):
                if pos == 0x70:
                    continue
                if header[pos:pos + 4] == old_bytes:
                    header[pos:pos + 4] = new_bytes

        with open(output_path, 'wb') as f:
            f.write(header)
            f.write(file_data)

        print(f"Pipeworks bundle built from manifest: {output_path}")
        print(f"  Files: {file_count}")
        print(f"  Header: 0x{len(header):X}, main data: 0x{len(file_data):X}, resource offset: 0x{resource_offset:X}")
        return True

    def _build_pipeworks_from_numeric_folders(self, source_dir, output_path, custom_alignments=None):
        if self.file_data is None:
            parsed = self.parse()
            if parsed and len(parsed) == 1 and 'error' in parsed[0]:
                print(parsed[0]['error'])
                return False

        if self.bundle_type != 'pipeworks':
            print("Error: Numeric-folder Pipeworks build requires a parsed Pipeworks template bundle.")
            return False

        self.custom_alignments = custom_alignments or {}
        self.detected_main_alignments_by_type = {}
        self.detected_resource_alignments_by_type = {}
        endian = '>' if self.is_big_endian else '<'

        source_files = []
        for root, dirs, files in os.walk(source_dir):
            dirs.sort()
            files.sort(key=str.lower)
            rel_root = os.path.relpath(root, source_dir)
            if rel_root == '.':
                continue
            parts = rel_root.replace('\\', '/').split('/')
            if not parts or not parts[0].isdigit():
                continue
            file_type = int(parts[0])
            if not 0 <= file_type <= 255:
                continue
            for filename in files:
                if filename == "_gzbuildr_pipeworks_manifest.json" or filename.endswith(".resource"):
                    continue
                path = os.path.join(root, filename)
                if os.path.isfile(path):
                    source_files.append({
                        "file_type": file_type,
                        "filename": filename.replace('|', '_'),
                        "source_path": path,
                    })

        source_files.sort(key=lambda item: (item["file_type"], item["filename"].lower()))
        if not source_files:
            print("Error: No files found in numeric type folders.")
            return False

        old_count = self.file_count
        toc_start = 0x78
        old_toc_end = toc_start + (old_count * 0x12)
        prefix = bytearray(self.file_data[:toc_start])

        header_gap_offsets = []
        for offset_pos in range(0x3C, 0x60, 4):
            value = self.read_long(offset_pos)
            if old_toc_end <= value < self.string_offset:
                header_gap_offsets.append((offset_pos, value))
        first_gap_table = min((value for _, value in header_gap_offsets), default=self.string_offset)
        initial_gap_padding = max(0, first_gap_table - old_toc_end)

        new_count = len(source_files)
        new_toc_end = toc_start + (new_count * 0x12)
        moved_table_start = max(first_gap_table, new_toc_end + initial_gap_padding)
        if moved_table_start % 16:
            moved_table_start += 16 - (moved_table_start % 16)
        table_shift = max(0, moved_table_start - first_gap_table)

        padding_after_toc = max(0, moved_table_start - new_toc_end)
        gap_after_toc = bytearray(b'\xFF' * padding_after_toc)
        gap_after_toc.extend(self.file_data[first_gap_table:self.string_offset])

        # Build a fresh string table containing only the new bundle's file names.
        string_count = new_count
        first_string_offset = 4 + (string_count * 4)
        string_offsets = []
        string_data = bytearray()
        for item in source_files:
            string_offsets.append(first_string_offset + len(string_data))
            string_data.extend(item["filename"].encode('ascii', errors='replace') + b'\x00')

        string_table = bytearray()
        string_table.extend(struct.pack('<I', string_count))
        for offset in string_offsets:
            string_table.extend(struct.pack('<I', offset))
        string_table.extend(string_data)

        original_metadata = bytearray(self.file_data[self.metadata_offset:self.metadata_offset + (old_count * 0x10)])
        metadata_templates = {}
        fallback_template = bytearray(0x10)
        fallback_template[8:12] = b'\x00\x01\x00\x00'
        for i in range(old_count):
            entry = bytearray(original_metadata[i * 0x10:(i + 1) * 0x10])
            if len(entry) == 0x10:
                metadata_templates.setdefault(entry[2], entry)
                fallback_template = entry

        toc = bytearray()
        metadata = bytearray()
        file_data = bytearray()
        detected_alignment = 16

        for file_num, item in enumerate(source_files):
            file_type = item["file_type"]
            data = self.read_replacement_file(item["source_path"])
            alignment = self.get_alignment_for_type(file_type, detected_alignment, is_resource=False)
            if file_data:
                padding = (alignment - (len(file_data) % alignment)) % alignment
                if padding:
                    file_data.extend(b'\x00' * padding)
            raw_offset = len(file_data)
            file_data.extend(data)

            toc.extend(struct.pack(f'{endian}H', file_num))
            toc.extend(struct.pack(f'{endian}I', raw_offset))
            toc.extend(struct.pack(f'{endian}I', len(data)))
            toc.extend(struct.pack(f'{endian}I', 0))
            toc.extend(struct.pack(f'{endian}I', 0))

            template = bytearray(metadata_templates.get(file_type, fallback_template))
            struct.pack_into(f'{endian}H', template, 0, file_num)
            template[2] = file_type
            struct.pack_into(f'{endian}I', template, 4, file_num)
            metadata.extend(template)

            print(f"  New file {file_num}: {file_type}/{item['filename']}, size {len(data)}, offset {raw_offset}, align {alignment}")

        header = bytearray()
        header.extend(prefix)
        header.extend(toc)
        header.extend(gap_after_toc)
        string_offset = len(header)
        header.extend(string_table)
        metadata_offset = len(header)
        header.extend(metadata)
        main_data_offset = len(header)
        metadata_padding = (16 - (main_data_offset % 16)) % 16
        if metadata_padding:
            header.extend(b'\x00' * metadata_padding)
            main_data_offset += metadata_padding

        unpadded_main_size = len(file_data)
        main_padding = (2048 - (len(file_data) % 2048)) % 2048
        if main_padding:
            file_data.extend(b'\x00' * main_padding)
        resource_offset = main_data_offset + len(file_data)

        struct.pack_into(f'{endian}I', header, 0x34, string_offset)
        for offset_pos, value in header_gap_offsets:
            struct.pack_into(f'{endian}I', header, offset_pos, value + table_shift)
        struct.pack_into(f'{endian}H', header, 0x62, new_count)
        struct.pack_into(f'{endian}I', header, 0x64, metadata_offset)
        struct.pack_into(f'{endian}I', header, 0x68, main_data_offset)
        struct.pack_into(f'{endian}I', header, 0x6C, unpadded_main_size)
        struct.pack_into(f'{endian}I', header, 0x70, resource_offset)

        old_resource_bytes = struct.pack(f'{endian}I', self.resource_data_offset)
        new_resource_bytes = struct.pack(f'{endian}I', resource_offset)
        for pos in range(0, max(0, string_offset - 3)):
            if pos == 0x70:
                continue
            if header[pos:pos + 4] == old_resource_bytes:
                header[pos:pos + 4] = new_resource_bytes

        with open(output_path, 'wb') as f:
            f.write(header)
            f.write(file_data)

        print(f"New Pipeworks bundle built from numeric folders: {output_path}")
        print(f"  Files: {new_count}")
        print(f"  Header: 0x{len(header):X}, main data: 0x{len(file_data):X}, resource offset: 0x{resource_offset:X}")
        return True

    def find_replacement_file(self, replacement_dir, original_name):
        """
        Find replacement file with case-insensitive filename match.

        NOTE: CMG files are bundle containers (same as BDG), not mesh files.
        They should not be replaced with .mesh files or vice versa.
        Returns (filepath, actual_name) if found, or (None, None) if not found.
        """
        if not replacement_dir or not os.path.isdir(replacement_dir):
            return None, None

        # First try exact match
        original_path = os.path.join(replacement_dir, original_name)
        if os.path.exists(original_path):
            return original_path, original_name

        # Try case-insensitive match
        original_lower = original_name.lower()
        for filename in os.listdir(replacement_dir):
            if filename.lower() == original_lower:
                filepath = os.path.join(replacement_dir, filename)
                if os.path.isfile(filepath):
                    return filepath, filename

        return None, None

    def validate_texture_replacement(self, original_data, replacement_data, filename):
        """Validate texture replacement for common issues"""
        issues = []
        warnings = []

        # Check for common texture formats
        original_size = len(original_data)
        replacement_size = len(replacement_data)

        # Check if file has a known texture header
        if len(replacement_data) >= 4:
            header = replacement_data[0:4]
            # Check for DDS header (common texture format)
            if header == b'DDS ':
                warnings.append("DDS texture detected - ensure mipmaps are included")

        # Check for size mismatch
        if replacement_size != original_size:
            # Calculate size difference percentage
            size_diff_pct = abs(replacement_size - original_size) / original_size * 100

            if size_diff_pct > 50:
                issues.append(f"Large size change: {original_size} -> {replacement_size} ({size_diff_pct:.1f}%)")
                issues.append("This may indicate missing mipmaps or incorrect format")
            else:
                warnings.append(f"Size changed: {original_size} -> {replacement_size} ({size_diff_pct:.1f}%)")

        # Check for power-of-2 dimensions (common requirement for textures with mipmaps)
        # Estimate if this might be a raw texture by checking if size matches common formats
        # Common texture sizes: 4bpp (DXT1), 8bpp (DXT5), 16bpp, 32bpp
        common_bpp = [4/8, 8/8, 2, 4]  # bytes per pixel for various formats

        for bpp in common_bpp:
            # Check if size matches a square power-of-2 texture
            for size in [16, 32, 64, 128, 256, 512, 1024, 2048, 4096]:
                expected_size = int(size * size * bpp)
                # For DXT compressed textures, include mipmap chain (adds ~33% to size)
                with_mipmaps = int(expected_size * 1.333)

                if replacement_size == expected_size:
                    warnings.append(f"Matches {size}x{size} texture without mipmaps (may cause low-res rendering)")
                    break
                elif replacement_size == with_mipmaps:
                    warnings.append(f"Appears to be {size}x{size} texture with mipmaps (good!)")
                    break

        return issues, warnings

    def _texture_main_entry_for_resource(self, resource_entry):
        """Build a minimal main texture entry from a resource entry's TOC row."""
        try:
            toc_offset = resource_entry['toc_entry_offset']
            main_offset = self.read_long(toc_offset + 2)
            main_size = self.read_long(toc_offset + 6)
            name = resource_entry.get('name', '')
            if name.lower().endswith('.resource'):
                name = name[:-9]
            return {
                'file_num': resource_entry.get('file_num'),
                'name': name,
                'offset': self.main_data_offset + main_offset,
                'size': main_size,
                'raw_offset': main_offset,
                'file_type': resource_entry.get('file_type'),
            }
        except Exception:
            return None

    def _texture_info_from_main_data(self, main_data, resource_size=0):
        if len(main_data) < 0x10:
            return None
        ext = os.path.splitext(self.filepath.lower())[1]
        if not getattr(self, 'is_big_endian', True) and ext in ('.cmf', '.ccf', '.bdl'):
            format_word = struct.unpack_from('<I', main_data, 0x0C)[0]
            fmt_code = (format_word >> 8) & 0xFF
            linear_formats = {
                0x10: ('XBOX_LIN_A1R5G5B5', 2),
                0x12: ('XBOX_LIN_A8R8G8B8', 4),
                0x1B: ('XBOX_LIN_AL8', 1),
                0x1D: ('XBOX_LIN_A4R4G4B4', 2),
                0x20: ('XBOX_LIN_A8L8', 2),
            }
            if fmt_code in linear_formats and len(main_data) >= 0x14:
                size_word = struct.unpack_from('<I', main_data, 0x10)[0]
                width = (size_word & 0x0FFF) + 1
                height = ((size_word >> 12) & 0x0FFF) + 1
                pitch = (((size_word >> 24) & 0xFF) + 1) * 64
                fmt_name, bytes_per_pixel = linear_formats[fmt_code]
                if width <= 0 or height <= 0 or pitch < width * bytes_per_pixel:
                    return None
                return {
                    'width': width,
                    'height': height,
                    'pitch': pitch,
                    'format_code': fmt_code,
                    'format': fmt_name,
                    'platform': 'xbox',
                    'mip_count': 1,
                    'format_word': format_word,
                }
            width_exp = (format_word >> 20) & 0x0F
            height_exp = (format_word >> 24) & 0x0F
            mip_count = (format_word >> 16) & 0x0F
            fmt_name = {
                7: 'XBOX_X8R8G8B8',
                12: 'XBOX_DXT1',
                14: 'XBOX_DXT3',
                15: 'XBOX_DXT5',
                1: 'XBOX_AL8',
                4: 'XBOX_A4R4G4B4',
                26: 'XBOX_A8L8',
            }.get(fmt_code)
            if not fmt_name or width_exp > 13 or height_exp > 13:
                return None
            return {
                'width': 1 << width_exp,
                'height': 1 << height_exp,
                'format_code': fmt_code,
                'format': fmt_name,
                'platform': 'xbox',
                'mip_count': max(1, mip_count),
                'format_word': format_word,
            }
        if not getattr(self, 'is_big_endian', True) and ext in ('.cmp', '.clp', '.bdp', '.bsf'):
            width = struct.unpack_from('<H', main_data, 0x08)[0]
            height = struct.unpack_from('<H', main_data, 0x0A)[0]
            if width <= 0 or height <= 0 or width > 8192 or height > 8192:
                return None
            fmt_code = struct.unpack_from('<H', main_data, 0x00)[0]
            ps2_storage_word = struct.unpack_from('<I', main_data, 0x04)[0] if len(main_data) >= 0x08 else 0
            mip_count = main_data[0x0C] if len(main_data) > 0x0C else 1
            fmt_name = self._choose_ps2_texture_format(fmt_code, width, height, resource_size, mip_count)
            if not fmt_name:
                return None
            if fmt_name == 'PS2_RGBA32' and width > 0:
                actual_height = resource_size // (width * 4)
                if 0 < actual_height <= height:
                    height = actual_height
            return {
                'width': width,
                'height': height,
                'format_code': fmt_code,
                'format': fmt_name,
                'platform': 'ps2',
                'mip_count': mip_count,
                'storage_word': ps2_storage_word,
            }
        width_height = struct.unpack_from('>I', main_data, 0x08)[0]
        width = width_height >> 16
        height = width_height & 0xFFFF
        if width <= 0 or height <= 0 or width > 8192 or height > 8192:
            return None
        # Wii texture records store the GX texture format as a big-endian word
        # at 0x04. The value at 0x0C is the mip count (for example, 8 for a
        # complete 512x512 chain), not a texture format.
        fmt_code = struct.unpack_from('>I', main_data, 0x04)[0]
        if fmt_code not in (0, 1, 2, 3, 4, 5, 6, 14):
            # Retain support for older/alternate records that used the field
            # previously read by GZBuildr.
            fmt_code = struct.unpack_from('>H', main_data, 0x0C)[0]
        fmt_name = self._choose_texture_format(fmt_code, width, height, resource_size)
        if not fmt_name:
            return None
        return {'width': width, 'height': height, 'format_code': fmt_code, 'format': fmt_name, 'platform': 'gcn'}

    def _choose_ps2_texture_format(self, fmt_code, width, height, resource_size, mip_count=1):
        if fmt_code == 3:
            psmt4_base = self._texture_block_size('PS2_PSMT4', width, height)
            psmt4_chain = self._texture_chain_size('PS2_PSMT4', width, height, max(1, mip_count))
            if resource_size == psmt4_chain or resource_size == psmt4_base or resource_size < width * height:
                return 'PS2_PSMT4'
            return 'PS2_PSMT8'
        if fmt_code == 1:
            rgba_chain_size = self._texture_chain_size('PS2_RGBA32', width, height, max(1, mip_count))
            if resource_size == rgba_chain_size:
                return 'PS2_RGBA32'
            if width > 0 and resource_size % (width * 4) == 0:
                actual_height = resource_size // (width * 4)
                if 0 < actual_height <= height:
                    return 'PS2_RGBA32'
            if resource_size >= width * height * 2:
                return 'PS2_BGR555'
            return 'PS2_UNSUPPORTED_16'
        if fmt_code == 9 and resource_size >= width * height * 2:
            return 'PS2_BGR555'

        base_8 = width * height
        base_16 = width * height * 2
        if resource_size >= base_16:
            return 'PS2_BGR555'
        if resource_size >= base_8:
            return 'PS2_PSMT8'
        return None

    def _texture_block_size(self, fmt_name, width, height):
        width = max(1, int(width))
        height = max(1, int(height))
        if fmt_name == 'PS2_PSMT8':
            return width * height
        if fmt_name == 'PS2_PSMT4':
            return (width * height + 1) // 2
        if fmt_name == 'PS2_RGBA32':
            return width * height * 4
        if fmt_name in ('PS2_RGB565', 'PS2_BGR555'):
            return width * height * 2
        if fmt_name == 'XBOX_X8R8G8B8':
            return width * height * 4
        if fmt_name == 'XBOX_A8L8':
            return width * height * 2
        if fmt_name == 'XBOX_AL8':
            return width * height
        if fmt_name == 'XBOX_A4R4G4B4':
            return width * height * 2
        if fmt_name.startswith('XBOX_LIN_'):
            return width * height * ({'XBOX_LIN_AL8': 1, 'XBOX_LIN_A8R8G8B8': 4}.get(fmt_name, 2))
        if fmt_name == 'XBOX_DXT1':
            return ((width + 3) // 4) * ((height + 3) // 4) * 8
        if fmt_name == 'XBOX_DXT3':
            return ((width + 3) // 4) * ((height + 3) // 4) * 16
        if fmt_name == 'XBOX_DXT5':
            return ((width + 3) // 4) * ((height + 3) // 4) * 16
        if fmt_name == 'I4':
            return ((width + 7) // 8) * ((height + 7) // 8) * 32
        if fmt_name in ('I8', 'IA4'):
            return ((width + 7) // 8) * ((height + 3) // 4) * 32
        if fmt_name in ('IA8', 'RGB565', 'RGB5A3'):
            return ((width + 3) // 4) * ((height + 3) // 4) * 32
        if fmt_name == 'RGBA8':
            return ((width + 3) // 4) * ((height + 3) // 4) * 64
        if fmt_name == 'CMPR':
            return ((width + 7) // 8) * ((height + 7) // 8) * 32
        return 0

    def _texture_chain_size(self, fmt_name, width, height, levels=32):
        total = 0
        w = max(1, width)
        h = max(1, height)
        for _ in range(levels):
            total += self._texture_block_size(fmt_name, w, h)
            if w == 1 and h == 1:
                break
            w = max(1, w // 2)
            h = max(1, h // 2)
        return total

    def _choose_texture_format(self, fmt_code, width, height, resource_size):
        gx_map = {
            0: 'I4',
            1: 'I8',
            2: 'IA4',
            3: 'IA8',
            4: 'RGB565',
            5: 'RGB5A3',
            6: 'RGBA8',
            14: 'CMPR',
        }
        format_hints = {
            7: 'IA4',
            8: 'CMPR',
        }
        hinted = gx_map.get(fmt_code) or format_hints.get(fmt_code)
        if fmt_code == 1 and resource_size >= width * height * 2:
            hinted = 'RGB5A3'
        candidates = ['CMPR', 'I4', 'I8', 'IA4', 'IA8', 'RGB565', 'RGB5A3', 'RGBA8']
        tolerance = max(128, int(max(1, resource_size) * 0.002))
        scored = []
        fits = []
        for fmt_name in candidates:
            base_size = self._texture_block_size(fmt_name, width, height)
            chain_size = self._texture_chain_size(fmt_name, width, height)
            best_diff = min(abs(resource_size - base_size), abs(resource_size - chain_size))
            if resource_size and best_diff <= tolerance:
                hinted_bonus = 0 if fmt_name == hinted else 1
                scored.append((best_diff, hinted_bonus, candidates.index(fmt_name), fmt_name))
            if resource_size >= base_size:
                fits.append(fmt_name)
        if scored:
            scored.sort()
            return scored[0][3]
        if hinted and hinted in fits:
            return hinted
        return fits[0] if fits else None

    def _texture_mip_layout(self, fmt_name, width, height, total_size):
        layout = []
        offset = 0
        w = max(1, width)
        h = max(1, height)
        while offset < total_size:
            size = self._texture_block_size(fmt_name, w, h)
            if size <= 0 or offset + size > total_size:
                break
            layout.append((w, h, offset, size))
            offset += size
            if w == 1 and h == 1:
                break
            w = max(1, w // 2)
            h = max(1, h // 2)
        return layout, offset

    def _texture_info_with_name_hint(self, info, texture_name):
        if not info or info.get('platform') != 'gcn':
            return info
        base = os.path.basename(str(texture_name or '')).lower()
        if base.endswith('.resource'):
            base = base[:-9]
        if base.endswith('_a') and info.get('format') == 'I4':
            info = dict(info)
            info['intensity_as_alpha'] = True
        if base.endswith('_c') and info.get('format') in ('IA8', 'RGB565', 'RGB5A3'):
            info = dict(info)
            info['format'] = 'RGB5A3'
        elif base.endswith(('_b', '_n')) and info.get('format') in ('RGB565', 'RGB5A3'):
            info = dict(info)
            info['format'] = 'IA8'
        return info

    def _rgb565_unpack(self, value):
        r = ((value >> 11) & 31) * 255 // 31
        g = ((value >> 5) & 63) * 255 // 63
        b = (value & 31) * 255 // 31
        return r, g, b, 255

    def _rgb565_pack(self, r, g, b):
        r5 = max(0, min(31, round(r * 31 / 255)))
        g6 = max(0, min(63, round(g * 63 / 255)))
        b5 = max(0, min(31, round(b * 31 / 255)))
        return (r5 << 11) | (g6 << 5) | b5

    def _rgb5a3_unpack(self, value):
        if value & 0x8000:
            r = ((value >> 10) & 31) * 255 // 31
            g = ((value >> 5) & 31) * 255 // 31
            b = (value & 31) * 255 // 31
            return r, g, b, 255
        a = ((value >> 12) & 7) * 255 // 7
        r = ((value >> 8) & 15) * 255 // 15
        g = ((value >> 4) & 15) * 255 // 15
        b = (value & 15) * 255 // 15
        return r, g, b, a

    def _rgb5a3_pack(self, r, g, b, a):
        if a < 224:
            a3 = max(0, min(7, round(a * 7 / 255)))
            r4 = max(0, min(15, round(r * 15 / 255)))
            g4 = max(0, min(15, round(g * 15 / 255)))
            b4 = max(0, min(15, round(b * 15 / 255)))
            return (a3 << 12) | (r4 << 8) | (g4 << 4) | b4
        r5 = max(0, min(31, round(r * 31 / 255)))
        g5 = max(0, min(31, round(g * 31 / 255)))
        b5 = max(0, min(31, round(b * 31 / 255)))
        return 0x8000 | (r5 << 10) | (g5 << 5) | b5

    def _decode_texture_image(self, data, fmt_name, width, height):
        if not HAS_PIL:
            return None
        img = Image.new('RGBA', (width, height))
        pix = img.load()
        pos = 0
        if fmt_name == 'I4':
            for ty in range(0, height, 8):
                for tx in range(0, width, 8):
                    for y in range(8):
                        for xpair in range(4):
                            if pos >= len(data):
                                return img
                            byte = data[pos]
                            pos += 1
                            for j, nib in enumerate(((byte >> 4) & 15, byte & 15)):
                                x = tx + xpair * 2 + j
                                yy = ty + y
                                if x < width and yy < height:
                                    v = nib * 17
                                    pix[x, yy] = (v, v, v, 255)
        elif fmt_name == 'I8':
            for ty in range(0, height, 4):
                for tx in range(0, width, 8):
                    for y in range(4):
                        for x in range(8):
                            if pos >= len(data):
                                return img
                            xx = tx + x
                            yy = ty + y
                            if xx < width and yy < height:
                                v = data[pos]
                                pix[xx, yy] = (v, v, v, 255)
                            pos += 1
        elif fmt_name == 'IA4':
            for ty in range(0, height, 4):
                for tx in range(0, width, 8):
                    for y in range(4):
                        for x in range(8):
                            if pos >= len(data):
                                return img
                            b = data[pos]
                            pos += 1
                            xx = tx + x
                            yy = ty + y
                            if xx < width and yy < height:
                                a = ((b >> 4) & 15) * 17
                                v = (b & 15) * 17
                                pix[xx, yy] = (v, v, v, a)
        elif fmt_name in ('IA8', 'RGB565', 'RGB5A3'):
            for ty in range(0, height, 4):
                for tx in range(0, width, 4):
                    for y in range(4):
                        for x in range(4):
                            if pos + 1 >= len(data):
                                return img
                            value = (data[pos] << 8) | data[pos + 1]
                            pos += 2
                            xx = tx + x
                            yy = ty + y
                            if xx >= width or yy >= height:
                                continue
                            if fmt_name == 'IA8':
                                pix[xx, yy] = (data[pos - 1], data[pos - 1], data[pos - 1], data[pos - 2])
                            elif fmt_name == 'RGB565':
                                pix[xx, yy] = self._rgb565_unpack(value)
                            else:
                                pix[xx, yy] = self._rgb5a3_unpack(value)
        elif fmt_name == 'RGBA8':
            for ty in range(0, height, 4):
                for tx in range(0, width, 4):
                    ar = []
                    gb = []
                    for _ in range(16):
                        if pos + 1 < len(data):
                            ar.append((data[pos], data[pos + 1]))
                        pos += 2
                    for _ in range(16):
                        if pos + 1 < len(data):
                            gb.append((data[pos], data[pos + 1]))
                        pos += 2
                    for i in range(min(len(ar), len(gb), 16)):
                        x = i % 4
                        y = i // 4
                        xx = tx + x
                        yy = ty + y
                        if xx < width and yy < height:
                            a, r = ar[i]
                            g, b = gb[i]
                            pix[xx, yy] = (r, g, b, a)
        elif fmt_name == 'CMPR':
            for y0 in range(0, height, 8):
                for x0 in range(0, width, 8):
                    for by, bx in ((0, 0), (0, 4), (4, 0), (4, 4)):
                        if pos + 8 > len(data):
                            return img
                        c0, c1, bits = struct.unpack('>HHI', data[pos:pos + 8])
                        pos += 8
                        palette = [self._rgb565_unpack(c0), self._rgb565_unpack(c1)]
                        if c0 > c1:
                            palette.append(tuple((2 * palette[0][i] + palette[1][i]) // 3 for i in range(3)) + (255,))
                            palette.append(tuple((palette[0][i] + 2 * palette[1][i]) // 3 for i in range(3)) + (255,))
                        else:
                            palette.append(tuple((palette[0][i] + palette[1][i]) // 2 for i in range(3)) + (255,))
                            palette.append((0, 0, 0, 0))
                        for py in range(4):
                            for px in range(4):
                                idx = (bits >> (30 - 2 * (py * 4 + px))) & 3
                                xx = x0 + bx + px
                                yy = y0 + by + py
                                if xx < width and yy < height:
                                    pix[xx, yy] = palette[idx]
        return img

    def _ps2_unswizzle8(self, data, width, height):
        out = bytearray(width * height)
        for y in range(height):
            for x in range(width):
                block = (y & ~0xF) * width + (x & ~0xF) * 2
                swap = (((y + 2) >> 2) & 1) * 4
                pos_y = (((y & ~3) >> 1) + (y & 1)) & 7
                col = pos_y * width * 2 + ((x + swap) & 7) * 4
                byte = ((y >> 1) & 1) + ((x >> 2) & 2)
                src = block + col + byte
                if src < len(data):
                    out[y * width + x] = data[src]
        return bytes(out)

    def _ps2_swizzle8(self, indexes, width, height):
        out = bytearray(width * height)
        for y in range(height):
            for x in range(width):
                block = (y & ~0xF) * width + (x & ~0xF) * 2
                swap = (((y + 2) >> 2) & 1) * 4
                pos_y = (((y & ~3) >> 1) + (y & 1)) & 7
                col = pos_y * width * 2 + ((x + swap) & 7) * 4
                byte = ((y >> 1) & 1) + ((x >> 2) & 2)
                dst = block + col + byte
                if dst < len(out):
                    out[dst] = indexes[y * width + x]
        return bytes(out)

    def _ps2_palette_rgba(self, palette_data):
        if len(palette_data) >= 1024:
            raw = palette_data[:1024]
            colors = [tuple(raw[i:i + 4]) for i in range(0, 1024, 4)]
            reordered = []
            for index in range(0, 256, 32):
                reordered.extend(
                    colors[index:index + 8]
                    + colors[index + 16:index + 24]
                    + colors[index + 8:index + 16]
                    + colors[index + 24:index + 32]
                )
            return [(r, g, b, min(255, a * 2)) for r, g, b, a in reordered]
        if len(palette_data) >= 64:
            raw = palette_data[:64]
            return [(r, g, b, min(255, a * 2)) for r, g, b, a in (tuple(raw[i:i + 4]) for i in range(0, 64, 4))]
        if len(palette_data) < 16:
            return None
        return None

    def _ps2_palette_resource_from_rgba(self, palette, color_count=256):
        color_count = 16 if color_count <= 16 else 256
        colors = list(palette[:color_count])
        while len(colors) < color_count:
            colors.append((0, 0, 0, 0))
        if color_count == 16:
            raw_order = colors
        else:
            raw_order = [(0, 0, 0, 0)] * 256
            for base in range(0, 256, 32):
                chunk = colors[base:base + 32]
                raw_order[base:base + 8] = chunk[0:8]
                raw_order[base + 8:base + 16] = chunk[16:24]
                raw_order[base + 16:base + 24] = chunk[8:16]
                raw_order[base + 24:base + 32] = chunk[24:32]
        out = bytearray()
        for r, g, b, a in raw_order:
            stored_a = max(0, min(128, round(a / 2)))
            out.extend(bytes((max(0, min(255, int(r))), max(0, min(255, int(g))), max(0, min(255, int(b))), stored_a)))
        return bytes(out)

    def _pending_ps2_palette_resource_for_entry(self, entry):
        pending = getattr(self, '_pending_ps2_palette_replacements', {})
        keys = {
            entry.get('file_num'),
            str(entry.get('name', '')).lower(),
            os.path.basename(str(entry.get('name', ''))).lower(),
        }
        palette_data = None
        for key in keys:
            if key in pending:
                palette_data = pending[key]
                break
        if palette_data is not None:
            for key in keys:
                pending.pop(key, None)
        return palette_data

    def _remember_ps2_palette_resource(self, palette_entry, palette_data):
        if not palette_entry or not palette_data:
            return
        if not hasattr(self, '_pending_ps2_palette_replacements'):
            self._pending_ps2_palette_replacements = {}
        keys = {
            palette_entry.get('file_num'),
            str(palette_entry.get('name', '')).lower(),
            os.path.basename(str(palette_entry.get('name', ''))).lower(),
        }
        for key in keys:
            self._pending_ps2_palette_replacements[key] = palette_data

    def _find_ps2_palette_entry(self, texture_entry):
        try:
            entries = self.parse()
        except Exception:
            return None
        texture_name = os.path.basename(texture_entry.get('name', ''))
        if texture_name.lower().endswith('.resource'):
            texture_name = texture_name[:-9]
        candidates = {
            f"{texture_name}.pal.resource".lower(),
            f"{texture_name}.pal".lower(),
        }
        next_file_num = texture_entry.get('file_num', -1) + 1
        for entry in entries:
            if not entry.get('is_resource') or entry.get('file_type') != 13:
                continue
            entry_base = os.path.basename(entry.get('name', '')).lower()
            if entry_base in candidates or entry.get('file_num') == next_file_num:
                return entry
        return None

    def _ps2_psmt4_offset(self, x, y, width, height):
        pages_horz = (width + 127) // 128
        pages_vert = (height + 127) // 128
        page_x = x & ~0x7F
        page_y = y & ~0x7F
        page_number = (page_y // 128) * pages_horz + (page_x // 128)
        page32_y = (page_number // max(1, pages_vert)) * 32
        page32_x = (page_number % max(1, pages_vert)) * 64
        page_location = page32_y * height * 2 + page32_x * 4
        loc_x = x & 0x7F
        loc_y = y & 0x7F
        block_location = ((loc_x & ~0x1F) >> 1) * height + (loc_y & ~0x0F) * 2
        swap_selector = (((y + 2) >> 2) & 1) * 4
        pos_y = (((y & ~3) >> 1) + (y & 1)) & 7
        column_location = pos_y * height * 2 + ((x + swap_selector) & 7) * 4
        byte_num = (x >> 3) & 3
        return page_location + block_location + column_location + byte_num, (y >> 1) & 1

    def _ps2_unswizzle4(self, data, width, height):
        indexes = bytearray(width * height)
        for y in range(height):
            for x in range(width):
                src, high_nibble = self._ps2_psmt4_offset(x, y, width, height)
                if src < len(data):
                    byte = data[src]
                    indexes[y * width + x] = ((byte >> 4) & 0x0F) if high_nibble else (byte & 0x0F)
        return bytes(indexes)

    def _ps2_swizzle4(self, indexes, width, height):
        out = bytearray((width * height + 1) // 2)
        for y in range(height):
            for x in range(width):
                dst, high_nibble = self._ps2_psmt4_offset(x, y, width, height)
                if dst < len(out):
                    value = indexes[y * width + x] & 0x0F
                    if high_nibble:
                        out[dst] = (out[dst] & 0x0F) | (value << 4)
                    else:
                        out[dst] = (out[dst] & 0xF0) | value
        return bytes(out)

    def _ps2_indexed_texture_uses_swizzle(self, texture_entry, info=None):
        ext = os.path.splitext(self.filepath.lower())[1]
        if ext in ('.bdp', '.bsf'):
            if not info:
                return False
            if int(info.get('mip_count') or 1) > 1:
                return True
            return bool(int(info.get('storage_word') or 0) & 0x40000000)
        return True

    def _decode_ps2_texture_image(self, resource_data, info, texture_entry):
        if not HAS_PIL:
            return None
        width = info['width']
        height = info['height']
        fmt_name = info['format']
        if fmt_name in ('PS2_PSMT8', 'PS2_PSMT4'):
            palette_entry = self._find_ps2_palette_entry(texture_entry)
            if palette_entry:
                palette_data = self.read_bytes(palette_entry['offset'], palette_entry['size'])
                palette = self._ps2_palette_rgba(palette_data)
            else:
                color_count = 16 if fmt_name == 'PS2_PSMT4' else 256
                palette = [(i * 255 // max(1, color_count - 1),) * 3 + (255,) for i in range(color_count)]
            if not palette:
                return None
            if fmt_name == 'PS2_PSMT4':
                indexes = self._ps2_unswizzle4(resource_data, width, height)
            else:
                raw_indexes = resource_data[:width * height]
                if len(raw_indexes) < width * height:
                    return None
                indexes = raw_indexes
            if fmt_name == 'PS2_PSMT8' and self._ps2_indexed_texture_uses_swizzle(texture_entry, info):
                indexes = self._ps2_unswizzle8(raw_indexes, width, height)
            img = Image.new('RGBA', (width, height))
            pix = img.load()
            palette_limit = len(palette)
            for y in range(height):
                row = y * width
                for x in range(width):
                    pix[x, y] = palette[indexes[row + x] % palette_limit]
            return img
        if fmt_name == 'PS2_BGR555':
            needed = width * height * 2
            if len(resource_data) < needed:
                return None
            img = Image.new('RGBA', (width, height))
            pix = img.load()
            pos = 0
            for y in range(height):
                for x in range(width):
                    value = resource_data[pos] | (resource_data[pos + 1] << 8)
                    pos += 2
                    r = (value & 31) * 255 // 31
                    g = ((value >> 5) & 31) * 255 // 31
                    b = ((value >> 10) & 31) * 255 // 31
                    pix[x, y] = (r, g, b, 255)
            return img
        if fmt_name == 'PS2_UNSUPPORTED_16':
            print(f"    Texture PNG skipped for {texture_entry.get('name')}: PS2 16-bit texture format is not supported yet")
            return None
        if fmt_name == 'PS2_RGBA32':
            needed = width * height * 4
            if len(resource_data) < needed:
                return None
            img = Image.new('RGBA', (width, height))
            pix = img.load()
            pos = 0
            for y in range(height):
                for x in range(width):
                    r = resource_data[pos]
                    g = resource_data[pos + 1]
                    b = resource_data[pos + 2]
                    a = min(255, resource_data[pos + 3] * 2)
                    pix[x, y] = (r, g, b, a)
                    pos += 4
            return img
        return None

    def _encode_ps2_texture_image(self, image, info, texture_entry, original_resource_data):
        width = info['width']
        height = info['height']
        fmt_name = info['format']
        resample = getattr(Image, 'Resampling', Image).LANCZOS if hasattr(Image, 'LANCZOS') or hasattr(Image, 'Resampling') else 1
        if fmt_name in ('PS2_PSMT8', 'PS2_PSMT4'):
            layout, used_size = self._texture_mip_layout(fmt_name, width, height, len(original_resource_data))
            if not layout:
                return None
            base_image = image.convert('RGBA').resize((width, height), resample)
            color_count = 16 if fmt_name == 'PS2_PSMT4' else 256
            try:
                palette_image = base_image.convert('P', palette=Image.Palette.ADAPTIVE, colors=color_count)
            except AttributeError:
                palette_image = base_image.convert('P', palette=Image.ADAPTIVE, colors=color_count)
            raw_palette = palette_image.getpalette() or []
            alpha_source = base_image.getchannel('A')
            alpha_by_index = [255] * color_count
            base_indexes = list(palette_image.getdata())
            base_alpha = list(alpha_source.getdata())
            alpha_totals = [0] * color_count
            alpha_counts = [0] * color_count
            for idx, alpha in zip(base_indexes, base_alpha):
                if idx < color_count:
                    alpha_totals[idx] += alpha
                    alpha_counts[idx] += 1
            palette = []
            for index in range(color_count):
                r = raw_palette[index * 3] if index * 3 < len(raw_palette) else 0
                g = raw_palette[index * 3 + 1] if index * 3 + 1 < len(raw_palette) else 0
                b = raw_palette[index * 3 + 2] if index * 3 + 2 < len(raw_palette) else 0
                if alpha_counts[index]:
                    alpha_by_index[index] = round(alpha_totals[index] / alpha_counts[index])
                palette.append((r, g, b, alpha_by_index[index]))
            palette_resource = self._ps2_palette_resource_from_rgba(palette, color_count)
            palette_entry = self._find_ps2_palette_entry(texture_entry)
            if not palette_entry:
                print(f"      WARNING CRITICAL: PS2 indexed texture has no palette resource for {texture_entry.get('name')}")
                return None
            self._remember_ps2_palette_resource(palette_entry, palette_resource)

            new_data = bytearray()
            for mip_width, mip_height, _offset, _size in layout:
                mip = image.convert('RGBA').resize((mip_width, mip_height), resample)
                if mip_width == width and mip_height == height:
                    indexed = palette_image
                else:
                    indexed = mip.convert('RGB').quantize(
                        palette=palette_image,
                        dither=Image.Dither.NONE if hasattr(Image, 'Dither') else 0,
                    )
                indexes = bytes(indexed.getdata())
                if fmt_name == 'PS2_PSMT4':
                    indexes = bytes((idx & 0x0F) for idx in indexes)
                    new_data.extend(self._ps2_swizzle4(indexes, mip_width, mip_height))
                elif self._ps2_indexed_texture_uses_swizzle(texture_entry, info):
                    new_data.extend(self._ps2_swizzle8(indexes, mip_width, mip_height))
                else:
                    new_data.extend(indexes)
            if used_size < len(original_resource_data):
                new_data.extend(original_resource_data[used_size:])
            return bytes(new_data)
        if fmt_name == 'PS2_BGR555':
            out = bytearray()
            layout, used_size = self._texture_mip_layout(fmt_name, width, height, len(original_resource_data))
            if not layout:
                return None
            for mip_width, mip_height, _offset, _size in layout:
                img = image.convert('RGBA').resize((mip_width, mip_height), resample)
                for r, g, b, _a in img.getdata():
                    value = (
                        (max(0, min(31, round(r * 31 / 255))))
                        | (max(0, min(31, round(g * 31 / 255))) << 5)
                        | (max(0, min(31, round(b * 31 / 255))) << 10)
                    )
                    out.extend(struct.pack('<H', value))
            if used_size < len(original_resource_data):
                out.extend(original_resource_data[used_size:])
            return bytes(out)
        if fmt_name == 'PS2_RGBA32':
            out = bytearray()
            layout, used_size = self._texture_mip_layout(fmt_name, width, height, len(original_resource_data))
            if not layout:
                return None
            for mip_width, mip_height, _offset, _size in layout:
                img = image.convert('RGBA').resize((mip_width, mip_height), resample)
                for r, g, b, a in img.getdata():
                    out.extend(bytes((r, g, b, max(0, min(128, round(a / 2))))))
            if used_size < len(original_resource_data):
                out.extend(original_resource_data[used_size:])
            return bytes(out)
        return None

    def _encode_texture_image(self, image, fmt_name, width, height, intensity_as_alpha=False):
        resample = getattr(Image, 'Resampling', Image).LANCZOS if hasattr(Image, 'LANCZOS') or hasattr(Image, 'Resampling') else 1
        if fmt_name in ('I4', 'I8'):
            if fmt_name == 'I4' and intensity_as_alpha and 'A' in image.getbands():
                img = image.getchannel('A').resize((width, height), resample)
            else:
                img = image.convert('L').resize((width, height), resample)
            pix = img.load()
        elif fmt_name == 'RGB565':
            img = image.convert('RGB').resize((width, height), resample)
            pix = img.load()
        else:
            img = image.convert('RGBA').resize((width, height), resample)
            pix = img.load()
        out = bytearray()
        if fmt_name == 'I4':
            for ty in range(0, height, 8):
                for tx in range(0, width, 8):
                    for y in range(8):
                        for xpair in range(4):
                            values = []
                            for j in range(2):
                                xx = tx + xpair * 2 + j
                                yy = ty + y
                                values.append((pix[xx, yy] if xx < width and yy < height else 0) >> 4)
                            out.append((values[0] << 4) | values[1])
        elif fmt_name == 'I8':
            for ty in range(0, height, 4):
                for tx in range(0, width, 8):
                    for y in range(4):
                        for x in range(8):
                            xx = tx + x
                            yy = ty + y
                            out.append(pix[xx, yy] if xx < width and yy < height else 0)
        elif fmt_name == 'IA4':
            for ty in range(0, height, 4):
                for tx in range(0, width, 8):
                    for y in range(4):
                        for x in range(8):
                            xx = tx + x
                            yy = ty + y
                            if xx < width and yy < height:
                                r, g, b, a = pix[xx, yy]
                                v = round((r + g + b) / 3) >> 4
                                alpha = a >> 4
                            else:
                                v = 0
                                alpha = 0
                            out.append((alpha << 4) | v)
        elif fmt_name == 'IA8':
            for ty in range(0, height, 4):
                for tx in range(0, width, 4):
                    for y in range(4):
                        for x in range(4):
                            xx = tx + x
                            yy = ty + y
                            if xx < width and yy < height:
                                r, g, b, a = pix[xx, yy]
                                v = round((r + g + b) / 3)
                            else:
                                a = 0
                                v = 0
                            out.extend((a, v))
        elif fmt_name == 'RGB565':
            for ty in range(0, height, 4):
                for tx in range(0, width, 4):
                    for y in range(4):
                        for x in range(4):
                            xx = tx + x
                            yy = ty + y
                            r, g, b = pix[xx, yy] if xx < width and yy < height else (0, 0, 0)
                            out.extend(struct.pack('>H', self._rgb565_pack(r, g, b)))
        elif fmt_name == 'RGB5A3':
            for ty in range(0, height, 4):
                for tx in range(0, width, 4):
                    for y in range(4):
                        for x in range(4):
                            xx = tx + x
                            yy = ty + y
                            r, g, b, a = pix[xx, yy] if xx < width and yy < height else (0, 0, 0, 0)
                            out.extend(struct.pack('>H', self._rgb5a3_pack(r, g, b, a)))
        elif fmt_name == 'RGBA8':
            for ty in range(0, height, 4):
                for tx in range(0, width, 4):
                    tile = []
                    for y in range(4):
                        for x in range(4):
                            xx = tx + x
                            yy = ty + y
                            tile.append(pix[xx, yy] if xx < width and yy < height else (0, 0, 0, 0))
                    for r, g, b, a in tile:
                        out.extend((a, r))
                    for r, g, b, a in tile:
                        out.extend((g, b))
        elif fmt_name == 'CMPR':
            for y0 in range(0, height, 8):
                for x0 in range(0, width, 8):
                    for by, bx in ((0, 0), (0, 4), (4, 0), (4, 4)):
                        block = []
                        for y in range(4):
                            for x in range(4):
                                xx = x0 + bx + x
                                yy = y0 + by + y
                                block.append(pix[xx, yy] if xx < width and yy < height else (0, 0, 0, 0))
                        out.extend(self._encode_cmpr_block(block))
        return bytes(out)

    def _encode_cmpr_block(self, pixels):
        opaque = all(a >= 128 for _, _, _, a in pixels)
        colors = [(r, g, b) for r, g, b, a in pixels if opaque or a >= 128] or [(0, 0, 0)]

        def lum(color):
            return color[0] * 0.299 + color[1] * 0.587 + color[2] * 0.114

        cmin = min(colors, key=lum)
        cmax = max(colors, key=lum)
        q0 = self._rgb565_pack(*cmax)
        q1 = self._rgb565_pack(*cmin)
        if opaque and q0 == q1:
            q0 = min(0xFFFF, q0 + 1)
        if opaque:
            if q0 <= q1:
                q0, q1 = q1, q0
            p0 = self._rgb565_unpack(q0)
            p1 = self._rgb565_unpack(q1)
            palette = [
                p0,
                p1,
                tuple((2 * p0[i] + p1[i]) // 3 for i in range(3)) + (255,),
                tuple((p0[i] + 2 * p1[i]) // 3 for i in range(3)) + (255,),
            ]
            allow_alpha = False
        else:
            if q0 > q1:
                q0, q1 = q1, q0
            p0 = self._rgb565_unpack(q0)
            p1 = self._rgb565_unpack(q1)
            palette = [p0, p1, tuple((p0[i] + p1[i]) // 2 for i in range(3)) + (255,), (0, 0, 0, 0)]
            allow_alpha = True
        bits = 0
        for i, (r, g, b, a) in enumerate(pixels):
            if allow_alpha and a < 128:
                idx = 3
            else:
                distances = [
                    (r - pr) * (r - pr) + (g - pg) * (g - pg) + (b - pb) * (b - pb)
                    for pr, pg, pb, pa in palette
                ]
                if allow_alpha:
                    distances[3] = 10 ** 18
                idx = min(range(4), key=lambda item: distances[item])
            bits |= (idx & 3) << (30 - 2 * i)
        return struct.pack('>HHI', q0, q1, bits)

    def _xbox_morton_index(self, x, y, width, height):
        index = 0
        source_bit = 1
        output_bit = 1
        while source_bit < width or source_bit < height:
            if source_bit < width:
                if x & source_bit:
                    index |= output_bit
                output_bit <<= 1
            if source_bit < height:
                if y & source_bit:
                    index |= output_bit
                output_bit <<= 1
            source_bit <<= 1
        return index

    def _xbox_linear_pitch(self, width, fmt_name):
        bytes_per_pixel = 1 if fmt_name == 'XBOX_LIN_AL8' else (4 if fmt_name == 'XBOX_LIN_A8R8G8B8' else 2)
        return ((width * bytes_per_pixel + 63) // 64) * 64

    def _xbox_dxt_palette(self, color0, color1, allow_transparency):
        p0 = self._rgb565_unpack(color0)
        p1 = self._rgb565_unpack(color1)
        if allow_transparency and color0 <= color1:
            return [
                p0,
                p1,
                tuple((p0[i] + p1[i]) // 2 for i in range(3)) + (255,),
                (0, 0, 0, 0),
            ]
        return [
            p0,
            p1,
            tuple((2 * p0[i] + p1[i]) // 3 for i in range(3)) + (255,),
            tuple((p0[i] + 2 * p1[i]) // 3 for i in range(3)) + (255,),
        ]

    def _decode_xbox_texture_image(self, resource_data, info):
        if not HAS_PIL:
            return None
        width = info['width']
        height = info['height']
        fmt_name = info['format']
        image = Image.new('RGBA', (width, height))
        pixels = image.load()
        fmt_code = info.get('format_code')
        if fmt_name.startswith('XBOX_LIN_'):
            pitch = info['pitch']
            for y in range(height):
                for x in range(width):
                    if fmt_name == 'XBOX_LIN_AL8':
                        value = resource_data[y * pitch + x]
                        luminance = (value & 0x0F) * 17
                        alpha = ((value >> 4) & 0x0F) * 17
                        pixels[x, y] = (luminance, luminance, luminance, alpha)
                    elif fmt_name == 'XBOX_LIN_A8R8G8B8':
                        offset = y * pitch + x * 4
                        b, g, r, a = resource_data[offset:offset + 4]
                        pixels[x, y] = (r, g, b, a)
                    else:
                        offset = y * pitch + x * 2
                        value = struct.unpack_from('<H', resource_data, offset)[0]
                        if fmt_name == 'XBOX_LIN_A1R5G5B5':
                            a = 255 if value & 0x8000 else 0
                            r = ((value >> 10) & 31) * 255 // 31
                            g = ((value >> 5) & 31) * 255 // 31
                            b = (value & 31) * 255 // 31
                        elif fmt_name == 'XBOX_LIN_A4R4G4B4':
                            a = ((value >> 12) & 15) * 17
                            r = ((value >> 8) & 15) * 17
                            g = ((value >> 4) & 15) * 17
                            b = (value & 15) * 17
                        else:
                            luminance = value & 0xFF
                            a = (value >> 8) & 0xFF
                            r = g = b = luminance
                        pixels[x, y] = (r, g, b, a)
            return image
        if fmt_name == 'XBOX_X8R8G8B8':
            for y in range(height):
                for x in range(width):
                    offset = self._xbox_morton_index(x, y, width, height) * 4
                    if offset + 4 > len(resource_data):
                        return None
                    b, g, r, _unused = resource_data[offset:offset + 4]
                    pixels[x, y] = (r, g, b, 255)
            return image
        if fmt_name == 'XBOX_A8L8':
            for y in range(height):
                for x in range(width):
                    offset = self._xbox_morton_index(x, y, width, height) * 2
                    if offset + 2 > len(resource_data):
                        return None
                    luminance, alpha = resource_data[offset:offset + 2]
                    pixels[x, y] = (luminance, luminance, luminance, alpha)
            return image
        if fmt_name == 'XBOX_AL8':
            for y in range(height):
                for x in range(width):
                    offset = self._xbox_morton_index(x, y, width, height)
                    value = resource_data[offset]
                    luminance = (value & 0x0F) * 17
                    alpha = ((value >> 4) & 0x0F) * 17
                    pixels[x, y] = (luminance, luminance, luminance, alpha)
            return image
        if fmt_name == 'XBOX_A4R4G4B4':
            for y in range(height):
                for x in range(width):
                    offset = self._xbox_morton_index(x, y, width, height) * 2
                    value = struct.unpack_from('<H', resource_data, offset)[0]
                    pixels[x, y] = (
                        ((value >> 8) & 15) * 17,
                        ((value >> 4) & 15) * 17,
                        (value & 15) * 17,
                        ((value >> 12) & 15) * 17,
                    )
            return image

        block_size = 8 if fmt_name == 'XBOX_DXT1' else 16
        blocks_wide = max(1, (width + 3) // 4)
        blocks_high = max(1, (height + 3) // 4)
        for block_y in range(blocks_high):
            for block_x in range(blocks_wide):
                offset = (block_y * blocks_wide + block_x) * block_size
                if offset + block_size > len(resource_data):
                    return None
                block = resource_data[offset:offset + block_size]
                if fmt_name == 'XBOX_DXT3':
                    alpha_bits = int.from_bytes(block[:8], 'little')
                    color_offset = 8
                    alpha_palette = None
                    alpha_selectors = None
                elif fmt_name == 'XBOX_DXT5':
                    alpha0, alpha1 = block[0], block[1]
                    alpha_selectors = int.from_bytes(block[2:8], 'little')
                    if alpha0 > alpha1:
                        alpha_palette = [alpha0, alpha1] + [
                            ((7 - i) * alpha0 + i * alpha1) // 7 for i in range(1, 7)
                        ]
                    else:
                        alpha_palette = [alpha0, alpha1] + [
                            ((5 - i) * alpha0 + i * alpha1) // 5 for i in range(1, 5)
                        ] + [0, 255]
                    alpha_bits = None
                    color_offset = 8
                else:
                    alpha_bits = None
                    alpha_palette = None
                    alpha_selectors = None
                    color_offset = 0
                color0, color1, selectors = struct.unpack_from('<HHI', block, color_offset)
                palette = self._xbox_dxt_palette(color0, color1, fmt_name == 'XBOX_DXT1')
                for py in range(4):
                    for px in range(4):
                        pixel_index = py * 4 + px
                        rgba = palette[(selectors >> (pixel_index * 2)) & 3]
                        if alpha_bits is not None:
                            alpha = ((alpha_bits >> (pixel_index * 4)) & 0x0F) * 17
                            rgba = rgba[:3] + (alpha,)
                        elif alpha_palette is not None:
                            alpha = alpha_palette[(alpha_selectors >> (pixel_index * 3)) & 7]
                            rgba = rgba[:3] + (alpha,)
                        x = block_x * 4 + px
                        y = block_y * 4 + py
                        if x < width and y < height:
                            pixels[x, y] = rgba
        return image

    def _encode_xbox_dxt_block(self, block_pixels, alpha_mode=None):
        with_explicit_alpha = alpha_mode in {'dxt3', 'dxt5'}
        opaque_pixels = [(r, g, b) for r, g, b, a in block_pixels if a >= 128]
        colors = opaque_pixels or [(0, 0, 0)]
        luminance = lambda color: color[0] * 0.299 + color[1] * 0.587 + color[2] * 0.114
        color0 = self._rgb565_pack(*max(colors, key=luminance))
        color1 = self._rgb565_pack(*min(colors, key=luminance))
        use_dxt1_alpha = not with_explicit_alpha and any(a < 128 for _r, _g, _b, a in block_pixels)
        if use_dxt1_alpha:
            if color0 > color1:
                color0, color1 = color1, color0
        else:
            if color0 <= color1:
                if color0 == color1:
                    color0 = min(0xFFFF, color0 + 1)
                if color0 <= color1:
                    color0, color1 = color1, color0
        palette = self._xbox_dxt_palette(color0, color1, use_dxt1_alpha)
        selectors = 0
        alpha_bits = 0
        for index, (r, g, b, a) in enumerate(block_pixels):
            if use_dxt1_alpha and a < 128:
                selected = 3
            else:
                distances = [
                    (r - pr) ** 2 + (g - pg) ** 2 + (b - pb) ** 2
                    for pr, pg, pb, _pa in palette
                ]
                if use_dxt1_alpha:
                    distances[3] = 1 << 60
                selected = min(range(4), key=distances.__getitem__)
            selectors |= selected << (index * 2)
            if alpha_mode == 'dxt3':
                alpha_bits |= max(0, min(15, round(a / 17))) << (index * 4)
        color_data = struct.pack('<HHI', color0, color1, selectors)
        if alpha_mode == 'dxt3':
            return alpha_bits.to_bytes(8, 'little') + color_data
        if alpha_mode == 'dxt5':
            alphas = [pixel[3] for pixel in block_pixels]
            alpha0 = max(alphas)
            alpha1 = min(alphas)
            if alpha0 == alpha1:
                alpha_palette = [alpha0] * 8
            else:
                alpha_palette = [alpha0, alpha1] + [
                    ((7 - i) * alpha0 + i * alpha1) // 7 for i in range(1, 7)
                ]
            alpha_selectors = 0
            for index, alpha in enumerate(alphas):
                selected = min(range(8), key=lambda item: abs(alpha - alpha_palette[item]))
                alpha_selectors |= selected << (index * 3)
            return bytes((alpha0, alpha1)) + alpha_selectors.to_bytes(6, 'little') + color_data
        return color_data

    def _encode_xbox_texture_level(self, source_image, fmt_name, width, height):
        resampling = getattr(Image, 'Resampling', Image)
        image = source_image.resize((width, height), getattr(resampling, 'LANCZOS', Image.LANCZOS)).convert('RGBA')
        pixels = image.load()
        if fmt_name.startswith('XBOX_LIN_'):
            pitch = self._xbox_linear_pitch(width, fmt_name)
            output = bytearray(pitch * height)
            for y in range(height):
                for x in range(width):
                    r, g, b, a = pixels[x, y]
                    if fmt_name == 'XBOX_LIN_AL8':
                        luminance = round((r + g + b) / 3) >> 4
                        output[y * pitch + x] = ((a >> 4) << 4) | luminance
                    elif fmt_name == 'XBOX_LIN_A8R8G8B8':
                        offset = y * pitch + x * 4
                        output[offset:offset + 4] = bytes((b, g, r, a))
                    else:
                        offset = y * pitch + x * 2
                        if fmt_name == 'XBOX_LIN_A1R5G5B5':
                            value = ((1 if a >= 128 else 0) << 15) | (round(r * 31 / 255) << 10) | (round(g * 31 / 255) << 5) | round(b * 31 / 255)
                        elif fmt_name == 'XBOX_LIN_A4R4G4B4':
                            value = (round(a / 17) << 12) | (round(r / 17) << 8) | (round(g / 17) << 4) | round(b / 17)
                        else:
                            luminance = max(0, min(255, round((r + g + b) / 3)))
                            value = (a << 8) | luminance
                        struct.pack_into('<H', output, offset, value)
            return bytes(output)
        if fmt_name == 'XBOX_X8R8G8B8':
            output = bytearray(width * height * 4)
            for y in range(height):
                for x in range(width):
                    r, g, b, _a = pixels[x, y]
                    offset = self._xbox_morton_index(x, y, width, height) * 4
                    output[offset:offset + 4] = bytes((b, g, r, 255))
            return bytes(output)
        if fmt_name == 'XBOX_A8L8':
            output = bytearray(width * height * 2)
            for y in range(height):
                for x in range(width):
                    r, g, b, a = pixels[x, y]
                    luminance = max(0, min(255, round((r + g + b) / 3)))
                    offset = self._xbox_morton_index(x, y, width, height) * 2
                    output[offset:offset + 2] = bytes((luminance, a))
            return bytes(output)
        if fmt_name == 'XBOX_AL8':
            output = bytearray(width * height)
            for y in range(height):
                for x in range(width):
                    r, g, b, a = pixels[x, y]
                    luminance = round((r + g + b) / 3) >> 4
                    output[self._xbox_morton_index(x, y, width, height)] = ((a >> 4) << 4) | luminance
            return bytes(output)
        if fmt_name == 'XBOX_A4R4G4B4':
            output = bytearray(width * height * 2)
            for y in range(height):
                for x in range(width):
                    r, g, b, a = pixels[x, y]
                    value = (round(a / 17) << 12) | (round(r / 17) << 8) | (round(g / 17) << 4) | round(b / 17)
                    offset = self._xbox_morton_index(x, y, width, height) * 2
                    struct.pack_into('<H', output, offset, value)
            return bytes(output)

        block_size = 8 if fmt_name == 'XBOX_DXT1' else 16
        blocks_wide = max(1, (width + 3) // 4)
        blocks_high = max(1, (height + 3) // 4)
        output = bytearray(blocks_wide * blocks_high * block_size)
        for block_y in range(blocks_high):
            for block_x in range(blocks_wide):
                block_pixels = []
                for py in range(4):
                    for px in range(4):
                        x = min(width - 1, block_x * 4 + px)
                        y = min(height - 1, block_y * 4 + py)
                        block_pixels.append(pixels[x, y])
                alpha_mode = 'dxt3' if fmt_name == 'XBOX_DXT3' else ('dxt5' if fmt_name == 'XBOX_DXT5' else None)
                encoded = self._encode_xbox_dxt_block(block_pixels, alpha_mode)
                offset = (block_y * blocks_wide + block_x) * block_size
                output[offset:offset + block_size] = encoded
        return bytes(output)

    def _encode_xbox_texture_image(self, source_image, info, original_resource_data):
        if info['format'].startswith('XBOX_LIN_'):
            encoded = self._encode_xbox_texture_level(source_image, info['format'], info['width'], info['height'])
            if len(encoded) != len(original_resource_data):
                return None
            return encoded
        layout, used_size = self._texture_mip_layout(
            info['format'], info['width'], info['height'], len(original_resource_data)
        )
        if not layout:
            return None
        output = bytearray()
        for width, height, _offset, expected_size in layout[:info.get('mip_count', len(layout))]:
            encoded = self._encode_xbox_texture_level(source_image, info['format'], width, height)
            if len(encoded) != expected_size:
                return None
            output.extend(encoded)
        if len(output) < len(original_resource_data):
            output.extend(original_resource_data[len(output):])
        return bytes(output)

    def _extract_texture_png(self, resource_entry, resource_data, output_path):
        if not HAS_PIL:
            print(f"    Texture PNG skipped for {resource_entry.get('name')}: Pillow is not installed")
            return
        main_entry = self._texture_main_entry_for_resource(resource_entry)
        if not main_entry or main_entry.get('size', 0) <= 0:
            return
        main_data = self.read_bytes(main_entry['offset'], main_entry['size'])
        info = self._texture_info_from_main_data(main_data, len(resource_data))
        info = self._texture_info_with_name_hint(info, main_entry.get('name'))
        if not info:
            return
        base_size = self._texture_block_size(info['format'], info['width'], info['height'])
        if len(resource_data) < base_size:
            return
        if info.get('platform') == 'ps2':
            image = self._decode_ps2_texture_image(resource_data, info, main_entry)
        elif info.get('platform') == 'xbox':
            image = self._decode_xbox_texture_image(resource_data, info)
        else:
            image = self._decode_texture_image(resource_data[:base_size], info['format'], info['width'], info['height'])
        if not image:
            return
        if info.get('intensity_as_alpha'):
            intensity = image.getchannel('R')
            image.putalpha(intensity)
        png_path = output_path[:-9] + '.png' if output_path.lower().endswith('.resource') else output_path + '.png'
        image.save(png_path)
        try:
            resource_mtime = os.path.getmtime(output_path)
            os.utime(png_path, (resource_mtime, resource_mtime))
        except OSError:
            pass
        print(f"    Texture PNG: {os.path.basename(png_path)} ({info['format']} {info['width']}x{info['height']})")

    def _find_texture_png_replacement(self, replacement_dir, resource_entry, main_entry=None):
        if not replacement_dir or not os.path.isdir(replacement_dir):
            return None, None
        candidates = []
        for name in resource_entry.get('replacement_names', [resource_entry['name']]):
            if name.lower().endswith('.resource'):
                candidates.append(name[:-9] + '.png')
            candidates.append(name + '.png')
        if main_entry:
            for name in main_entry.get('replacement_names', [main_entry.get('name', '')]):
                if name:
                    candidates.append(name + '.png')
        seen = set()
        for candidate in candidates:
            if not candidate or candidate.lower() in seen:
                continue
            seen.add(candidate.lower())
            path, actual_name = self.find_replacement_file(replacement_dir, candidate)
            if path:
                return path, actual_name
        return None, None

    def _texture_png_should_override_resource(self, png_path, resource_path):
        if not png_path:
            return False
        if not resource_path:
            return True
        try:
            return os.path.getmtime(png_path) > os.path.getmtime(resource_path)
        except OSError:
            return True

    def _build_texture_resource_from_png(self, png_path, main_entry, resource_entry, original_resource_data):
        if not HAS_PIL:
            print(f"      WARNING CRITICAL: Cannot encode {png_path}; Pillow is not installed")
            return None
        main_data = self.read_bytes(main_entry['offset'], main_entry['size'])
        info = self._texture_info_from_main_data(main_data, len(original_resource_data))
        info = self._texture_info_with_name_hint(info, main_entry.get('name'))
        if not info:
            print(f"      WARNING CRITICAL: Could not read texture metadata for {resource_entry.get('name')}")
            return None
        source_image = Image.open(png_path).convert('RGBA')
        if info.get('platform') == 'ps2':
            encoded = self._encode_ps2_texture_image(source_image, info, main_entry, original_resource_data)
            if encoded is None:
                print(f"      WARNING CRITICAL: Could not encode PS2 {info['format']} texture for {resource_entry.get('name')}")
                return None
            if len(encoded) != len(original_resource_data):
                print(
                    f"      WARNING CRITICAL: Encoded PS2 texture size changed "
                    f"({len(encoded)} vs original {len(original_resource_data)})"
                )
                return None
            print(
                f"      PNG texture encoded: {os.path.basename(png_path)} -> "
                f"{info['format']} {info['width']}x{info['height']}"
            )
            return encoded
        if info.get('platform') == 'xbox':
            encoded = self._encode_xbox_texture_image(source_image, info, original_resource_data)
            if encoded is None or len(encoded) != len(original_resource_data):
                encoded_size = len(encoded) if encoded is not None else 0
                print(
                    f"      WARNING CRITICAL: Encoded Xbox texture size changed "
                    f"({encoded_size} vs original {len(original_resource_data)})"
                )
                return None
            print(
                f"      PNG texture encoded: {os.path.basename(png_path)} -> "
                f"{info['format']} {info['width']}x{info['height']} with {info.get('mip_count', 1)} mip level(s)"
            )
            return encoded
        layout, used_size = self._texture_mip_layout(info['format'], info['width'], info['height'], len(original_resource_data))
        if not layout:
            print(f"      WARNING CRITICAL: Could not infer mip layout for {resource_entry.get('name')}")
            return None
        new_data = bytearray()
        for width, height, _offset, _size in layout:
            new_data.extend(self._encode_texture_image(
                source_image,
                info['format'],
                width,
                height,
                intensity_as_alpha=bool(info.get('intensity_as_alpha')),
            ))
        if used_size < len(original_resource_data):
            new_data.extend(original_resource_data[used_size:])
            print(f"      Info: Preserved {len(original_resource_data) - used_size} trailing texture byte(s)")
        print(
            f"      PNG texture encoded: {os.path.basename(png_path)} -> "
            f"{info['format']} {info['width']}x{info['height']} with {len(layout)} mip level(s)"
        )
        return bytes(new_data)

    def get_alignment_for_type(self, file_type, detected_alignment, is_resource=False):
        """Get appropriate alignment for file type, with CMG/CMP-specific handling"""

        # Check if custom alignments were provided (from GUI)
        if hasattr(self, 'custom_alignments') and file_type in self.custom_alignments:
            return self.custom_alignments[file_type]

        detected_by_type = (
            getattr(self, 'detected_resource_alignments_by_type', {})
            if is_resource
            else getattr(self, 'detected_main_alignments_by_type', {})
        )
        if file_type in detected_by_type:
            return detected_by_type[file_type]

        # Check if we're rebuilding a CMG or CMP bundle
        ext = os.path.splitext(self.filepath.lower())[1]
        is_cmg = ext == ".cmg"
        is_cmp = ext == ".cmp"
        is_clp = ext in (".clp", ".clf")
        is_bdp = ext == ".bdp"
        is_bsf = ext == ".bsf"
        is_bdl = ext == ".bdl"
        is_ccg = ext == ".ccg"
        is_cmf = ext in (".cmf", ".ccf")

        if is_cmg or is_ccg:
            # CMG/CCG-specific (DAMM/GameCube)
            type_alignments = {
                0: 64,    # Static Mesh
                2: 16,    # MONSTER_DATA (Stats/Config)
                6: 16,    # Material
                9: 64,    # Texture
                13: 16,   # Palette
                17: 64,   # Rigged Mesh
                20: 16,   # Particle
            }
        elif is_cmf:
            # CMF/CCF-specific (Xbox DAMM)
            type_alignments = {
                0: 64,    # Static Mesh
                2: 16,    # MONSTER_DATA (Stats/Config)
                6: 16,    # Material
                9: 64,    # Texture
                13: 16,   # Palette
                17: 64,   # Rigged Mesh
                20: 16,   # Particle
            }
        elif is_cmp or is_bdp or is_bdl or is_clp or is_bsf:
            # PS2/Xbox Specific (CMP/BDP/BDL/CLP/BSF)
            type_alignments = {
                0: 128,    # Static Mesh
                6: 16,    # Material
                9: 64,   # Texture
                13: 16,   # Palette
                17: 128,   # Rigged Mesh
                20: 16,   # Particle
            }
        else:
            # BDG / UNLEASHED (WII)
            type_alignments = {
                0: 512,   # Static Mesh
                6: 16,    # Material
                9: 128,   # Texture
                13: 16,   # Palette
                17: 512,  # Rigged Mesh
                20: 16,   # Particle
            }

        return type_alignments.get(file_type, detected_alignment)

    def _slot_capacity_map(self, entries, block_size):
        """Return original per-file slot capacities within a data block."""
        usable_entries = sorted(
            [
                entry for entry in (entries or [])
                if entry.get('raw_offset') is not None and entry.get('size', 0) >= 0
            ],
            key=lambda entry: entry['raw_offset']
        )
        capacities = {}
        for index, entry in enumerate(usable_entries):
            start = entry['raw_offset']
            if index + 1 < len(usable_entries):
                end = usable_entries[index + 1]['raw_offset']
            else:
                end = block_size
            capacities[entry['file_num']] = max(0, end - start)
        return capacities

    def _try_rebuild_preserving_slots(
        self,
        output_bdg_path,
        header_and_toc,
        toc_entry_count,
        file_data_map,
        replacement_dir,
        edited_entries,
        rename_rules,
        endian,
    ):
        """Patch replacements into their original slots when every changed file fits."""
        if len(header_and_toc) != self.main_data_offset:
            return False

        main_block_size = max(0, self.resource_data_offset - self.main_data_offset)
        resource_block_size = max(0, len(self.file_data) - self.resource_data_offset)
        main_entries = [
            info.get('main')
            for info in file_data_map.values()
            if info and info.get('main') and not info['main'].get('is_new_file')
        ]
        resource_entries = [
            info.get('resource')
            for info in file_data_map.values()
            if info and info.get('resource') and not info['resource'].get('is_new_file')
        ]
        main_capacities = self._slot_capacity_map(main_entries, main_block_size)
        resource_capacities = self._slot_capacity_map(resource_entries, resource_block_size)

        output_data = bytearray(self.file_data)
        output_data[:len(header_and_toc)] = header_and_toc
        written_file_data = {}

        print("\nTrying slot-preserving rebuild (QuickBMS-style offsets)...")
        for i in range(toc_entry_count):
            toc_offset = 0x78 + (i * 0x12)
            if edited_entries or i >= self.file_count:
                file_num = struct.unpack_from(f'{endian}H', header_and_toc, toc_offset)[0]
            else:
                file_num = self.read_short(toc_offset)

            if file_num in written_file_data:
                cached = written_file_data[file_num]
                struct.pack_into(f'{endian}I', output_data, toc_offset + 2, cached['main_offset'])
                struct.pack_into(f'{endian}I', output_data, toc_offset + 6, cached['main_size'])
                struct.pack_into(f'{endian}I', output_data, toc_offset + 10, cached['res_offset'])
                struct.pack_into(f'{endian}I', output_data, toc_offset + 14, cached['res_size'])
                continue

            file_info = file_data_map.get(file_num, {'main': None, 'resource': None})
            main_offset = 0
            main_size = 0
            res_offset = 0
            res_size = 0

            if file_info.get('main'):
                entry = file_info['main']
                replacement_path = None
                actual_name = None
                for candidate_name in entry.get('replacement_names', [entry['name']]):
                    replacement_path, actual_name = self.find_replacement_file(replacement_dir, candidate_name)
                    if replacement_path:
                        break

                if replacement_path:
                    file_data = self.read_replacement_file(replacement_path)
                    original_data = self.read_bytes(entry['offset'], entry['size'])
                    if entry['file_type'] == 9:
                        issues, warnings = self.validate_texture_replacement(original_data, file_data, entry['name'])
                        for issue in issues:
                            print(f"    WARNING CRITICAL: {issue}")
                        for warning in warnings:
                            print(f"    Info: {warning}")
                    file_display = entry['name'] if actual_name == entry['name'] else f"{entry['name']} -> {actual_name}"
                    print(f"  File {file_num} ({file_display}): slot-preserve replacement, size {len(file_data)}")
                else:
                    file_data = self.read_bytes(entry['offset'], entry['size'])
                    if edited_entries and rename_rules and entry['file_type'] == 2:
                        file_data, patch_count, patch_warnings = self._patch_fixed_strings_with_rename_rules(file_data, rename_rules)
                        if patch_count:
                            print(f"  File {file_num} ({entry['name']}): Patched {patch_count} fixed string(s) with rename rules")
                        for warning in patch_warnings:
                            print(f"    Warning: {warning}")

                capacity = main_capacities.get(file_num, entry['size'])
                if len(file_data) > capacity:
                    print(
                        f"  Slot preserve skipped: file {file_num} needs {len(file_data)} bytes "
                        f"but original slot has {capacity}"
                    )
                    return False

                main_offset = entry['raw_offset']
                main_size = len(file_data)
                output_data[entry['offset']:entry['offset'] + len(file_data)] = file_data
                old_end = entry['offset'] + entry['size']
                new_end = entry['offset'] + len(file_data)
                if new_end < old_end:
                    output_data[new_end:old_end] = b'\x00' * (old_end - new_end)

            if file_info.get('resource'):
                entry = file_info['resource']
                replacement_path = None
                res_actual_name = None
                for candidate_name in entry.get('replacement_names', [entry['name']]):
                    replacement_path, res_actual_name = self.find_replacement_file(replacement_dir, candidate_name)
                    if replacement_path:
                        break

                original_data = self.read_bytes(entry['offset'], entry['size'])
                pending_palette_data = self._pending_ps2_palette_resource_for_entry(entry) if entry.get('file_type') == 13 else None
                png_path, png_actual_name = (None, None)
                if entry.get('file_type') == 9 and file_info.get('main'):
                    png_path, png_actual_name = self._find_texture_png_replacement(
                        replacement_dir,
                        entry,
                        file_info.get('main')
                    )
                use_png = self._texture_png_should_override_resource(png_path, replacement_path)

                if pending_palette_data is not None:
                    resource_data = pending_palette_data
                    res_info = entry['name']
                    print(f"    Resource ({res_info}): generated PS2 palette replacement, size {len(resource_data)}")
                elif use_png:
                    encoded_data = self._build_texture_resource_from_png(
                        png_path,
                        file_info['main'],
                        entry,
                        original_data
                    )
                    if encoded_data is None:
                        return False
                    resource_data = encoded_data
                    res_info = entry['name'] if png_actual_name == entry['name'] else f"{entry['name']} -> {png_actual_name}"
                    source_note = "newer PNG replacement" if replacement_path else "PNG replacement"
                    print(f"    Resource ({res_info}): slot-preserve {source_note}, size {len(resource_data)}")
                elif replacement_path:
                    resource_data = self.read_replacement_file(replacement_path)
                    if entry['file_type'] == 9:
                        issues, warnings = self.validate_texture_replacement(original_data, resource_data, entry['name'])
                        for issue in issues:
                            print(f"      WARNING CRITICAL: {issue}")
                        for warning in warnings:
                            print(f"      Info: {warning}")
                    res_info = entry['name'] if res_actual_name == entry['name'] else f"{entry['name']} -> {res_actual_name}"
                    print(f"    Resource ({res_info}): slot-preserve replacement, size {len(resource_data)}")
                else:
                    resource_data = original_data

                capacity = resource_capacities.get(file_num, entry['size'])
                if len(resource_data) > capacity:
                    print(
                        f"  Slot preserve skipped: resource {file_num} needs {len(resource_data)} bytes "
                        f"but original slot has {capacity}"
                    )
                    return False

                res_offset = entry['raw_offset']
                res_size = len(resource_data)
                output_data[entry['offset']:entry['offset'] + len(resource_data)] = resource_data
                old_end = entry['offset'] + entry['size']
                new_end = entry['offset'] + len(resource_data)
                if new_end < old_end:
                    output_data[new_end:old_end] = b'\x00' * (old_end - new_end)

            written_file_data[file_num] = {
                'main_offset': main_offset,
                'main_size': main_size,
                'res_offset': res_offset,
                'res_size': res_size,
            }
            struct.pack_into(f'{endian}I', output_data, toc_offset + 2, main_offset)
            struct.pack_into(f'{endian}I', output_data, toc_offset + 6, main_size)
            struct.pack_into(f'{endian}I', output_data, toc_offset + 10, res_offset)
            struct.pack_into(f'{endian}I', output_data, toc_offset + 14, res_size)

        with open(output_bdg_path, 'wb') as f:
            f.write(output_data)
        print("Slot-preserving rebuild complete with original offsets and padding kept")
        return True

    def rebuild_bdg(self, output_bdg_path, file_entries, replacement_dir, custom_alignments=None, new_file_paths=None, renamed_files=None, rename_rules=None):
        """Rebuild BDG file with replacements, insertions, or rename edits."""
        try:
            if renamed_files and new_file_paths:
                print("Error: Rename saves cannot be combined with Add New Files. Save renames separately.")
                return False
            rename_rules = rename_rules or []

            # Store custom alignments for use in get_alignment_for_type
            self.custom_alignments = custom_alignments if custom_alignments else {}
            self._pending_ps2_palette_replacements = {}

            # Create a mutable copy of file_data
            new_data = bytearray(self.file_data)

            # First, get ALL files from the archive
            all_files = self.parse()

            # Detect alignment from original file structure
            main_files = [f for f in all_files if not f['is_resource']]
            resource_files = [f for f in all_files if f['is_resource']]

            detected_main_alignment = self.detect_alignment(sorted(main_files, key=lambda x: x['raw_offset']))
            detected_resource_alignment = self.detect_alignment(sorted(resource_files, key=lambda x: x['raw_offset'])) if resource_files else 16
            self.detected_main_alignments_by_type = self.detect_alignments_by_type(main_files)
            self.detected_resource_alignments_by_type = self.detect_alignments_by_type(resource_files)

            print(f"Detected base alignment - Main: {detected_main_alignment} bytes, Resource: {detected_resource_alignment} bytes")
            if self.detected_main_alignments_by_type:
                detected_summary = ", ".join(
                    f"type {file_type}: {alignment}"
                    for file_type, alignment in sorted(self.detected_main_alignments_by_type.items())
                )
                print(f"Detected main alignment by type - {detected_summary}")
            if self.detected_resource_alignments_by_type:
                detected_summary = ", ".join(
                    f"type {file_type}: {alignment}"
                    for file_type, alignment in sorted(self.detected_resource_alignments_by_type.items())
                )
                print(f"Detected resource alignment by type - {detected_summary}")

            # Build a map of file_num to actual file data entries
            file_data_map = {}
            for entry in all_files:
                file_num = entry['file_num']
                if file_num not in file_data_map:
                    file_data_map[file_num] = {'main': None, 'resource': None}

                if entry['is_resource']:
                    # Keep entry with largest size (handles dummy entries with size=0)
                    if file_data_map[file_num]['resource'] is None or entry['size'] > file_data_map[file_num]['resource']['size']:
                        file_data_map[file_num]['resource'] = entry
                else:
                    # Keep entry with largest size (handles dummy entries with size=0)
                    if file_data_map[file_num]['main'] is None or entry['size'] > file_data_map[file_num]['main']['size']:
                        file_data_map[file_num]['main'] = entry

            new_records = self._make_new_file_records(
                new_file_paths,
                existing_names=[entry['name'] for entry in all_files],
                vol=False
            )
            if new_file_paths and not new_records:
                print("Error: No new Pipeworks files could be safely inserted.")
                return False
            has_requested_insert_indexes = any(record.get('insert_index') is not None for record in new_records)
            index_remap = {}
            embedded_reference_changes = []

            renamed_files = {
                int(file_num): os.path.basename(str(name).replace('\\', '/')).replace('|', '_')
                for file_num, name in (renamed_files or {}).items()
                if str(name).strip()
            }
            protected_cmp_string_ids = set()
            protected_cmp_file_nums = set()
            if renamed_files and os.path.splitext(self.filepath)[1].lower() == '.cmp':
                # PS2 CMP render/model resources use these string IDs as exact internal
                # lookup keys. Some IDs are shared with animation rows, so protect by
                # string ID first and then skip every file row that points at one.
                cmp_render_types = {3, 9, 13, 16, 17, 21}
                for entry in main_files:
                    metadata_bytes = bytearray(entry.get('metadata_bytes') or b'\x00' * 0x10)
                    if len(metadata_bytes) < 0x10:
                        metadata_bytes.extend(b'\x00' * (0x10 - len(metadata_bytes)))
                    string_id = struct.unpack_from(
                        ('>' if self.is_big_endian else '<') + 'I',
                        metadata_bytes,
                        4
                    )[0]
                    if entry.get('file_type') in cmp_render_types:
                        protected_cmp_string_ids.add(string_id)

                for entry in main_files:
                    metadata_bytes = bytearray(entry.get('metadata_bytes') or b'\x00' * 0x10)
                    if len(metadata_bytes) < 0x10:
                        metadata_bytes.extend(b'\x00' * (0x10 - len(metadata_bytes)))
                    string_id = struct.unpack_from(
                        ('>' if self.is_big_endian else '<') + 'I',
                        metadata_bytes,
                        4
                    )[0]
                    if string_id in protected_cmp_string_ids:
                        protected_cmp_file_nums.add(entry['file_num'])

                skipped_renames = sorted(file_num for file_num in renamed_files if file_num in protected_cmp_file_nums)
                if skipped_renames:
                    for file_num in skipped_renames:
                        print(f"  CMP safe rename: skipped render-critical file {file_num}")
                        renamed_files.pop(file_num, None)
            extra_string_values = list(getattr(self, '_extra_string_values', []) or [])
            edited_entries = bool(renamed_files or extra_string_values)

            # Get the actual TOC entry count from header (not the parsed entries which splits main/resource)
            toc_start = 0x78

            # Determine endianness format
            endian = '>' if self.is_big_endian else '<'

            if edited_entries:
                final_entries = []
                edited_file_data_map = {}
                original_names = {}

                print(f"\nApplying entry/string-table edits...")
                if renamed_files:
                    print(f"  Renaming {len(renamed_files)} file(s)")
                if extra_string_values:
                    print(f"  Appending {len(extra_string_values)} string table value(s)")

                for i in range(self.file_count):
                    toc_offset = toc_start + (i * 0x12)
                    old_file_num = self.read_short(toc_offset)

                    file_info = file_data_map.get(old_file_num)
                    if not file_info or not file_info.get('main'):
                        print(f"  Warning: TOC entry {i} references missing file_num {old_file_num}; skipping")
                        continue

                    main_entry = file_info['main']
                    file_type = main_entry['file_type']
                    original_name = main_entry['name']
                    original_names[old_file_num] = original_name
                    original_filename = original_name.split('/')[-1]
                    renamed_filename = renamed_files.get(old_file_num)
                    output_filename = renamed_filename or original_filename
                    output_name = f"{file_type}/{output_filename}"

                    metadata_bytes = bytearray(main_entry.get('metadata_bytes') or b'\x00' * 0x10)
                    if len(metadata_bytes) < 0x10:
                        metadata_bytes.extend(b'\x00' * (0x10 - len(metadata_bytes)))
                    string_id = struct.unpack_from(f'{endian}I', metadata_bytes, 4)[0]

                    final_entries.append({
                        'file_num': old_file_num,
                        'file_type': file_type,
                        'filename': output_filename,
                        'string_id': string_id,
                        'metadata_bytes': bytes(metadata_bytes[:0x10]),
                        'append_string': False,
                        'replace_string': renamed_filename is not None,
                    })

                    new_main = dict(main_entry)
                    new_main['original_file_num'] = old_file_num
                    new_main['file_num'] = old_file_num
                    new_main['name'] = output_name
                    new_main['original_name'] = original_name
                    new_main['replacement_names'] = [output_name, original_name] if output_name != original_name else [original_name]

                    new_resource = None
                    if file_info.get('resource'):
                        new_resource = dict(file_info['resource'])
                        new_resource['original_file_num'] = old_file_num
                        new_resource['file_num'] = old_file_num
                        original_resource_name = new_resource['name']
                        output_resource_name = f"{output_name}.resource"
                        new_resource['name'] = output_resource_name
                        new_resource['original_name'] = original_resource_name
                        new_resource['replacement_names'] = (
                            [output_resource_name, original_resource_name]
                            if output_resource_name != original_resource_name
                            else [original_resource_name]
                        )

                    edited_file_data_map[old_file_num] = {'main': new_main, 'resource': new_resource}
                    if renamed_filename is not None:
                        print(f"  Renamed file {old_file_num}: {original_name} -> {output_name}")

                if not final_entries:
                    print("Error: Rename rebuild would create an empty Pipeworks bundle.")
                    return False

                header_and_toc, toc_entry_count, header_size = self._build_pipeworks_header_for_entry_edits(
                    final_entries,
                    endian,
                    preserve_metadata_count=True,
                    rename_rules=rename_rules
                )
                file_data_map = edited_file_data_map
                print(f"Rename output file count: {toc_entry_count}")

                if not replacement_dir and header_size == self.main_data_offset:
                    output_data = bytearray(self.file_data)
                    output_data[:header_size] = header_and_toc
                    print("Rename-only save: preserving original data layout and ToC offsets")

                    if rename_rules:
                        for file_num, file_info in sorted(file_data_map.items()):
                            entry = file_info.get('main') if file_info else None
                            if not entry or entry.get('file_type') != 2:
                                continue
                            start = entry['offset']
                            end = start + entry['size']
                            patched_data, patch_count, patch_warnings = self._patch_fixed_strings_with_rename_rules(
                                bytes(output_data[start:end]),
                                rename_rules
                            )
                            if patch_count:
                                output_data[start:end] = patched_data
                                print(f"  File {file_num} ({entry['name']}): Patched {patch_count} fixed string(s) with rename rules")
                            for warning in patch_warnings:
                                print(f"    Warning: {warning}")

                    with open(output_bdg_path, 'wb') as f:
                        f.write(output_data)
                    print("Rename-only save complete with original offsets preserved")
                    return True
            elif new_records:
                if has_requested_insert_indexes:
                    header_and_toc, toc_entry_count, header_size, old_to_new, new_file_indexes, shifted_ranges = (
                        self._build_pipeworks_header_for_name_id_insertions(new_records, endian)
                    )
                    index_remap = {
                        old_index: new_index
                        for old_index, new_index in old_to_new.items()
                        if old_index != new_index
                    }
                    rebuilt_file_data_map = {}
                    for old_file_num, file_info in file_data_map.items():
                        new_main = dict(file_info['main']) if file_info.get('main') else None
                        new_resource = dict(file_info['resource']) if file_info.get('resource') else None
                        if new_main:
                            old_string_id = new_main.get('string_id', old_file_num)
                            new_main['original_file_num'] = old_file_num
                            new_main['string_id'] = old_to_new.get(old_string_id, old_string_id)
                        if new_resource:
                            old_string_id = new_resource.get('string_id', old_file_num)
                            new_resource['original_file_num'] = old_file_num
                            new_resource['string_id'] = old_to_new.get(old_string_id, old_string_id)
                        rebuilt_file_data_map[old_file_num] = {'main': new_main, 'resource': new_resource}
                    for record in new_records:
                        file_num = record['file_num']
                        rebuilt_file_data_map[file_num] = {
                            'main': {
                                'file_num': file_num,
                                'name': record['stored_name'],
                                'offset': 0,
                                'size': os.path.getsize(record['source_path']),
                                'raw_offset': 0,
                                'toc_entry_offset': toc_start + (file_num * 0x12),
                                'is_resource': False,
                                'file_type': record['file_type'],
                                'string_id': record['string_id'],
                                'metadata_bytes': None,
                                'is_new_file': True,
                                'source_path': record['source_path'],
                                'display_name': record['filename'],
                            },
                            'resource': None
                        }
                    file_data_map = rebuilt_file_data_map

                    print(f"\nAdding {len(new_records)} new file(s) to Pipeworks bundle with virtual Name ID ordering...")
                    for record in new_records:
                        target = record.get('insert_index')
                        target_text = "append" if target is None else str(target)
                        print(f"  New file: {record['filename']} -> target {target_text}, file_num {record['file_num']}, Name ID {record['string_id']}")
                    if shifted_ranges:
                        print("  Shifted Name ID ranges:")
                        for start, end, delta in shifted_ranges:
                            print(f"    old {start}-{end} -> new {start + delta}-{end + delta} (+{delta})")
                    if index_remap:
                        print("  Old Name ID to new Name ID remap:")
                        for old_index, new_index in sorted(index_remap.items()):
                            print(f"    old {old_index} -> new {new_index}")
                    for filename, new_index in sorted(new_file_indexes.items(), key=lambda item: item[1]):
                        print(f"    new {filename} -> {new_index}")
                    print("  Embedded reference patching: enabled for aligned 16/32-bit Name ID values in type-2 entries")
                else:
                    header_and_toc, toc_entry_count, header_size = self._build_pipeworks_header_for_insertions(new_records, endian)
                    for record in new_records:
                        file_num = record['file_num']
                        file_data_map[file_num] = {
                            'main': {
                                'file_num': file_num,
                                'name': record['stored_name'],
                                'offset': 0,
                                'size': os.path.getsize(record['source_path']),
                                'raw_offset': 0,
                                'toc_entry_offset': toc_start + (file_num * 0x12),
                                'is_resource': False,
                                'file_type': record['file_type'],
                                'metadata_bytes': None,
                                'is_new_file': True,
                                'source_path': record['source_path'],
                                'display_name': record['filename'],
                            },
                            'resource': None
                        }
                    print(f"\nAdding {len(new_records)} new file(s) to Pipeworks bundle...")
            else:
                # Keep header and TOC structure
                toc_entry_count = self.file_count
                header_size = self.main_data_offset
                header_and_toc = new_data[:header_size]

            # Build new data sections
            if not new_records and not extra_string_values and self._try_rebuild_preserving_slots(
                output_bdg_path,
                header_and_toc,
                toc_entry_count,
                file_data_map,
                replacement_dir,
                edited_entries,
                rename_rules,
                endian,
            ):
                return True

            print("Falling back to repacked rebuild layout")
            new_file_data = bytearray()
            new_resource_data = bytearray()

            # Track data that has already been written (to avoid writing duplicate file_num data multiple times)
            written_file_data = {}  # file_num -> {'main_offset': ..., 'main_size': ..., 'res_offset': ..., 'res_size': ...}

            # Process ALL TOC entries in order by reading directly from the original TOC
            print(f"\nRebuilding {toc_entry_count} TOC entries (referencing {len(file_data_map)} unique file_nums)...")
            for i in range(toc_entry_count):
                toc_offset = toc_start + (i * 0x12)

                # Read original TOC entry
                if edited_entries or (new_records and has_requested_insert_indexes):
                    file_num = struct.unpack_from(f'{endian}H', header_and_toc, toc_offset)[0]
                elif i < self.file_count:
                    file_num = self.read_short(toc_offset)
                else:
                    file_num = struct.unpack_from(f'{endian}H', header_and_toc, toc_offset)[0]

                # Get the actual file data for this file_num
                file_info = file_data_map.get(file_num, {'main': None, 'resource': None})

                # Check if we've already written this file_num's data
                if file_num in written_file_data:
                    # Reuse offsets from when we first wrote this file_num
                    cached = written_file_data[file_num]
                    main_offset = cached['main_offset']
                    main_size = cached['main_size']
                    res_offset = cached['res_offset']
                    res_size = cached['res_size']

                    print(f"  TOC entry at 0x{toc_offset:X} (file_num={file_num}): Reusing previously written data")
                else:
                    # First time seeing this file_num, process and write the file data
                    main_offset = 0
                    main_size = 0
                    if file_info['main']:
                        entry = file_info['main']

                        # Get appropriate alignment for this file type
                        file_alignment = self.get_alignment_for_type(entry['file_type'], detected_main_alignment, is_resource=False)

                        if entry.get('is_new_file'):
                            replacement_path = entry['source_path']
                            actual_name = entry.get('display_name', os.path.basename(replacement_path))
                        else:
                            # Look for replacement file (exact filename match only)
                            replacement_path = None
                            actual_name = None
                            for candidate_name in entry.get('replacement_names', [entry['name']]):
                                replacement_path, actual_name = self.find_replacement_file(replacement_dir, candidate_name)
                                if replacement_path:
                                    break

                        if replacement_path and entry.get('is_new_file'):
                            file_data = self.read_replacement_file(replacement_path)
                            print(f"  File {file_num} ({entry['name']}): Inserting new file, type {entry['file_type']}, size {len(file_data)}, align {file_alignment}")
                        elif replacement_path:
                            file_data = self.read_replacement_file(replacement_path)
                            original_data = self.read_bytes(entry['offset'], entry['size'])

                            size_changed = len(file_data) != entry['size']
                            issues = []
                            warnings = []

                            if entry['file_type'] == 9:  # Texture
                                issues, warnings = self.validate_texture_replacement(original_data, file_data, entry['name'])

                            status = "replacement" if size_changed else "replacement (same size)"
                            file_display = entry['name'] if actual_name == entry['name'] else f"{entry['name']} -> {actual_name}"
                            print(f"  File {file_num} ({file_display}): Using {status}, size {len(file_data)}, align {file_alignment}")
                            for issue in issues:
                                print(f"    WARNING CRITICAL: {issue}")
                            for warning in warnings:
                                print(f"    Info: {warning}")
                        else:
                            file_data = self.read_bytes(entry['offset'], entry['size'])
                            if edited_entries and rename_rules and entry['file_type'] == 2:
                                patched_data, patch_count, patch_warnings = self._patch_fixed_strings_with_rename_rules(file_data, rename_rules)
                                if patch_count:
                                    file_data = patched_data
                                    print(f"  File {file_num} ({entry['name']}): Patched {patch_count} fixed string(s) with rename rules")
                                for warning in patch_warnings:
                                    print(f"    Warning: {warning}")
                            print(f"  File {file_num} ({entry['name']}): Using original, size {len(file_data)}, align {file_alignment}")

                        if index_remap and entry['file_type'] == 2 and not entry.get('is_new_file'):
                            patched_data, ref_changes = self._patch_embedded_index_references(
                                file_data,
                                index_remap,
                                endian,
                                file_num,
                                entry['name']
                            )
                            if ref_changes:
                                file_data = patched_data
                                embedded_reference_changes.extend(ref_changes)
                                print(f"  File {file_num} ({entry['name']}): Patched {len(ref_changes)} embedded Name ID reference(s)")

                        # Calculate new offset with proper alignment
                        current_pos = len(new_file_data)
                        if current_pos > 0:
                            # Apply alignment padding based on file type
                            padding = (file_alignment - (current_pos % file_alignment)) % file_alignment
                            if padding > 0:
                                new_file_data.extend(b'\x00' * padding)

                        main_offset = len(new_file_data)
                        main_size = len(file_data)

                        # Add file data
                        new_file_data.extend(file_data)
                        if entry.get('is_new_file'):
                            name_id_text = entry.get('string_id', file_num)
                            print(f"    Inserted new file: filename={entry.get('display_name', entry['name'])}, file_num={file_num}, Name ID={name_id_text}, type={entry['file_type']}, size={main_size}, offset={main_offset}, alignment={file_alignment}")

                    # Process resource file
                    res_offset = 0
                    res_size = 0
                    if file_info['resource']:
                        entry = file_info['resource']

                        # Resources typically use the same alignment as their parent file type
                        resource_alignment = self.get_alignment_for_type(entry['file_type'], detected_resource_alignment, is_resource=True)

                        # Look for replacement file (exact filename match only)
                        replacement_path = None
                        res_actual_name = None
                        for candidate_name in entry.get('replacement_names', [entry['name']]):
                            replacement_path, res_actual_name = self.find_replacement_file(replacement_dir, candidate_name)
                            if replacement_path:
                                break

                        original_data = self.read_bytes(entry['offset'], entry['size'])
                        pending_palette_data = self._pending_ps2_palette_resource_for_entry(entry) if entry.get('file_type') == 13 else None
                        png_path, png_actual_name = (None, None)
                        if entry.get('file_type') == 9 and file_info.get('main'):
                            png_path, png_actual_name = self._find_texture_png_replacement(
                                replacement_dir,
                                entry,
                                file_info.get('main')
                            )
                        use_png = self._texture_png_should_override_resource(png_path, replacement_path)

                        if pending_palette_data is not None:
                            resource_data = pending_palette_data
                            size_changed = len(resource_data) != entry['size']
                            status = "generated PS2 palette replacement"
                            if not size_changed:
                                status += " (same size)"
                            print(f"    Resource ({entry['name']}): Using {status}, size {len(resource_data)}, align {resource_alignment}")
                        elif use_png:
                            encoded_data = self._build_texture_resource_from_png(
                                png_path,
                                file_info['main'],
                                entry,
                                original_data
                            )
                            if encoded_data is None:
                                return False
                            resource_data = encoded_data
                            size_changed = len(resource_data) != entry['size']
                            status = "newer PNG replacement" if replacement_path else "PNG replacement"
                            if not size_changed:
                                status += " (same size)"
                            res_info = entry['name'] if png_actual_name == entry['name'] else f"{entry['name']} -> {png_actual_name}"
                            print(f"    Resource ({res_info}): Using {status}, size {len(resource_data)}, align {resource_alignment}")
                        elif replacement_path:
                            resource_data = self.read_replacement_file(replacement_path)

                            size_changed = len(resource_data) != entry['size']
                            issues = []
                            warnings = []

                            if entry['file_type'] == 9:  # Texture resource (likely mipmaps)
                                issues, warnings = self.validate_texture_replacement(original_data, resource_data, entry['name'])

                            status = "replacement" if size_changed else "replacement (same size)"
                            res_info = entry['name'] if res_actual_name == entry['name'] else f"{entry['name']} -> {res_actual_name}"
                            print(f"    Resource ({res_info}): Using {status}, size {len(resource_data)}, align {resource_alignment}")
                            for issue in issues:
                                print(f"      WARNING CRITICAL: {issue}")
                            for warning in warnings:
                                print(f"      Info: {warning}")
                        else:
                            resource_data = original_data
                            print(f"    Resource: Using original, size {len(resource_data)}, align {resource_alignment}")

                        # Calculate new offset with proper alignment
                        current_pos = len(new_resource_data)
                        if current_pos > 0:
                            # Apply alignment padding based on file type
                            padding = (resource_alignment - (current_pos % resource_alignment)) % resource_alignment
                            if padding > 0:
                                new_resource_data.extend(b'\x00' * padding)

                        res_offset = len(new_resource_data)
                        res_size = len(resource_data)

                        # Add resource data
                        new_resource_data.extend(resource_data)

                    # Cache the written data for this file_num
                    written_file_data[file_num] = {
                        'main_offset': main_offset,
                        'main_size': main_size,
                        'res_offset': res_offset,
                        'res_size': res_size
                    }

                # Write TOC entry (whether new data or cached)
                # TOC entry structure (18 bytes):
                # +0: file_num (2 bytes) - keep original
                # +2: main_offset (4 bytes)
                # +6: main_size (4 bytes)
                # +10: resource_offset (4 bytes)
                # +14: resource_size (4 bytes)

                print(f"    Writing TOC at 0x{toc_offset:X}: offset={main_offset}, size={main_size}, res_offset={res_offset}, res_size={res_size}")

                struct.pack_into(f'{endian}I', header_and_toc, toc_offset + 2, main_offset)
                struct.pack_into(f'{endian}I', header_and_toc, toc_offset + 6, main_size)
                struct.pack_into(f'{endian}I', header_and_toc, toc_offset + 10, res_offset)
                struct.pack_into(f'{endian}I', header_and_toc, toc_offset + 14, res_size)

                # Verify what we wrote
                verify_offset = struct.unpack_from(f'{endian}I', header_and_toc, toc_offset + 2)[0]
                verify_size = struct.unpack_from(f'{endian}I', header_and_toc, toc_offset + 6)[0]
                print(f"    Verified TOC: offset={verify_offset}, size={verify_size}")

            unpadded_main_data_size = len(new_file_data)

            # Add final padding to main data block to ensure resource block starts aligned
            if len(new_file_data) > 0:
                # Align to at least 2048 bytes for resource block start
                block_alignment = 2048
                padding = (block_alignment - (len(new_file_data) % block_alignment)) % block_alignment
                if padding > 0:
                    new_file_data.extend(b'\x00' * padding)
                    print(f"\nAdded {padding} bytes of padding to main data block for {block_alignment}-byte alignment")

            # Update resource block offset in header
            new_resource_block_offset = header_size + len(new_file_data)
            struct.pack_into(f'{endian}I', header_and_toc, 0x6C, unpadded_main_data_size)
            struct.pack_into(f'{endian}I', header_and_toc, 0x70, new_resource_block_offset)

            old_resource_block_bytes = struct.pack(f'{endian}I', self.resource_data_offset)
            new_resource_block_bytes = struct.pack(f'{endian}I', new_resource_block_offset)
            new_string_offset = struct.unpack_from(f'{endian}I', header_and_toc, 0x34)[0]
            header_table_end = min(new_string_offset, len(header_and_toc))
            for pos in range(0, max(0, header_table_end - 3)):
                if pos == 0x70:
                    continue
                if header_and_toc[pos:pos + 4] == old_resource_block_bytes:
                    header_and_toc[pos:pos + 4] = new_resource_block_bytes

            # Add final padding to resource data block to ensure file ends aligned
            if len(new_resource_data) > 0:
                # Align to 16 bytes for file end
                file_end_alignment = 16
                padding = (file_end_alignment - (len(new_resource_data) % file_end_alignment)) % file_end_alignment
                if padding > 0:
                    new_resource_data.extend(b'\x00' * padding)
                    print(f"Added {padding} bytes of padding to resource data block for {file_end_alignment}-byte alignment")
            struct.pack_into(f'{endian}I', header_and_toc, 0x74, len(new_resource_data))

            print(f"\nFinal structure:")
            print(f"  Header + TOC size: {header_size} (0x{header_size:X})")
            print(f"  Main data size: {len(new_file_data)} (0x{len(new_file_data):X})")
            print(f"  Resource data offset: {new_resource_block_offset} (0x{new_resource_block_offset:X})")
            print(f"  Resource data size: {len(new_resource_data)} (0x{len(new_resource_data):X})")
            print(f"  Total file size: {header_size + len(new_file_data) + len(new_resource_data)} bytes")
            if index_remap:
                if embedded_reference_changes:
                    print("  Embedded Name ID references patched:")
                    for file_num, file_name, offset, bit_width, old_value, new_value in embedded_reference_changes:
                        print(f"    file {file_num} {file_name} @0x{offset:X} u{bit_width}: {old_value} -> {new_value}")
                else:
                    print("  Warning: Name ID remap requested, but no embedded type-2 references were found/patched.")
            print(f"\nRebuild complete with proper alignment and validation\n")

            # Write new BDG file
            with open(output_bdg_path, 'wb') as f:
                f.write(header_and_toc)
                f.write(new_file_data)
                f.write(new_resource_data)

            return True

        except Exception as e:
            print(f"Error rebuilding BDG: {e}")
            import traceback
            traceback.print_exc()
            return False

    def rebuild_vol(self, output_vol_path, file_entries, replacement_dir, new_file_paths=None):
        """Rebuild VOL file with replaced files - based on VOL_Extract.BMS structure"""
        try:
            # Get all files
            all_files = self.parse()
            new_records = self._make_new_file_records(
                new_file_paths,
                existing_names=[
                    entry['name'].split('/')[-1] if '/' in entry['name'] else entry['name']
                    for entry in all_files
                ],
                vol=True
            )

            print(f"\nRebuilding VOL with {len(all_files) + len(new_records)} files...")

            # Collect file data and track info
            file_data_list = []

            for entry in all_files:
                # Look for replacement file
                replacement_path, actual_name = self.find_replacement_file(replacement_dir, entry['name'])

                if replacement_path:
                    file_data = self.read_replacement_file(replacement_path)
                    size_changed = len(file_data) != entry['size']

                    file_info = entry['name']
                    if actual_name != entry['name']:
                        file_info = f"{entry['name']} -> {actual_name}"

                    status = "replacement" if size_changed else "replacement (same size)"
                    print(f"  File {entry['file_num']} ({file_info}): {status}, size {len(file_data)}")
                else:
                    file_data = self.read_bytes(entry['offset'], entry['size'])
                    print(f"  File {entry['file_num']} ({entry['name']}): Using original, size {len(file_data)}")

                # Strip folder prefix from name when storing in VOL
                # VOL stores just the filename, not the folder structure we added
                original_name = entry['name']
                if '/' in original_name:
                    # Get just the filename part
                    stored_name = original_name.split('/')[-1]
                else:
                    stored_name = original_name

                file_data_list.append({
                    'data': file_data,
                    'name': stored_name,
                    'file_id': entry.get('file_id', entry['file_num']),
                    'file_type': entry.get('file_type', self._infer_new_file_type(stored_name)),
                    'is_new_file': False
                })

            next_file_id = max([info['file_id'] for info in file_data_list], default=-1) + 1
            for idx, record in enumerate(new_records):
                file_data = self.read_replacement_file(record['source_path'])
                file_id = next_file_id + idx
                file_data_list.append({
                    'data': file_data,
                    'name': record['stored_name'],
                    'file_id': file_id,
                    'file_type': record['file_type'],
                    'is_new_file': True
                })
                print(f"  File {file_id} ({record['stored_name']}): Inserting new file, type {record['file_type']}, size {len(file_data)}, align 16")

            # Calculate offsets - VOL structure:
            # 1. Header: 16 bytes
            # 2. TOC: 12 bytes per file (offset, size, fid)
            # 3. String offset table: 4 bytes per file
            # 4. 4-byte gap (0x00000000)
            # 5. String table: null-terminated strings
            # 6. Padding (0xFF bytes) to align file data
            # 7. File data

            header_size = 16
            toc_size = len(file_data_list) * 0xC
            string_offset_table_size = len(file_data_list) * 4

            # String table starts after: header + TOC + string offset table + 4 bytes
            # This matches BMS formula: (12 * FILES) + (4 * FILES) + 20
            string_table_start = header_size + toc_size + string_offset_table_size + 4

            if new_records:
                string_table_data = bytearray()
                string_offsets = []
                for file_info in file_data_list:
                    string_offsets.append(len(string_table_data))
                    string_table_data.extend(file_info['name'].encode('ascii', errors='replace') + b'\x00')
                side_table_values = [len(file_data_list)]
                side_table_values.extend(string_offset_table_size + 4 + offset for offset in string_offsets[:-1])
                original_string_section_size = string_offset_table_size + 4 + string_offsets[-1]
                original_string_offset_table = b''.join(struct.pack('<I', offset) for offset in side_table_values)
            else:
                # Extract ORIGINAL string offset table and string data to preserve exact structure
                # The string offset table has special values that must be preserved
                original_string_offset_table_start = 16 + (len(file_data_list) * 12)
                original_string_offset_table_size = len(file_data_list) * 4
                original_string_offset_table = self.file_data[original_string_offset_table_start:original_string_offset_table_start + original_string_offset_table_size]

                # Extract original string data (starts after offset table + 4-byte size field)
                original_string_data_start = (12 * len(file_data_list)) + (4 * len(file_data_list)) + 20
                original_datastart = struct.unpack('<I', self.file_data[0x0C:0x10])[0]
                string_table_data = bytearray(self.file_data[original_string_data_start:original_datastart])

                # Extract and preserve ORIGINAL string section size field
                original_size_field_pos = 16 + (len(file_data_list) * 12) + (len(file_data_list) * 4)
                original_string_section_size = struct.unpack('<I', self.file_data[original_size_field_pos:original_size_field_pos+4])[0]

            # String table end (this is the DATASTART value)
            string_table_end = string_table_start + len(string_table_data)

            # Get original alignment from first file offset
            original_first_file_offset = struct.unpack('<I', self.file_data[16:20])[0]

            # Use original alignment if possible, otherwise align to nearest power of 2
            if original_first_file_offset >= string_table_end:
                # Use original offset as data_start
                data_start = original_first_file_offset
            else:
                data_start = ((string_table_end + 0xF) // 0x10) * 0x10

            padding_before_data = data_start - string_table_end

            # Build output
            new_data = bytearray()

            # Build header (16 bytes):
            # 0x00-03: Magic "PVOL"
            # 0x04-07: UNK (0x1001)
            # 0x08-0B: FILES count
            # 0x0C-0F: DATASTART (end of string table)
            new_data.extend(b'PVOL')
            new_data.extend(struct.pack('<I', 0x1001))  # UNK
            new_data.extend(struct.pack('<I', len(file_data_list)))  # FILES
            new_data.extend(struct.pack('<I', string_table_end))  # DATASTART = string table end

            # Build TOC (12 bytes per file: OFFSET, SIZE, FID)
            # Pre-calculate all file offsets with 16-byte alignment (last hex digit is 0)
            file_offsets = []
            current_file_offset = data_start
            for file_info in file_data_list:
                file_offsets.append(current_file_offset)
                # Move to next file
                current_file_offset += len(file_info['data'])
                # Align to NEXT 16-byte boundary, with minimum 16 bytes padding
                # If already aligned, add 16; otherwise add padding to reach next boundary
                padding = (16 - (current_file_offset % 16)) % 16
                if padding == 0:
                    padding = 16  # Minimum gap of 16 bytes
                current_file_offset += padding

            # Write TOC
            for i, file_info in enumerate(file_data_list):
                new_data.extend(struct.pack('<I', file_offsets[i]))  # OFFSET (absolute)
                new_data.extend(struct.pack('<I', len(file_info['data'])))  # SIZE
                new_data.extend(struct.pack('<I', file_info['file_id']))  # FID

            # Write ORIGINAL string offset table (preserve exact values)
            new_data.extend(original_string_offset_table)

            new_data.extend(struct.pack('<I', original_string_section_size))

            # Add string table
            new_data.extend(string_table_data)

            # Add padding to align file data section (use 0xFF like original)
            new_data.extend(b'\xFF' * padding_before_data)

            # Add file data with 16-byte alignment between files (last hex digit = 0)
            for i, file_info in enumerate(file_data_list):
                new_data.extend(file_info['data'])
                if file_info.get('is_new_file'):
                    print(f"    Inserted new file: filename={file_info['name']}, index={file_info['file_id']}, type={file_info['file_type']}, size={len(file_info['data'])}, offset={file_offsets[i]}, alignment=16")

                # Add 0xFF padding - minimum 16 bytes between files (except for last file)
                if i < len(file_data_list) - 1:
                    current_pos = len(new_data)
                    padding = (16 - (current_pos % 16)) % 16
                    if padding == 0:
                        padding = 16  # Minimum gap of 16 bytes
                    new_data.extend(b'\xFF' * padding)

            # Add padding at end - align to 16 bytes then add 16 more bytes (total 16-32 bytes)
            current_pos = len(new_data)
            padding = (16 - (current_pos % 16)) % 16
            new_data.extend(b'\xFF' * (padding + 16))

            # Write output file
            with open(output_vol_path, 'wb') as f:
                f.write(new_data)

            print(f"\nVOL rebuilt successfully: {output_vol_path}")
            print(f"  Total size: {len(new_data)} bytes")
            print(f"  Files: {len(file_data_list)}")
            print(f"  Header: {header_size} bytes (0x00-0x0F)")
            print(f"  TOC: {toc_size} bytes (0x10-0x{15 + toc_size:X})")
            print(f"  String offset table: {string_offset_table_size} bytes (0x{16 + toc_size:X}-0x{15 + toc_size + string_offset_table_size:X})")
            print(f"  String table: {len(string_table_data)} bytes at 0x{string_table_start:X}")
            print(f"  String table ends (DATASTART): 0x{string_table_end:X}")
            print(f"  Padding: {padding_before_data} bytes (0xFF)")
            print(f"  File data start: 0x{data_start:X}")
            return True

        except Exception as e:
            print(f"Error rebuilding VOL: {e}")
            import traceback
            traceback.print_exc()
            return False


def build_vol_from_directory(source_dir, output_path, log_callback=None):
    """Build a flat PVOL bundle from every file under source_dir."""
    def log(text):
        if log_callback:
            log_callback(text)

    log("\n=== Building New VOL Bundle ===\n")
    log(f"Source directory: {source_dir}\n")

    file_list = []
    seen_names = {}
    for root, dirs, files in os.walk(source_dir):
        dirs.sort(key=str.lower)
        for filename in sorted(files, key=str.lower):
            filepath = os.path.join(root, filename)
            if not os.path.isfile(filepath):
                continue

            stored_name = filename
            key = stored_name.lower()
            if key in seen_names:
                raise ValueError(
                    "VOL stores base filenames only, so duplicate names cannot be packed safely:\n"
                    f"{seen_names[key]}\n{filepath}"
                )
            seen_names[key] = filepath

            with open(filepath, 'rb') as f:
                data = f.read()

            file_list.append({
                'name': stored_name,
                'data': data,
                'size': len(data)
            })

    if not file_list:
        raise ValueError("No files found in directory.")

    file_list.sort(key=lambda item: item['name'].lower())
    log(f"Found {len(file_list)} files (sorted alphabetically)\n")

    file_count = len(file_list)
    header_size = 16
    toc_size = file_count * 0xC
    string_offset_table_size = file_count * 4

    string_data = bytearray()
    string_offsets = []
    for file_info in file_list:
        string_offsets.append(len(string_data))
        string_data.extend(file_info['name'].encode('ascii', errors='replace') + b'\x00')

    string_table_start = header_size + toc_size + string_offset_table_size + 4
    string_table_end = string_table_start + len(string_data)
    data_start = ((string_table_end + 0xF) // 0x10) * 0x10
    padding_before_data = data_start - string_table_end

    file_offsets = []
    current_offset = data_start
    for file_info in file_list:
        file_offsets.append(current_offset)
        current_offset += file_info['size']
        padding = (16 - (current_offset % 16)) % 16
        if padding == 0:
            padding = 16
        current_offset += padding

    output_data = bytearray()
    output_data.extend(b'PVOL')
    output_data.extend(struct.pack('<I', 0x1001))
    output_data.extend(struct.pack('<I', file_count))
    output_data.extend(struct.pack('<I', string_table_end))

    for i, file_info in enumerate(file_list):
        output_data.extend(struct.pack('<I', file_offsets[i]))
        output_data.extend(struct.pack('<I', file_info['size']))
        output_data.extend(struct.pack('<I', i))

    side_table_values = [file_count]
    side_table_values.extend(string_offset_table_size + 4 + offset for offset in string_offsets[:-1])
    for offset in side_table_values:
        output_data.extend(struct.pack('<I', offset))

    final_name_offset = string_offset_table_size + 4 + string_offsets[-1]
    output_data.extend(struct.pack('<I', final_name_offset))
    output_data.extend(string_data)
    output_data.extend(b'\xFF' * padding_before_data)

    for i, file_info in enumerate(file_list):
        output_data.extend(file_info['data'])
        log(f"  File {i}: {file_info['name']}, size {file_info['size']}, offset 0x{file_offsets[i]:X}, alignment 16\n")

        if i < len(file_list) - 1:
            current_pos = len(output_data)
            padding = (16 - (current_pos % 16)) % 16
            if padding == 0:
                padding = 16
            output_data.extend(b'\xFF' * padding)

    current_pos = len(output_data)
    padding = (16 - (current_pos % 16)) % 16
    output_data.extend(b'\xFF' * (padding + 16))

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, 'wb') as f:
        f.write(output_data)

    log("\nVOL bundle created successfully!\n")
    log(f"Output: {output_path}\n")
    log(f"Size: {len(output_data)} bytes\n")
    return {
        'path': output_path,
        'size': len(output_data),
        'file_count': file_count,
        'data_start': data_start
    }


def _both_endian_16(value):
    return struct.pack('<H', value) + struct.pack('>H', value)


def _both_endian_32(value):
    return struct.pack('<I', value) + struct.pack('>I', value)


def _iso_now_7():
    now = datetime.now()
    return bytes([
        now.year - 1900,
        now.month,
        now.day,
        now.hour,
        now.minute,
        now.second,
        0,
    ])


def _iso_now_17():
    return datetime.now().strftime("%Y%m%d%H%M%S00").encode('ascii') + b'\x00'


def _iso_clean_identifier(name, is_dir=False):
    stem, ext = os.path.splitext(name)
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_"

    def clean(text):
        text = text.upper().replace('-', '_').replace(' ', '_')
        return ''.join(ch if ch in allowed else '_' for ch in text)

    if is_dir:
        cleaned = clean(name)[:31].strip('_')
        return cleaned or "DIR"

    cleaned_stem = clean(stem)[:31].strip('_') or "FILE"
    cleaned_ext = clean(ext[1:])[:12].strip('_') if ext else ""
    if cleaned_ext:
        return f"{cleaned_stem}.{cleaned_ext};1"
    return f"{cleaned_stem};1"


def _iso_record(identifier, extent, data_length, flags):
    if isinstance(identifier, int):
        ident = bytes([identifier])
    else:
        ident = identifier.encode('ascii', errors='replace')

    record = bytearray()
    record.append(0)  # filled after length is known
    record.append(0)
    record.extend(_both_endian_32(extent))
    record.extend(_both_endian_32(data_length))
    record.extend(_iso_now_7())
    record.append(flags)
    record.append(0)
    record.append(0)
    record.extend(_both_endian_16(1))
    record.append(len(ident))
    record.extend(ident)
    if len(ident) % 2 == 0:
        record.append(0)
    record[0] = len(record)
    return bytes(record)


class _IsoDir:
    def __init__(self, name, parent=None):
        self.name = name
        self.parent = parent or self
        self.dirs = []
        self.files = []
        self.iso_name = _iso_clean_identifier(name, True) if name else ""
        self.extent = 0
        self.size = 0
        self.path_index = 0
        self.data = b''


def _collect_iso_tree(source_dir):
    root = _IsoDir("")
    dir_map = {os.path.abspath(source_dir): root}
    file_count = 0

    for current_root, dirs, files in os.walk(source_dir):
        dirs.sort(key=str.lower)
        files.sort(key=str.lower)
        current_abs = os.path.abspath(current_root)
        current_dir = dir_map[current_abs]

        for dirname in dirs:
            child_abs = os.path.join(current_abs, dirname)
            child = _IsoDir(dirname, current_dir)
            current_dir.dirs.append(child)
            dir_map[child_abs] = child

        for filename in files:
            path = os.path.join(current_abs, filename)
            if not os.path.isfile(path):
                continue
            current_dir.files.append({
                'name': filename,
                'iso_name': _iso_clean_identifier(filename, False),
                'path': path,
                'size': os.path.getsize(path),
                'extent': 0,
            })
            file_count += 1

    return root, file_count


def _flatten_iso_dirs(root):
    dirs = []
    queue = [root]
    while queue:
        node = queue.pop(0)
        dirs.append(node)
        queue.extend(sorted(node.dirs, key=lambda item: item.iso_name))
    for idx, node in enumerate(dirs, start=1):
        node.path_index = idx
    return dirs


def _build_path_tables(dirs):
    little = bytearray()
    big = bytearray()
    for node in dirs:
        ident = b'\x00' if node.parent is node else node.iso_name.encode('ascii', errors='replace')
        parent_idx = 1 if node.parent is node else node.parent.path_index

        little.append(len(ident))
        little.append(0)
        little.extend(struct.pack('<I', node.extent))
        little.extend(struct.pack('<H', parent_idx))
        little.extend(ident)
        if len(ident) % 2:
            little.append(0)

        big.append(len(ident))
        big.append(0)
        big.extend(struct.pack('>I', node.extent))
        big.extend(struct.pack('>H', parent_idx))
        big.extend(ident)
        if len(ident) % 2:
            big.append(0)

    return bytes(little), bytes(big)


def _build_iso_dir_data(node):
    parent = node.parent if node.parent is not None else node
    records = bytearray()
    records.extend(_iso_record(0, node.extent, node.size, 0x02))
    records.extend(_iso_record(1, parent.extent, parent.size, 0x02))

    children = []
    for child in node.dirs:
        children.append((child.iso_name, _iso_record(child.iso_name, child.extent, child.size, 0x02)))
    for file_info in node.files:
        children.append((file_info['iso_name'], _iso_record(file_info['iso_name'], file_info['extent'], file_info['size'], 0x00)))

    for _, record in sorted(children, key=lambda item: item[0]):
        pos_in_sector = len(records) % 2048
        if pos_in_sector and pos_in_sector + len(record) > 2048:
            records.extend(b'\x00' * (2048 - pos_in_sector))
        records.extend(record)

    node.size = len(records)
    if len(records) % 2048:
        records.extend(b'\x00' * (2048 - (len(records) % 2048)))
    return bytes(records)


def _estimate_iso_dir_size(node):
    records_len = len(_iso_record(0, 0, 0, 0x02)) + len(_iso_record(1, 0, 0, 0x02))
    children = []
    children.extend((child.iso_name, len(_iso_record(child.iso_name, 0, child.size, 0x02))) for child in node.dirs)
    children.extend((file_info['iso_name'], len(_iso_record(file_info['iso_name'], 0, file_info['size'], 0x00))) for file_info in node.files)
    for _, record_len in sorted(children, key=lambda item: item[0]):
        pos_in_sector = records_len % 2048
        if pos_in_sector and pos_in_sector + record_len > 2048:
            records_len += 2048 - pos_in_sector
        records_len += record_len
    return records_len


def _iso_vrs_descriptor(identifier):
    descriptor = bytearray(2048)
    descriptor[0] = 0
    descriptor[1:6] = identifier.encode('ascii')
    descriptor[6] = 1
    return bytes(descriptor)


def _write_zero_until(handle, sector):
    target = sector * 2048
    current = handle.tell()
    if current < target:
        handle.write(b'\x00' * (target - current))


def _build_primary_volume_descriptor(volume_id, total_sectors, path_table_size, l_path_extent, m_path_extent, root):
    pvd = bytearray(2048)
    pvd[0] = 1
    pvd[1:6] = b'CD001'
    pvd[6] = 1
    pvd[8:40] = b'GZBUILDR'.ljust(32, b' ')
    pvd[40:72] = volume_id.encode('ascii', errors='replace')[:32].ljust(32, b' ')
    pvd[80:88] = _both_endian_32(total_sectors)
    pvd[120:124] = _both_endian_16(1)
    pvd[124:128] = _both_endian_16(1)
    pvd[128:132] = _both_endian_16(2048)
    pvd[132:140] = _both_endian_32(path_table_size)
    pvd[140:144] = struct.pack('<I', l_path_extent)
    pvd[144:148] = struct.pack('<I', 0)
    pvd[148:152] = struct.pack('>I', m_path_extent)
    pvd[152:156] = struct.pack('>I', 0)
    pvd[156:156 + 34] = _iso_record(0, root.extent, root.size, 0x02)
    pvd[190:318] = b'GZBuildr ISO Builder'.ljust(128, b' ')
    pvd[318:446] = volume_id.encode('ascii', errors='replace')[:128].ljust(128, b' ')
    now = _iso_now_17()
    for pos in (813, 830, 847, 864):
        pvd[pos:pos + 17] = now
    pvd[881] = 1
    return bytes(pvd)


def _build_iso_from_directory_internal(source_dir, output_path, log_callback=None):
    """Build a MODE1/2048 ISO9660 image from a directory tree."""
    def log(text):
        if log_callback:
            log_callback(text)

    l_path_extent = 257
    root_dir_extent = 259
    first_file_extent = 369
    trailing_sectors = 19

    log("\n=== Building ISO Image ===\n")
    log("Data Type: MODE1/2048\n")
    log("File System: ISO9660 + UDF VRS\n")
    log(f"Source directory: {source_dir}\n")

    root, file_count = _collect_iso_tree(source_dir)
    dirs = _flatten_iso_dirs(root)
    if file_count == 0 and len(dirs) == 1:
        raise ValueError("No files found in directory.")

    # Directory record lengths do not depend on the numeric data_length values,
    # so one sizing pass is enough before assigning final extents.
    for node in reversed(dirs):
        node.size = _estimate_iso_dir_size(node)
    little_path, big_path = _build_path_tables(dirs)
    l_path_sectors = (len(little_path) + 2047) // 2048
    m_path_extent = l_path_extent + l_path_sectors
    m_path_sectors = (len(big_path) + 2047) // 2048

    current_sector = max(root_dir_extent, m_path_extent + m_path_sectors)
    for node in dirs:
        node.extent = current_sector
        current_sector += max(1, (node.size + 2047) // 2048)

    current_sector = max(first_file_extent, current_sector)
    for node in dirs:
        for file_info in sorted(node.files, key=lambda item: item['iso_name']):
            file_info['extent'] = current_sector
            current_sector += (file_info['size'] + 2047) // 2048

    for node in dirs:
        node.data = _build_iso_dir_data(node)

    little_path, big_path = _build_path_tables(dirs)
    total_sectors = current_sector

    volume_id = _iso_clean_identifier(os.path.basename(os.path.normpath(source_dir)) or "GZBUILDR", True)
    pvd = _build_primary_volume_descriptor(volume_id, total_sectors, len(little_path), l_path_extent, m_path_extent, root)
    terminator = bytearray(2048)
    terminator[0] = 255
    terminator[1:6] = b'CD001'
    terminator[6] = 1

    output_parent = os.path.dirname(output_path)
    if output_parent:
        os.makedirs(output_parent, exist_ok=True)
    with open(output_path, 'wb') as iso:
        iso.write(b'\x00' * (16 * 2048))
        iso.write(pvd)
        iso.write(terminator)
        iso.write(_iso_vrs_descriptor("BEA01"))
        iso.write(_iso_vrs_descriptor("NSR02"))
        iso.write(_iso_vrs_descriptor("TEA01"))
        _write_zero_until(iso, l_path_extent)
        iso.write(little_path)
        iso.write(b'\x00' * ((l_path_sectors * 2048) - len(little_path)))
        _write_zero_until(iso, m_path_extent)
        iso.write(big_path)
        iso.write(b'\x00' * ((m_path_sectors * 2048) - len(big_path)))
        _write_zero_until(iso, root_dir_extent)

        for node in dirs:
            _write_zero_until(iso, node.extent)
            iso.write(node.data)
            log(f"  Directory: /{node.iso_name if node.iso_name else ''}, sector {node.extent}, size {node.size}\n")

        _write_zero_until(iso, first_file_extent)
        for node in dirs:
            for file_info in sorted(node.files, key=lambda item: item['iso_name']):
                _write_zero_until(iso, file_info['extent'])
                with open(file_info['path'], 'rb') as src:
                    shutil.copyfileobj(src, iso)
                padding = (2048 - (file_info['size'] % 2048)) % 2048
                if padding:
                    iso.write(b'\x00' * padding)
                rel = os.path.relpath(file_info['path'], source_dir)
                log(f"  File: {rel}, sector {file_info['extent']}, size {file_info['size']}\n")
        _write_zero_until(iso, total_sectors + trailing_sectors)

    size = os.path.getsize(output_path)
    log("\nISO image created successfully!\n")
    log(f"Output: {output_path}\n")
    log(f"Files: {file_count}\n")
    log(f"Size: {size} bytes\n")
    return {
        'path': output_path,
        'size': size,
        'file_count': file_count,
        'filesystem': 'ISO9660 + UDF VRS',
        'data_type': 'MODE1/2048',
    }


def build_iso_from_directory(source_dir, output_path, log_callback=None):
    """Build a MODE1/2048 ISO image from a directory tree."""
    return _build_iso_from_directory_internal(source_dir, output_path, log_callback)


class ExtractWindow:
    FILE_TYPE_NAMES = {
        0: "Static Mesh",
        1: "Skeleton",
        2: "Interface (GSTE), IFL File, Lighting, MonsterData, LevelData, CityData, NeoSkyData",
        3: "Skeleton, Camera",
        4: "Animation, Skeleton, Camera",
        6: "Material",
        9: "Texture",
        13: "Palette",
        16: "PWK File",
        17: "Rigged Mesh",
        20: "Particle",
        21: "Camera, Path",
        22: "PRX File",
        23: "Localization",
        24: "Archive",
        25: "Audio",
        26: "BDP File",
        27: "Video"
    }

    def __init__(
        self,
        parent,
        file_entries,
        parser,
        output_text_callback,
        extract_dir_callback=None,
        remembered_file_nums=None,
        selection_update_callback=None,
    ):
        self.all_file_entries = file_entries
        self.file_entries = [entry for entry in file_entries if not entry.get('is_resource')]
        self.resource_entries_by_file_num = {}
        for entry in file_entries:
            if entry.get('is_resource'):
                self.resource_entries_by_file_num.setdefault(self._entry_file_num(entry), []).append(entry)
        self.parser = parser
        self.output_text_callback = output_text_callback
        self.extract_dir_callback = extract_dir_callback  # Callback to pass extract dir back to main GUI
        self.selection_update_callback = selection_update_callback
        self.bundle_key = os.path.abspath(parser.filepath).lower() if parser and hasattr(parser, 'filepath') else ""
        remembered = remembered_file_nums or set()
        self.remembered_file_nums = {int(value) for value in remembered if str(value).lstrip("-").isdigit()}
        self._bulk_selection_update = False
        self._selection_count_after_id = None
        self._search_after_id = None
        self._search_query = ""

        self.window = tk.Toplevel(parent)
        set_window_icon(self.window)
        self.window.title("Extract Files")
        self.window.geometry("800x750")
        self.window.resizable(True, True)
        self.window.minsize(600, 500)
        # Remove grab_set() to allow non-modal behavior

        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Instructions and status
        top_frame = ttk.Frame(main_frame)
        top_frame.pack(fill=tk.X, pady=(0, 5))

        label = ttk.Label(top_frame, text="Select files to extract (click category to expand):")
        label.pack(side=tk.LEFT)

        total_files = len(self.file_entries)
        self.status_label = ttk.Label(top_frame, text=f"0 / {total_files} files selected")
        self.status_label.pack(side=tk.RIGHT)
        self.total_files = total_files

        # Create scrollable frame for categories
        scroll_container = ttk.Frame(main_frame)
        scroll_container.pack(fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(scroll_container, orient="vertical")
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        canvas = tk.Canvas(scroll_container, yscrollcommand=scrollbar.set, bg=APP_BG, highlightthickness=0)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar.config(command=canvas.yview)

        # Create inner frame for content
        scrollable_frame = ttk.Frame(canvas)
        canvas_frame = canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")

        def on_frame_configure(event):
            canvas.configure(scrollregion=canvas.bbox("all"))
            canvas.itemconfig(canvas_frame, width=event.width)

        scrollable_frame.bind("<Configure>", on_frame_configure)
        canvas.bind("<Configure>", lambda e: canvas.itemconfig(canvas_frame, width=e.width))

        # Enable mouse wheel scrolling
        def on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        def on_mousewheel_linux(event):
            if event.num == 4:
                canvas.yview_scroll(-1, "units")
            elif event.num == 5:
                canvas.yview_scroll(1, "units")

        # Bind mouse wheel events
        canvas.bind_all("<MouseWheel>", on_mousewheel)
        canvas.bind_all("<Button-4>", on_mousewheel_linux)
        canvas.bind_all("<Button-5>", on_mousewheel_linux)

        # Cleanup bindings when dialog closes
        def cleanup_bindings():
            try:
                canvas.unbind_all("<MouseWheel>")
                canvas.unbind_all("<Button-4>")
                canvas.unbind_all("<Button-5>")
            except:
                pass

        self.cleanup_bindings = cleanup_bindings
        self.window.protocol("WM_DELETE_WINDOW", self.destroy)

        # Group files by type (or extension for VOL files)
        self.files_by_type = {}
        self.is_vol = parser.bundle_type == 'vol'

        for entry in self.file_entries:
            if self.is_vol:
                # For VOL files, group by extension (extract from folder path)
                name = entry['name']
                if '/' in name:
                    group_key = name.split('/')[0]  # e.g., "CNF", "OVL", "ICN"
                else:
                    group_key = 'NO_EXTENSION'
            else:
                # For Pipeworks bundles, group by file_type number
                group_key = entry.get('file_type', 0)

            if group_key not in self.files_by_type:
                self.files_by_type[group_key] = []
            self.files_by_type[group_key].append(entry)

        # Store checkboxes and category state
        self.check_vars = {}
        self.category_vars = {}
        self.category_expanded = {}
        self.category_user_expanded = set()  # tracks categories the user manually expanded
        self.category_frames = {}
        self.category_content_frames = {}
        self.file_widgets = {}

        # Create collapsible sections for each file type/extension
        # Sort by extension name (alphabetically) for VOL, or by type number for Pipeworks
        if self.is_vol:
            sorted_keys = sorted(self.files_by_type.keys(), key=lambda x: str(x).lower())
        else:
            sorted_keys = sorted(self.files_by_type.keys())

        for group_key in sorted_keys:
            entries = self.files_by_type[group_key]

            # Generate appropriate label based on bundle type
            if self.is_vol:
                # For VOL files, show extension name
                if group_key == 'NO_EXTENSION':
                    title_text = f"{group_key} ({len(entries)} files)"
                else:
                    title_text = f"{group_key} ({len(entries)} files)"
            else:
                # For Pipeworks bundles, show type number and name
                type_name = self.FILE_TYPE_NAMES.get(group_key, f"Unknown Type {group_key}")
                title_text = f"Type {group_key}: {type_name} ({len(entries)} files)"

            # Category container
            category_container = ttk.Frame(scrollable_frame)
            category_container.pack(fill=tk.X, padx=5, pady=2)

            # Header frame (clickable to expand/collapse)
            header_frame = ttk.Frame(category_container, relief=tk.RAISED, borderwidth=1)
            header_frame.pack(fill=tk.X)

            # Track expansion state
            self.category_expanded[group_key] = False

            # Arrow and label
            arrow_label = ttk.Label(header_frame, text="▶", width=2)
            arrow_label.pack(side=tk.LEFT, padx=(5, 0))

            title_label = ttk.Label(header_frame, text=title_text)
            title_label.pack(side=tk.LEFT, pady=5)

            match_label = ttk.Label(header_frame, text="")
            match_label.pack(side=tk.RIGHT, padx=(6, 8), pady=5)

            # Category select all checkbox
            category_var = tk.BooleanVar(value=False)
            self.category_vars[group_key] = category_var

            # Content frame (hidden by default)
            content_frame = ttk.Frame(category_container)
            self.category_content_frames[group_key] = content_frame
            self.category_frames[group_key] = {
                'arrow': arrow_label,
                'match_label': match_label,
                'content': content_frame,
                'container': category_container,
                'loaded': False
            }

            # Make header clickable
            def make_toggle(gk, arrow, content):
                def toggle(event=None):
                    self.toggle_category_expand(gk, arrow, content)
                return toggle

            toggle_func = make_toggle(group_key, arrow_label, content_frame)
            header_frame.bind("<Button-1>", toggle_func)
            arrow_label.bind("<Button-1>", toggle_func)
            title_label.bind("<Button-1>", toggle_func)

            if any(entry.get('file_num') in self.remembered_file_nums for entry in entries):
                self.window.after(10, toggle_func)

        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill=tk.X, pady=(10, 0))

        # Left side buttons
        expand_all_btn = ttk.Button(button_frame, text="Expand All", command=self.expand_all)
        expand_all_btn.pack(side=tk.LEFT, padx=(0, 5))

        collapse_all_btn = ttk.Button(button_frame, text="Collapse All", command=self.collapse_all)
        collapse_all_btn.pack(side=tk.LEFT, padx=(0, 5))

        select_all_btn = ttk.Button(button_frame, text="Select All", command=self.select_all)
        select_all_btn.pack(side=tk.LEFT, padx=(0, 5))

        deselect_all_btn = ttk.Button(button_frame, text="Deselect All", command=self.deselect_all)
        deselect_all_btn.pack(side=tk.LEFT, padx=(0, 5))

        # Right side button
        extract_btn = ttk.Button(button_frame, text="Extract Selected", command=self.extract)
        extract_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Search filter
        search_frame = ttk.Frame(main_frame)
        search_frame.pack(fill=tk.X, pady=(8, 0))

        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))

        self.search_var = tk.StringVar()
        self.search_var.trace_add('write', lambda *args: self.schedule_search_filter())
        search_entry = ttk.Entry(search_frame, textvariable=self.search_var)
        search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        apply_button_outline(self.window)
        self.update_selection_count()

    def _entry_file_num(self, entry):
        file_num = entry.get('file_num')
        if isinstance(file_num, int):
            return file_num
        if isinstance(file_num, str) and file_num.lstrip("-").isdigit():
            return int(file_num)
        return None

    def _entry_display_name(self, entry):
        return entry['name'].split('/')[-1] if '/' in entry['name'] else entry['name']

    def _all_file_nums(self):
        return {num for num in (self._entry_file_num(entry) for entry in self.file_entries) if num is not None}

    def _category_file_nums(self, group_key):
        return {num for num in (self._entry_file_num(entry) for entry in self.files_by_type.get(group_key, [])) if num is not None}

    def _created_file_nums(self, group_key):
        return {
            self._entry_file_num(entry)
            for _var, entry in self.check_vars.get(group_key, [])
            if self._entry_file_num(entry) is not None
        }

    def _matching_entries(self, group_key, query):
        if not query:
            return list(self.files_by_type.get(group_key, []))
        return [
            entry for entry in self.files_by_type.get(group_key, [])
            if query in self._entry_display_name(entry).lower()
        ]

    def _sync_category_checkbox(self, group_key):
        nums = self._category_file_nums(group_key)
        self.category_vars[group_key].set(bool(nums) and nums.issubset(self.remembered_file_nums))

    def _sync_loaded_vars(self, group_key=None):
        groups = [group_key] if group_key is not None else list(self.check_vars.keys())
        self._bulk_selection_update = True
        try:
            for key in groups:
                for var, entry in self.check_vars.get(key, []):
                    file_num = self._entry_file_num(entry)
                    if file_num is not None:
                        var.set(file_num in self.remembered_file_nums)
        finally:
            self._bulk_selection_update = False

    def schedule_search_filter(self):
        """Debounce search so typing does not repack thousands of widgets per keypress."""
        if self._search_after_id:
            self.window.after_cancel(self._search_after_id)
        self._search_after_id = self.window.after(180, self.apply_search_filter)

    def schedule_selection_count_update(self):
        if self._bulk_selection_update:
            return
        if self._selection_count_after_id:
            self.window.after_cancel(self._selection_count_after_id)
        self._selection_count_after_id = self.window.after(60, self.update_selection_count)

    def _filter_loaded_category_widgets(self, group_key, query):
        widgets = self.file_widgets.get(group_key, [])
        any_visible = False
        for cb, name_lower in widgets:
            if not query or query in name_lower:
                cb.pack(anchor=tk.W, pady=3)
                any_visible = True
            else:
                cb.pack_forget()

        category_cb = self.category_frames[group_key].get('category_cb')
        if category_cb:
            if any_visible:
                category_cb.pack(anchor=tk.W, pady=(0, 5))
            else:
                category_cb.pack_forget()
        return any_visible

    def toggle_category_expand(self, group_key, arrow_label, content_frame):
        """Expand or collapse a category"""
        is_expanded = self.category_expanded[group_key]

        if is_expanded:
            # Collapse
            content_frame.pack_forget()
            arrow_label.config(text="▶")
            self.category_expanded[group_key] = False
            self.category_user_expanded.discard(group_key)
        else:
            # Expand
            content_frame.pack(fill=tk.X, padx=10, pady=5)
            arrow_label.config(text="▼")
            self.category_expanded[group_key] = True
            self.category_user_expanded.add(group_key)

            # Lazy load checkboxes if not already loaded
            if not self.category_frames[group_key]['loaded']:
                self.load_category_files(group_key, content_frame)
                self.category_frames[group_key]['loaded'] = True
            if self._search_query:
                self._filter_loaded_category_widgets(group_key, self._search_query)

    def load_category_files(self, group_key, content_frame, entries=None):
        """Lazy load file checkboxes for a category"""
        entries = self.files_by_type[group_key] if entries is None else entries

        # Select all checkbox
        category_var = self.category_vars[group_key]
        if 'category_cb' not in self.category_frames[group_key]:
            category_cb = ttk.Checkbutton(
                content_frame,
                text="Select All in Category",
                variable=category_var,
                command=lambda: self.toggle_category_selection(group_key)
            )
            category_cb.pack(anchor=tk.W, pady=(0, 5))
            self.category_frames[group_key]['category_cb'] = category_cb
        else:
            self.category_frames[group_key]['category_cb'].pack(anchor=tk.W, pady=(0, 5))

        # Initialize check_vars dict for this category
        if group_key not in self.check_vars:
            self.check_vars[group_key] = []

        # Initialize file_widgets dict for this category (for search filtering)
        if group_key not in self.file_widgets:
            self.file_widgets[group_key] = []

        # Individual file checkboxes
        created_file_nums = self._created_file_nums(group_key)
        for entry in entries:
            file_num = self._entry_file_num(entry)
            if file_num is not None and file_num in created_file_nums:
                continue
            var = tk.BooleanVar(value=file_num in self.remembered_file_nums)
            var.trace_add('write', lambda *args: self.schedule_selection_count_update())
            self.check_vars[group_key].append((var, entry))
            if file_num is not None:
                created_file_nums.add(file_num)

            # Extract just filename without folder
            display_name = self._entry_display_name(entry)

            cb = ttk.Checkbutton(
                content_frame,
                text=f"  {display_name} ({entry['size']} bytes)",
                variable=var
            )
            cb.pack(anchor=tk.W, pady=3)
            self.file_widgets[group_key].append((cb, display_name.lower()))
        self._sync_category_checkbox(group_key)
        self.update_selection_count()

    def apply_search_filter(self):
        """Filter visible file checkboxes based on search text"""
        self._search_after_id = None
        query = self.search_var.get().lower().strip()
        self._search_query = query

        for group_key, frame_info in self.category_frames.items():
            container = frame_info.get('container')
            if not container:
                continue

            if query:
                match_count = len(self._matching_entries(group_key, query))
                if not match_count:
                    container.pack_forget()
                    continue

                frame_info['match_label'].config(text=f"{match_count} file{'s' if match_count != 1 else ''} found")
                container.pack(fill=tk.X, padx=5, pady=2)

                content_frame = frame_info['content']
                if group_key in self.category_user_expanded:
                    if not frame_info['loaded']:
                        self.load_category_files(group_key, content_frame)
                        frame_info['loaded'] = True
                    self._filter_loaded_category_widgets(group_key, query)
                    content_frame.pack(fill=tk.X, padx=10, pady=5)
                    frame_info['arrow'].config(text="▼")
                    self.category_expanded[group_key] = True
                else:
                    content_frame.pack_forget()
                    frame_info['arrow'].config(text="▶")
                    self.category_expanded[group_key] = False
            else:
                frame_info['match_label'].config(text="")
                container.pack(fill=tk.X, padx=5, pady=2)
                content_frame = frame_info['content']

                if group_key in self.category_user_expanded:
                    if not frame_info['loaded']:
                        self.load_category_files(group_key, content_frame)
                        frame_info['loaded'] = True
                    self._filter_loaded_category_widgets(group_key, "")
                    content_frame.pack(fill=tk.X, padx=10, pady=5)
                    frame_info['arrow'].config(text="▼")
                    self.category_expanded[group_key] = True
                else:
                    content_frame.pack_forget()
                    frame_info['arrow'].config(text="▶")
                    self.category_expanded[group_key] = False

    def update_selection_count(self):
        """Update the status label with current selection count"""
        self._selection_count_after_id = None
        self.save_current_selection()
        count = len(self.remembered_file_nums)
        self.status_label.config(text=f"{count} / {self.total_files} files selected")

    def save_current_selection(self):
        """Remember checked boxes only while this bundle remains the active parsed file."""
        if not self.bundle_key:
            return

        selected = set(self.remembered_file_nums)
        loaded_file_nums = set()
        for group_key in self.check_vars:
            for var, entry in self.check_vars[group_key]:
                file_num = self._entry_file_num(entry)
                if file_num is None:
                    continue
                loaded_file_nums.add(file_num)
                if var.get():
                    selected.add(file_num)
                else:
                    selected.discard(file_num)
        self.remembered_file_nums = selected
        for group_key in self.category_vars:
            self._sync_category_checkbox(group_key)
        if self.selection_update_callback:
            self.selection_update_callback(set(selected))

    def toggle_category_selection(self, group_key):
        """Toggle all files in a category"""
        state = self.category_vars[group_key].get()
        nums = self._category_file_nums(group_key)
        if state:
            self.remembered_file_nums.update(nums)
        else:
            self.remembered_file_nums.difference_update(nums)
        self._sync_loaded_vars(group_key)
        self.update_selection_count()

    def expand_all(self):
        """Expand all categories"""
        for group_key in self.category_frames:
            if not self.category_expanded[group_key]:
                arrow = self.category_frames[group_key]['arrow']
                content = self.category_frames[group_key]['content']
                self.toggle_category_expand(group_key, arrow, content)

    def collapse_all(self):
        """Collapse all categories"""
        for group_key in self.category_frames:
            if self.category_expanded[group_key]:
                arrow = self.category_frames[group_key]['arrow']
                content = self.category_frames[group_key]['content']
                self.toggle_category_expand(group_key, arrow, content)

    def select_all(self):
        """Select all files in all categories"""
        self.remembered_file_nums = self._all_file_nums()
        for group_key in self.category_vars:
            self.category_vars[group_key].set(True)
        self._sync_loaded_vars()
        self.update_selection_count()

    def deselect_all(self):
        """Deselect all files in all categories"""
        self.remembered_file_nums.clear()
        for group_key in self.category_vars:
            self.category_vars[group_key].set(False)
        self._sync_loaded_vars()
        self.update_selection_count()

    def _get_bundle_extract_dir(self, output_dir):
        """Create a bundle-named extraction root inside the selected output directory."""
        if self.parser and hasattr(self.parser, 'filepath') and self.parser.filepath:
            bundle_name = os.path.splitext(os.path.basename(self.parser.filepath))[0]
        else:
            bundle_name = "extracted"

        safe_name = ''.join(c if c not in '<>:"/\\|?*' and ord(c) >= 32 else '_' for c in bundle_name).strip()
        if not safe_name:
            safe_name = "extracted"
        return os.path.join(output_dir, safe_name)

    def extract(self):
        """Extract selected files"""
        self.save_current_selection()
        selected_file_nums = set(self.remembered_file_nums)
        selected_files = [
            entry for entry in self.file_entries
            if self._entry_file_num(entry) in selected_file_nums
        ]
        sidecar_files = []
        for entry in selected_files:
            sidecar_files.extend(self.resource_entries_by_file_num.get(self._entry_file_num(entry), []))
        for group_key in self.check_vars:
            for var, entry in self.check_vars[group_key]:
                if self._entry_file_num(entry) is None and var.get():
                    selected_files.append(entry)

        if not selected_files:
            messagebox.showwarning("No Selection", "Please select files to extract.")
            return
        # Ask for output directory
        initial_extract = (
            os.path.dirname(self.parser.filepath)
            if self.parser and hasattr(self.parser, 'filepath')
            else os.path.expanduser("~")
        )
        output_dir = _dialog(
            self.window,
            filedialog.askdirectory,
            title="Select Output Directory",
            initialdir=initial_extract,
        )
        if not output_dir:
            return

        extract_root = self._get_bundle_extract_dir(output_dir)

        # Extract files
        success_count = 0
        fail_count = 0

        entries_to_extract = selected_files + sidecar_files
        for entry in entries_to_extract:
            if self.parser.extract_file(entry, extract_root):
                success_count += 1
            else:
                fail_count += 1

        if len(selected_files) == len(self.file_entries) and fail_count == 0 and self.parser.bundle_type == 'pipeworks':
            try:
                self.parser.write_pipeworks_manifest(extract_root, self.all_file_entries)
            except Exception as manifest_err:
                self.output_text_callback(f"Warning: could not write rebuild manifest: {manifest_err}\n")

        # Show results
        message = f"Extraction complete!\n\nSuccessful: {success_count}\nFailed: {fail_count}"
        messagebox.showinfo("Extraction Complete", message)

        # Update main window output
        self.output_text_callback(f"\n{message}\n")
        self.output_text_callback(f"Files extracted to: {extract_root}\n")

        # Pass extract directory back to main GUI
        if self.extract_dir_callback:
            self.extract_dir_callback(extract_root)

    def destroy(self):
        """Clean up and destroy window"""
        if self._search_after_id:
            self.window.after_cancel(self._search_after_id)
            self._search_after_id = None
        if self._selection_count_after_id:
            self.window.after_cancel(self._selection_count_after_id)
            self._selection_count_after_id = None
        self.save_current_selection()
        self.cleanup_bindings()
        self.window.destroy()


class RebuildWindow:
    def __init__(self, parent, parsed_files, parser, output_text_callback, bulk_bundles=None, last_extract_dir=None, zip_source=None):
        self.parsed_files = parsed_files
        self.parser = parser
        self.output_text_callback = output_text_callback
        self.build_from_scratch = (parsed_files is None or parser is None)
        self.bulk_bundles = bulk_bundles  # List of bundle file paths for bulk rebuild
        self.last_extract_dir = last_extract_dir  # Auto-populate with last extraction directory
        self.zip_source = zip_source  # Original ZIP path if current bundle came from a ZIP
        self.settings = load_app_settings()
        self.default_alignment_preset_name = ""
        self._loading_alignment_preset = False
        self.bundle_key = os.path.abspath(parser.filepath).lower() if parser and hasattr(parser, 'filepath') else ""

        self.window = tk.Toplevel(parent)
        set_window_icon(self.window)
        self.window.title("Build Bundle from Directory" if self.build_from_scratch else "Rebuild Bundle")
        self.window.geometry("800x640")
        self.window.resizable(True, True)
        self.window.minsize(600, 560)

        self.main_frame = ttk.Frame(self.window, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        main_frame = self.main_frame

        # Mode toggle (only show when bulk bundles are available and not build-from-scratch)
        self.bulk_mode = tk.BooleanVar(value=False)
        self.add_new_files_mode = tk.BooleanVar(value=False)
        self.added_new_files = []
        self.added_new_file_set = set()
        self.added_new_file_insert_vars = {}
        mode_frame = None
        if self.bulk_bundles and not self.build_from_scratch:
            mode_frame = ttk.Frame(main_frame)
            mode_frame.pack(fill=tk.X, pady=(0, 8))

            self._mode_cb = ttk.Checkbutton(
                mode_frame,
                text="Bulk Rebuild",
                variable=self.bulk_mode,
                command=self._on_mode_change
            )
            self._mode_cb.pack(side=tk.LEFT, anchor=tk.W)

        if not self.build_from_scratch:
            if mode_frame is None:
                mode_frame = ttk.Frame(main_frame)
                mode_frame.pack(fill=tk.X, pady=(0, 8))
            self.add_new_files_cb = ttk.Checkbutton(
                mode_frame,
                text="Add New Files - Intended for Game Assets",
                variable=self.add_new_files_mode,
                command=self._on_add_new_files_toggle
            )
            self.add_new_files_cb.pack(side=tk.LEFT, anchor=tk.W, padx=(16 if self.bulk_bundles else 0, 0))

        # Instructions
        if self.build_from_scratch:
            instructions = ttk.Label(main_frame, text="Build a new bundle from a directory of files:")
        else:
            instructions = ttk.Label(main_frame, text="Select optional replacement files, then rebuild:")
        instructions.pack(anchor=tk.W, pady=(0, 10))

        # Replacement directory section
        repl_frame = ttk.LabelFrame(main_frame, text="Replacement Files Directory", padding="5")
        repl_frame.pack(fill=tk.X, pady=(0, 10))
        repl_frame.columnconfigure(0, weight=1)

        self.repl_dir_var = tk.StringVar()
        remembered_repl = self.settings.get("rebuild_replacement_dirs", {}).get(self.bundle_key, "")
        if remembered_repl and os.path.isdir(remembered_repl):
            self.repl_dir_var.set(remembered_repl)
        elif self.last_extract_dir and os.path.isdir(self.last_extract_dir):
            self.repl_dir_var.set(self.last_extract_dir)
        repl_entry = ttk.Entry(repl_frame, textvariable=self.repl_dir_var, state='readonly')
        repl_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))

        repl_browse_btn = ttk.Button(repl_frame, text="Browse", command=self.browse_replacement_dir)
        repl_browse_btn.grid(row=0, column=1)

        # Output file is chosen when Rebuild/Save is pressed.
        self.output_file_var = tk.StringVar()
        self.output_file_var.trace_add('write', lambda *args: self.update_alignments_on_file_change())

        # Create two-column layout: alignment controls on left, status on right
        self.content_frame = ttk.Frame(main_frame)
        content_frame = self.content_frame
        content_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 2))
        content_frame.columnconfigure(0, weight=0)  # Alignment controls - fixed width
        content_frame.columnconfigure(1, weight=1)  # Status - expandable
        content_frame.rowconfigure(0, weight=1)

        # Left side: Block Alignment controls
        self.left_frame = ttk.Frame(content_frame)
        self.left_frame.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.W), padx=(0, 10))

        self.alignment_frame = ttk.LabelFrame(self.left_frame, text="Block Alignment", padding="10")
        self.alignment_frame.pack(fill=tk.X, anchor=tk.N)

        # Alignment options
        alignment_values = [16, 32, 64, 128, 256, 512, 1024, 2048]

        # File type labels and their IDs
        file_types = [
            ("Static Mesh", 0),
            ("Material", 6),
            ("Texture", 9),
            ("Palette", 13),
            ("Rigged Mesh", 17),
            ("Particle", 20)
        ]

        # Store dropdown variables and widgets
        self.alignment_vars = {}
        self.alignment_dropdowns = {}
        self.alignment_labels = {}

        # Create dropdowns for each file type
        for idx, (type_name, type_id) in enumerate(file_types):
            # Label
            label = ttk.Label(self.alignment_frame, text=type_name, width=15, anchor='w')
            label.grid(row=idx, column=0, sticky=tk.W, pady=3, padx=(0, 10))
            self.alignment_labels[type_id] = label

            # Dropdown - initially show N/A
            var = tk.StringVar(value='N/A')
            self.alignment_vars[type_id] = var
            dropdown = ttk.Combobox(
                self.alignment_frame,
                textvariable=var,
                values=['N/A'],
                state='disabled',
                width=8
            )
            dropdown.grid(row=idx, column=1, sticky=tk.W, pady=3)
            self.alignment_dropdowns[type_id] = dropdown

        # Add separator line and extension detected label
        self.alignment_separator = ttk.Frame(self.alignment_frame, height=2, relief=tk.SUNKEN)
        self.alignment_separator.grid(row=len(file_types), column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 5))

        self.alignment_action_row = len(file_types) + 1
        self.alignment_extension_row = len(file_types) + 2
        self.alignment_bulk_action_row = len(file_types)
        self.action_frame = ttk.Frame(self.alignment_frame)
        self.action_frame.grid(row=self.alignment_action_row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 0))
        self.action_frame.columnconfigure(0, weight=1)
        self.action_frame.columnconfigure(1, weight=1)

        self.reset_alignment_btn = ttk.Button(self.action_frame, text="Reset", command=self.reset_alignments)
        self.reset_alignment_btn.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))

        self.rebuild_btn = ttk.Button(self.action_frame, text="Rebuild Bundle", command=self.rebuild)
        self.rebuild_btn.grid(row=0, column=1, sticky=(tk.W, tk.E))

        self.alignment_preset_var = tk.StringVar()
        self.alignment_preset_dropdown = ttk.Combobox(
            self.alignment_frame,
            textvariable=self.alignment_preset_var,
            state='readonly',
            width=20
        )
        self.alignment_preset_dropdown.grid(row=self.alignment_extension_row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
        self.alignment_preset_dropdown.bind('<<ComboboxSelected>>', self.on_alignment_preset_selected)

        self.bulk_align_note = ttk.Label(
            self.alignment_frame,
            text="Auto-detected\nper bundle",
            foreground='gray',
            font=('TkDefaultFont', 9),
            justify=tk.CENTER
        )

        self._create_add_new_files_section()

        # Right side: Status section
        status_frame = ttk.LabelFrame(content_frame, text="Status", padding="5")
        status_frame.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N))
        status_frame.columnconfigure(0, weight=1)

        status_text_frame, self.status_text = create_dark_scrolled_text(
            status_frame,
            wrap=tk.WORD,
            width=50,
            height=15,
            font=('Consolas', 9)
        )
        status_text_frame.grid(row=0, column=0, sticky=(tk.W, tk.E))
        if not self.build_from_scratch and self.parser:
            self.set_default_alignments()
        self._update_add_new_files_visibility()
        apply_button_outline(self.window)

    def _create_add_new_files_section(self):
        self.add_new_title_label = ttk.Label(self.main_frame, text="Add New Files")
        self.add_new_frame = ttk.Frame(self.main_frame, padding="6", relief=tk.GROOVE, borderwidth=1)
        self.add_new_frame.columnconfigure(0, weight=0)
        self.add_new_frame.columnconfigure(1, weight=1)
        self.add_new_frame.rowconfigure(0, weight=1)

        controls_frame = ttk.Frame(self.add_new_frame)
        controls_frame.grid(row=0, column=0, sticky=(tk.N, tk.W), padx=(0, 6))

        browse_btn = ttk.Button(controls_frame, text="Browse", command=self.browse_new_files)
        browse_btn.pack(fill=tk.X, pady=(0, 4))

        clear_btn = ttk.Button(controls_frame, text="Clear", command=self.clear_new_files)
        clear_btn.pack(fill=tk.X)

        list_outer = ttk.Frame(self.add_new_frame, height=150)
        list_outer.grid(row=0, column=1, sticky=(tk.W, tk.E, tk.N, tk.S))
        list_outer.pack_propagate(False)

        self.add_files_canvas = tk.Canvas(
            list_outer,
            highlightthickness=1,
            highlightbackground=APP_BORDER,
            bg=APP_TEXT_BG,
            bd=0,
        )
        self.add_files_scrollbar = ttk.Scrollbar(list_outer, orient=tk.VERTICAL, command=self.add_files_canvas.yview)
        self.add_files_list_frame = ttk.Frame(self.add_files_canvas)
        self.add_files_window = self.add_files_canvas.create_window((0, 0), window=self.add_files_list_frame, anchor="nw")

        self.add_files_canvas.configure(yscrollcommand=self.add_files_scrollbar.set)
        self.add_files_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.add_files_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        if HAS_DND:
            self.add_files_canvas.drop_target_register(DND_FILES)
            self.add_files_canvas.dnd_bind('<<Drop>>', self._on_new_files_drop)
            self.add_files_list_frame.drop_target_register(DND_FILES)
            self.add_files_list_frame.dnd_bind('<<Drop>>', self._on_new_files_drop)

        self.add_files_list_frame.bind(
            "<Configure>",
            lambda event: self.add_files_canvas.configure(scrollregion=self.add_files_canvas.bbox("all"))
        )
        self.add_files_canvas.bind(
            "<Configure>",
            lambda event: self.add_files_canvas.itemconfigure(self.add_files_window, width=event.width)
        )
        self.add_files_canvas.bind("<MouseWheel>", self._on_add_files_mousewheel)
        self.add_files_list_frame.bind("<MouseWheel>", self._on_add_files_mousewheel)
        self._refresh_new_files_list()

    def _on_add_new_files_toggle(self):
        self._update_add_new_files_visibility()

    def _update_add_new_files_visibility(self):
        if self.build_from_scratch or not hasattr(self, 'add_new_frame'):
            return

        if self.bulk_mode.get():
            self.add_new_files_mode.set(False)
            if hasattr(self, 'add_new_files_cb'):
                self.add_new_files_cb.pack_forget()
            self.add_new_title_label.pack_forget()
            self.add_new_frame.pack_forget()
            return

        if hasattr(self, 'add_new_files_cb'):
            self.add_new_files_cb.config(state='normal')
            if not self.add_new_files_cb.winfo_ismapped():
                self.add_new_files_cb.pack(side=tk.LEFT, anchor=tk.W, padx=(16 if self.bulk_bundles else 0, 0))

        if self.add_new_files_mode.get():
            self.add_new_title_label.pack(fill=tk.X, anchor=tk.W, pady=(0, 0), after=self.content_frame)
            self.add_new_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 4), after=self.add_new_title_label)
        else:
            self.add_new_title_label.pack_forget()
            self.add_new_frame.pack_forget()

    def _on_add_files_mousewheel(self, event):
        self.add_files_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

    def _on_new_files_drop(self, event):
        paths = self.window.tk.splitlist(event.data)
        self._append_new_files(paths)

    def browse_new_files(self):
        initial = (
            self.repl_dir_var.get()
            or (os.path.dirname(self.parser.filepath) if self.parser and hasattr(self.parser, 'filepath') else None)
            or os.path.expanduser("~")
        )
        paths = _dialog(
            self.window,
            filedialog.askopenfilenames,
            title="Select Files to Add",
            initialdir=initial,
        )
        self._append_new_files(paths)

    def _append_new_files(self, paths):
        added = 0
        for path in paths or []:
            if not path or not os.path.isfile(path):
                continue
            full_path = os.path.abspath(path)
            key = full_path.lower()
            if key in self.added_new_file_set:
                continue
            self.added_new_file_set.add(key)
            self.added_new_files.append(full_path)
            self.added_new_file_insert_vars[key] = tk.StringVar()
            added += 1
        if added:
            self._refresh_new_files_list()
            self.status_text.insert(tk.END, f"Added {added} new file(s) to insertion list.\n")

    def _remove_new_file(self, path):
        key = path.lower()
        self.added_new_files = [item for item in self.added_new_files if item.lower() != key]
        self.added_new_file_set.discard(key)
        self.added_new_file_insert_vars.pop(key, None)
        self._refresh_new_files_list()

    def clear_new_files(self):
        self.added_new_files.clear()
        self.added_new_file_set.clear()
        self.added_new_file_insert_vars.clear()
        self._refresh_new_files_list()
        self.status_text.insert(tk.END, "Cleared new file insertion list.\n")

    def _refresh_new_files_list(self):
        for child in self.add_files_list_frame.winfo_children():
            child.destroy()

        if not self.added_new_files:
            empty = ttk.Label(self.add_files_list_frame, text="No files selected", foreground='gray', font=('TkDefaultFont', 8))
            empty.pack(anchor=tk.W, padx=4, pady=3)
            return

        header = ttk.Frame(self.add_files_list_frame)
        header.pack(fill=tk.X, padx=2, pady=(1, 2))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="File", font=('TkDefaultFont', 8, 'bold')).grid(row=0, column=0, sticky=(tk.W, tk.E))
        ttk.Label(header, text="Insert Index", font=('TkDefaultFont', 8, 'bold')).grid(row=0, column=1, sticky=tk.W, padx=(4, 3))

        for path in self.added_new_files:
            row = ttk.Frame(self.add_files_list_frame)
            row.pack(fill=tk.X, padx=2, pady=1)
            row.columnconfigure(0, weight=1)
            name = os.path.basename(path)
            label = ttk.Label(row, text=name, font=('TkDefaultFont', 8))
            label.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 3))
            label.bind("<MouseWheel>", self._on_add_files_mousewheel)
            key = path.lower()
            var = self.added_new_file_insert_vars.setdefault(key, tk.StringVar())
            index_entry = ttk.Entry(row, textvariable=var, width=8)
            index_entry.grid(row=0, column=1, sticky=tk.W, padx=(4, 3))
            index_entry.bind("<MouseWheel>", self._on_add_files_mousewheel)
            remove_btn = ttk.Button(row, text="X", width=2, command=lambda p=path: self._remove_new_file(p))
            remove_btn.configure(style='GZ.TButton')
            remove_btn.grid(row=0, column=2, sticky=tk.E)

    def _get_new_file_specs(self):
        specs = []
        max_index = 0
        if self.parser and getattr(self.parser, 'bundle_type', None) == 'pipeworks':
            try:
                max_index = len(self.parser._read_pipeworks_string_entries())
            except Exception:
                main_entries = [entry for entry in (self.parsed_files or []) if not entry.get('is_resource')]
                string_ids = [
                    int(entry.get('string_id', entry.get('file_num', 0)))
                    for entry in main_entries
                    if str(entry.get('string_id', entry.get('file_num', ''))).lstrip("-").isdigit()
                ]
                max_index = (max(string_ids) + 1) if string_ids else len(main_entries)
        for path in self.added_new_files:
            var = self.added_new_file_insert_vars.get(path.lower())
            raw_index = var.get().strip() if var else ""
            insert_index = None
            if raw_index:
                try:
                    insert_index = int(raw_index, 10)
                except ValueError:
                    raise ValueError(f"Insert Index for {os.path.basename(path)} must be a whole number.")
                if insert_index < 0 or insert_index > max_index:
                    raise ValueError(
                        f"Insert Index for {os.path.basename(path)} must be a Name ID between 0 and {max_index}."
                    )
            specs.append({'path': path, 'insert_index': insert_index})
        return specs

    def _write_insert_preview(self, new_file_specs):
        if not new_file_specs:
            return
        self.status_text.insert(tk.END, "Add New Files preview:\n")
        indexed = []
        append = []
        for order, spec in enumerate(new_file_specs):
            name = os.path.basename(spec['path'])
            if spec.get('insert_index') is None:
                append.append((order, name))
            else:
                indexed.append((spec['insert_index'], order, name))
        for target, _order, name in sorted(indexed, key=lambda item: (item[0], item[1])):
            self.status_text.insert(tk.END, f"  {name} -> insert at Name ID {target}\n")
        for _order, name in append:
            self.status_text.insert(tk.END, f"  {name} -> append\n")
        if indexed:
            try:
                if self.parser and getattr(self.parser, 'bundle_type', None) == 'pipeworks':
                    records = self.parser._make_new_file_records(
                        new_file_specs,
                        existing_names=[entry['name'] for entry in (self.parsed_files or [])],
                        vol=False
                    )
                    _items, old_to_new, new_file_indexes, shifted_ranges = self.parser._plan_name_id_insertions(records)
                    if shifted_ranges:
                        self.status_text.insert(tk.END, "  Shifted Name ID ranges:\n")
                        for start, end, delta in shifted_ranges:
                            self.status_text.insert(tk.END, f"    old {start}-{end} -> new {start + delta}-{end + delta}\n")
                    changed = [(old, new) for old, new in sorted(old_to_new.items()) if old != new]
                    if changed:
                        self.status_text.insert(tk.END, "  Name ID remap sample:\n")
                        for old, new in changed[:12]:
                            self.status_text.insert(tk.END, f"    old {old} -> new {new}\n")
                        if len(changed) > 12:
                            self.status_text.insert(tk.END, f"    ... {len(changed) - 12} more\n")
                    for name, new_index in sorted(new_file_indexes.items(), key=lambda item: item[1]):
                        self.status_text.insert(tk.END, f"    new {name} -> {new_index}\n")
            except Exception as err:
                targets = [target for target, _order, _name in indexed]
                self.status_text.insert(tk.END, f"  Existing Name IDs {min(targets)} and after may shift down.\n")
                self.status_text.insert(tk.END, f"  Preview remap detail unavailable: {err}\n")
            self.status_text.insert(tk.END, "  Embedded reference scan/patch: aligned 16/32-bit Name ID values in type-2 entries.\n")
        self.status_text.insert(tk.END, "\n")

    def _on_mode_change(self):
        """Switch UI between Individual and Bulk modes"""
        file_types_ordered = [0, 6, 9, 13, 17, 20]
        if self.bulk_mode.get():
            for idx, type_id in enumerate(file_types_ordered):
                if type_id in self.alignment_dropdowns:
                    if type_id in self.alignment_labels:
                        self.alignment_labels[type_id].grid_remove()
                    self.alignment_dropdowns[type_id].grid_remove()
            self.alignment_separator.grid_remove()
            self.alignment_preset_dropdown.grid_remove()
            self.bulk_align_note.grid(row=0, column=0, columnspan=2, rowspan=len(self.alignment_vars),
                                      sticky=tk.NSEW, pady=10)
            self.action_frame.grid(row=self.alignment_bulk_action_row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(4, 0))
            self.rebuild_btn.config(text="Bulk Rebuild")
            self.reset_alignment_btn.config(state='disabled')
        else:
            self.bulk_align_note.grid_remove()
            self.alignment_separator.grid(row=len(file_types_ordered), column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 5))
            self.alignment_preset_dropdown.grid(row=self.alignment_extension_row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(5, 0))
            self.action_frame.grid(row=self.alignment_action_row, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 0))
            for idx, type_id in enumerate(file_types_ordered):
                if type_id in self.alignment_dropdowns:
                    if type_id in self.alignment_labels:
                        self.alignment_labels[type_id].grid(row=idx, column=0, sticky=tk.W, pady=3, padx=(0, 10))
                    self.alignment_dropdowns[type_id].grid(row=idx, column=1, sticky=tk.W, pady=3)
            self.rebuild_btn.config(text="Rebuild Bundle")
            self.reset_alignment_btn.config(state='normal')
        self._update_add_new_files_visibility()

    def get_alignment_presets(self):
        presets = self.settings.get("alignment_presets", {})
        return presets if isinstance(presets, dict) else {}

    def refresh_alignment_preset_dropdown(self, selected=None):
        values = []
        if self.default_alignment_preset_name:
            values.append(self.default_alignment_preset_name)
        values.extend(sorted(self.get_alignment_presets().keys(), key=str.lower))
        values.append("Save Current Preset...")
        self.alignment_preset_dropdown.config(values=values)
        if selected and selected in values:
            self.alignment_preset_var.set(selected)
        elif self.default_alignment_preset_name:
            self.alignment_preset_var.set(self.default_alignment_preset_name)
        elif values:
            self.alignment_preset_var.set(values[0])
        else:
            self.alignment_preset_var.set("")

    def get_current_alignment_values(self):
        values = {}
        for type_id, var in self.alignment_vars.items():
            value = var.get()
            if value and value != "N/A":
                values[str(type_id)] = value
        return values

    def apply_alignment_values(self, values):
        alignment_values = [16, 32, 64, 128, 256, 512, 1024, 2048]
        for type_id in self.alignment_vars:
            value = values.get(str(type_id), values.get(type_id, "N/A")) if isinstance(values, dict) else "N/A"
            if value == "N/A":
                self.alignment_dropdowns[type_id].config(state='disabled', values=['N/A'])
                self.alignment_vars[type_id].set('N/A')
            else:
                self.alignment_dropdowns[type_id].config(state='readonly', values=alignment_values)
                self.alignment_vars[type_id].set(str(value))

    def save_current_alignment_preset(self):
        name = simpledialog.askstring(
            "Save Alignment Preset",
            "Preset name:",
            parent=self.window,
        )
        if not name:
            self.refresh_alignment_preset_dropdown()
            return
        name = name.strip()
        if not name:
            self.refresh_alignment_preset_dropdown()
            return
        self.settings.setdefault("alignment_presets", {})[name] = self.get_current_alignment_values()
        save_app_settings(self.settings)
        self.refresh_alignment_preset_dropdown(selected=name)
        self.status_text.insert(tk.END, f"Saved block alignment preset: {name}\n")

    def on_alignment_preset_selected(self, event=None):
        if self._loading_alignment_preset:
            return
        selected = self.alignment_preset_var.get()
        if selected == "Save Current Preset...":
            self.save_current_alignment_preset()
            return
        if selected == self.default_alignment_preset_name:
            self.set_default_alignments()
            return
        preset = self.get_alignment_presets().get(selected)
        if preset is not None:
            self.apply_alignment_values(preset)
            self.status_text.insert(tk.END, f"Applied block alignment preset: {selected}\n")

    def reset_alignments(self):
        """Reset alignment dropdowns to defaults for the selected output bundle type."""
        if self.output_file_var.get():
            self.update_alignments_on_file_change()
        elif not self.build_from_scratch and self.parser:
            self.set_default_alignments()
        else:
            for type_id in self.alignment_vars:
                self.alignment_vars[type_id].set('N/A')
                self.alignment_dropdowns[type_id].config(state='disabled', values=['N/A'])
            self.default_alignment_preset_name = ""
            self.refresh_alignment_preset_dropdown()
        self.status_text.insert(tk.END, "Block alignment values reset.\n")

    def _extension_alignment_defaults(self, filepath):
        filepath_lower = (filepath or "").lower()
        if filepath_lower.endswith(('.cmg', '.ccg', '.cmf', '.ccf')):
            return {
                0: 64,    # Static Mesh
                6: 16,    # Material
                9: 64,    # Texture
                13: 16,   # Palette
                17: 64,   # Rigged Mesh
                20: 16,   # Particle
            }
        if filepath_lower.endswith(('.cmp', '.bdp', '.bdl', '.clp', '.clf', '.bsf')):
            return {
                0: 128,   # Static Mesh
                6: 16,    # Material
                9: 64,    # Texture
                13: 16,   # Palette
                17: 128,  # Rigged Mesh
                20: 16,   # Particle
            }
        return {
            0: 512,   # Static Mesh
            6: 16,    # Material
            9: 128,   # Texture
            13: 16,   # Palette
            17: 512,  # Rigged Mesh
            20: 16,   # Particle
        }

    def _detected_alignment_defaults(self):
        if not self.parser or self.parser.bundle_type != 'pipeworks':
            return {}
        entries = self.parsed_files or []
        main_files = [entry for entry in entries if not entry.get('is_resource')]
        return self.parser.detect_alignments_by_type(main_files)

    def _apply_alignment_defaults(self, defaults):
        alignment_values = [16, 32, 64, 128, 256, 512, 1024, 2048]
        for type_id, value in defaults.items():
            if type_id in self.alignment_vars:
                self.alignment_dropdowns[type_id].config(state='readonly', values=alignment_values)
                self.alignment_vars[type_id].set(value)

    def set_default_alignments(self):
        """Set default alignment values from the premade extension presets."""
        filepath = self.parser.filepath.lower()
        defaults = self._extension_alignment_defaults(filepath)
        self._apply_alignment_defaults(defaults)

        ext = os.path.splitext(filepath)[1].upper().lstrip('.')
        self.default_alignment_preset_name = f".{ext} Preset" if ext else "Bundle Preset"
        self._loading_alignment_preset = True
        self.refresh_alignment_preset_dropdown()
        self._loading_alignment_preset = False

    def update_alignments_on_file_change(self):
        """Update alignment defaults when output file extension changes"""
        output_path = self.output_file_var.get()
        if not output_path:
            # Reset to N/A if no file selected
            for type_id in self.alignment_vars:
                self.alignment_vars[type_id].set('N/A')
                self.alignment_dropdowns[type_id].config(state='disabled', values=['N/A'])
            self.default_alignment_preset_name = ""
            self.refresh_alignment_preset_dropdown()
            return

        filepath_lower = output_path.lower()

        ext = os.path.splitext(output_path)[1].upper().lstrip('.')
        self.default_alignment_preset_name = f".{ext} Preset" if ext else "Bundle Preset"
        self._loading_alignment_preset = True
        self.refresh_alignment_preset_dropdown()
        self._loading_alignment_preset = False

        defaults = self._extension_alignment_defaults(filepath_lower)
        self._apply_alignment_defaults(defaults)

    def browse_replacement_dir(self):
        """Browse for replacement files directory"""
        initial = (
            self.repl_dir_var.get()
            or (os.path.dirname(self.parser.filepath) if self.parser and hasattr(self.parser, 'filepath') else None)
            or os.path.expanduser("~")
        )
        directory = _dialog(
            self.window,
            filedialog.askdirectory,
            title="Select Directory with Replacement Files",
            initialdir=initial,
        )
        if directory:
            self.repl_dir_var.set(directory)
            if self.bundle_key:
                self.settings = load_app_settings()
                self.settings.setdefault("rebuild_replacement_dirs", {})[self.bundle_key] = directory
                save_app_settings(self.settings)
            self.status_text.insert(tk.END, f"Replacement directory: {directory}\n")

    def browse_output_file(self):
        """Browse for output bundle file location"""
        # Derive default filename and extension from the bundle being parsed
        initial_file = ""
        default_ext = "*.*"
        if not self.build_from_scratch and self.parser and hasattr(self.parser, 'filepath'):
            src = self.parser.filepath
            initial_file = os.path.basename(src)
            ext = os.path.splitext(src)[1].lower()
            if ext:
                default_ext = ext

        ext_upper = default_ext.lstrip('.').upper()
        filetypes = [
            (f"{ext_upper} Files", f"*{default_ext}"),
            ("Bundle Files", "*.bdg *.cmg *.cmp *.clp *.clf *.bdp *.bdl *.bsf *.vol *.ccg *.cmf *.ccf"),
            ("All Files", "*.*"),
        ]

        initialdir = (
            os.path.dirname(self.parser.filepath)
            if not self.build_from_scratch and self.parser and hasattr(self.parser, 'filepath')
            else os.path.expanduser("~")
        )
        filepath = _dialog(
            self.window,
            filedialog.asksaveasfilename,
            title="Save Rebuilt Bundle As",
            initialdir=initialdir,
            initialfile=initial_file,
            defaultextension=default_ext,
            filetypes=filetypes,
        )
        if filepath:
            self.output_file_var.set(filepath)
            self.status_text.insert(tk.END, f"Output file: {filepath}\n")
        return filepath

    def _get_mod_filenames(self, replacement_dir):
        """Return a set of lowercase filenames present in the replacement directory"""
        try:
            return {f.lower() for f in os.listdir(replacement_dir) if os.path.isfile(os.path.join(replacement_dir, f))}
        except Exception:
            return set()

    def _bundle_has_matches(self, bundle_path, mod_filenames):
        """Return True if any entry in the bundle matches a mod filename.
        Handles both direct bundle files and ZIP-wrapped bundles."""
        try:
            actual_path = bundle_path
            tmp_dir = None

            if bundle_path.lower().endswith('.zip'):
                ensure_app_dirs()
                tmp_dir = tempfile.mkdtemp(prefix="gzbuildr_bulk_check_", dir=str(get_temp_dir()))
                bundle_extensions = ('.bdg', '.cmg', '.cmp', '.clp', '.clf', '.bdp', '.bdl', '.bsf', '.vol', '.ccg', '.cmf', '.ccf')
                with zipfile.ZipFile(bundle_path, 'r') as zf:
                    for member in zf.namelist():
                        if member.lower().endswith(bundle_extensions):
                            zf.extract(member, tmp_dir)
                            actual_path = os.path.join(tmp_dir, member)
                            break
                    else:
                        return False

            tmp_parser = PipeworksParser(actual_path)
            entries = tmp_parser.parse()
            if not entries or (len(entries) == 1 and 'error' in entries[0]):
                return False
            for entry in entries:
                if entry.get('name', '').lower() in mod_filenames:
                    return True
        except Exception:
            pass
        finally:
            if tmp_dir:
                shutil.rmtree(tmp_dir, ignore_errors=True)
        return False

    def _backup_existing_bulk_output(self, output_path):
        """Move an existing bulk output file into an adjacent backups folder."""
        if not output_path or not os.path.exists(output_path):
            return None

        backup_dir = os.path.join(os.path.dirname(output_path), "backups")
        os.makedirs(backup_dir, exist_ok=True)

        base_name = os.path.basename(output_path)
        backup_path = os.path.join(backup_dir, f"{base_name}.bak")
        index = 1
        while os.path.exists(backup_path):
            backup_path = os.path.join(backup_dir, f"{base_name}.bak{index}")
            index += 1

        shutil.move(output_path, backup_path)
        return backup_path

    def rebuild(self):
        """Perform the rebuild operation"""
        replacement_dir = self.repl_dir_var.get()
        if replacement_dir and self.bundle_key:
            self.settings = load_app_settings()
            self.settings.setdefault("rebuild_replacement_dirs", {})[self.bundle_key] = replacement_dir
            save_app_settings(self.settings)

        if not replacement_dir and (self.build_from_scratch or self.bulk_mode.get()):
            messagebox.showwarning("Missing Input", "Please select a replacement files directory.")
            return

        if self.bulk_mode.get():
            self._bulk_rebuild(replacement_dir)
            return

        output_path = self.browse_output_file()
        if not output_path:
            return

        if self.build_from_scratch:
            self.build_from_directory(replacement_dir, output_path)
            return

        # Get custom alignment values from dropdowns
        custom_alignments = {}
        for type_id, var in self.alignment_vars.items():
            value = var.get()
            if value != 'N/A':
                try:
                    custom_alignments[type_id] = int(value)
                except ValueError:
                    pass

        # Log alignment settings
        self.status_text.insert(tk.END, "\nBlock Alignment Settings:\n")
        type_names = {0: "Static Mesh", 6: "Material", 9: "Texture", 13: "Palette", 17: "Rigged Mesh", 20: "Particle"}
        for type_id, alignment in sorted(custom_alignments.items()):
            self.status_text.insert(tk.END, f"  {type_names.get(type_id, f'Type {type_id}')}: {alignment} bytes\n")
        self.status_text.insert(tk.END, "\n")

        self.status_text.insert(tk.END, "Rebuilding bundle file...\n")
        self.status_text.update()

        try:
            new_file_paths = self._get_new_file_specs() if self.add_new_files_mode.get() else []
        except ValueError as err:
            messagebox.showerror("Invalid Insert Index", str(err))
            self.status_text.insert(tk.END, f"Invalid Insert Index: {err}\n")
            return
        if new_file_paths:
            self.status_text.insert(tk.END, f"Adding {len(new_file_paths)} brand-new file(s).\n")
            self._write_insert_preview(new_file_paths)
            if any(spec.get('insert_index') is not None for spec in new_file_paths):
                proceed = messagebox.askyesno(
                    "Confirm Indexed Insert",
                    "One or more new files will be inserted into the bundle Name ID/string-table order.\n\n"
                    "Existing Name IDs at and after each target will shift, and GZBuildr will patch aligned "
                    "16/32-bit Name ID references in type-2 entries where it can identify them.\n\n"
                    "Continue?"
                )
                if not proceed:
                    self.status_text.insert(tk.END, "Indexed insertion cancelled.\n")
                    return

        if self.parser.bundle_type == 'vol':
            success = self.parser.rebuild_vol(output_path, self.parsed_files, replacement_dir, new_file_paths)
        else:
            success = self.parser.rebuild_bdg(
                output_path,
                self.parsed_files,
                replacement_dir,
                custom_alignments,
                new_file_paths
            )

        if success:
            final_path = output_path
            if self.zip_source:
                bundle_name = os.path.basename(output_path)
                zip_name = os.path.splitext(bundle_name)[0] + '.zip'
                zip_out = os.path.join(os.path.dirname(output_path), zip_name)
                try:
                    with zipfile.ZipFile(zip_out, 'w', zipfile.ZIP_DEFLATED) as zf:
                        zf.write(output_path, bundle_name)
                    os.remove(output_path)
                    final_path = zip_out
                    self.status_text.insert(tk.END, f"Re-packaged into ZIP: {zip_name}\n")
                except Exception as zip_err:
                    self.status_text.insert(tk.END, f"Warning: could not create ZIP: {zip_err}\n")

            messagebox.showinfo("Success", f"Bundle rebuilt successfully!\n\nSaved to: {final_path}")
            self.status_text.insert(tk.END, f"✓ Bundle rebuilt successfully!\n")
            self.output_text_callback(f"\nBundle rebuilt successfully: {final_path}\n")
        else:
            messagebox.showerror("Error", "Failed to rebuild bundle file. Check console for errors.")
            self.status_text.insert(tk.END, "✗ Failed to rebuild bundle file.\n")
            self.output_text_callback("Failed to rebuild bundle file.\n")

    def _bulk_rebuild(self, replacement_dir):
        """Rebuild all bundles in bulk_bundles that contain at least one matching mod file"""
        initial_output = (
            os.path.dirname(self.parser.filepath)
            if self.parser and hasattr(self.parser, 'filepath')
            else os.path.expanduser("~")
        )
        output_dir = _dialog(
            self.window,
            filedialog.askdirectory,
            title="Select Bulk Rebuild Output Directory",
            initialdir=initial_output,
        )
        if not output_dir:
            return

        if not self.bulk_bundles:
            messagebox.showwarning("No Bundles", "No bundles are loaded for bulk rebuild.")
            return

        mod_filenames = self._get_mod_filenames(replacement_dir)
        if not mod_filenames:
            messagebox.showwarning("No Mod Files", "No files found in the replacement directory.")
            return

        self.status_text.insert(tk.END, f"\n=== Bulk Rebuild ===\n")
        self.status_text.insert(tk.END, f"Replacement dir: {replacement_dir}\n")
        self.status_text.insert(tk.END, f"Output dir:      {output_dir}\n")
        self.status_text.insert(tk.END, f"Mod files found: {len(mod_filenames)}\n")
        self.status_text.insert(tk.END, f"Bundles to scan: {len(self.bulk_bundles)}\n\n")
        self.status_text.update()
        self.rebuild_btn.config(state='disabled')

        rebuilt = 0
        skipped = 0
        failed = 0
        backup_paths = []

        for bundle_path in self.bulk_bundles:
            bundle_name = os.path.basename(bundle_path)
            self.status_text.insert(tk.END, f"[ {bundle_name} ]\n")
            self.status_text.update()

            if not self._bundle_has_matches(bundle_path, mod_filenames):
                self.status_text.insert(tk.END, f"  -> No matching mod files - skipped\n\n")
                skipped += 1
                continue

            is_zip = bundle_path.lower().endswith('.zip')
            tmp_dir = None

            try:
                actual_bundle_path = bundle_path
                inner_bundle_name = bundle_name

                if is_zip:
                    ensure_app_dirs()
                    tmp_dir = tempfile.mkdtemp(prefix="gzbuildr_bulk_", dir=str(get_temp_dir()))
                    bundle_extensions = ('.bdg', '.cmg', '.cmp', '.clp', '.clf', '.bdp', '.bdl', '.bsf', '.vol', '.ccg', '.cmf', '.ccf')
                    with zipfile.ZipFile(bundle_path, 'r') as zf:
                        for member in zf.namelist():
                            if member.lower().endswith(bundle_extensions):
                                zf.extract(member, tmp_dir)
                                actual_bundle_path = os.path.join(tmp_dir, member)
                                inner_bundle_name = os.path.basename(member)
                                break
                        else:
                            self.status_text.insert(tk.END, f"  -> No bundle inside ZIP - skipped\n\n")
                            skipped += 1
                            continue

                tmp_output_path = os.path.join(tmp_dir if is_zip else output_dir, inner_bundle_name) if is_zip else os.path.join(output_dir, inner_bundle_name)

                tmp_parser = PipeworksParser(actual_bundle_path)
                tmp_entries = tmp_parser.parse()

                if not tmp_entries or (len(tmp_entries) == 1 and 'error' in tmp_entries[0]):
                    self.status_text.insert(tk.END, f"  -> Parse error - skipped\n\n")
                    skipped += 1
                    continue

                if not is_zip:
                    backup_path = self._backup_existing_bulk_output(tmp_output_path)
                    if backup_path:
                        backup_paths.append(backup_path)
                        self.status_text.insert(tk.END, f"  -> Existing output moved to backups: {os.path.basename(backup_path)}\n")

                if tmp_parser.bundle_type == 'vol':
                    success = tmp_parser.rebuild_vol(tmp_output_path, tmp_entries, replacement_dir)
                else:
                    preset_alignments = self._extension_alignment_defaults(actual_bundle_path)
                    self.status_text.insert(
                        tk.END,
                        f"  -> Alignment preset: {os.path.splitext(inner_bundle_name)[1].upper().lstrip('.') or 'default'}\n"
                    )
                    success = tmp_parser.rebuild_bdg(tmp_output_path, tmp_entries, replacement_dir, preset_alignments)

                if success:
                    if is_zip:
                        zip_out_name = os.path.splitext(bundle_name)[0] + '.zip'
                        zip_out = os.path.join(output_dir, zip_out_name)
                        backup_path = self._backup_existing_bulk_output(zip_out)
                        if backup_path:
                            backup_paths.append(backup_path)
                            self.status_text.insert(tk.END, f"  -> Existing output moved to backups: {os.path.basename(backup_path)}\n")
                        with zipfile.ZipFile(zip_out, 'w', zipfile.ZIP_DEFLATED) as zf:
                            zf.write(tmp_output_path, inner_bundle_name)
                        final_out = zip_out
                    else:
                        final_out = tmp_output_path

                    self.status_text.insert(tk.END, f"  -> Rebuilt OK: {os.path.basename(final_out)}\n\n")
                    rebuilt += 1
                else:
                    self.status_text.insert(tk.END, f"  -> Rebuild FAILED\n\n")
                    failed += 1

            except Exception as exc:
                self.status_text.insert(tk.END, f"  -> Error: {exc}\n\n")
                failed += 1
            finally:
                if tmp_dir:
                    shutil.rmtree(tmp_dir, ignore_errors=True)

            self.status_text.update()

        self.rebuild_btn.config(state='normal')

        summary = (
            f"Bulk rebuild complete!\n\n"
            f"Rebuilt:  {rebuilt}\n"
            f"Skipped (no matches): {skipped}\n"
            f"Failed:   {failed}"
        )
        if backup_paths:
            backup_dir = os.path.dirname(backup_paths[0])
            summary += (
                f"\n\nExisting output files were moved into:\n"
                f"{backup_dir}"
            )
        self.status_text.insert(tk.END, f"=== Done ===\n{summary}\n")
        self.output_text_callback(f"\nBulk rebuild complete - {rebuilt} rebuilt, {skipped} skipped, {failed} failed\n")
        messagebox.showinfo("Bulk Rebuild Complete", summary)

    def build_from_directory(self, source_dir, output_path):
        """Build a new bundle from directory without needing a parsed file"""
        output_ext = os.path.splitext(output_path)[1].lower()
        pipeworks_exts = ('.bdg', '.cmg', '.cmp', '.clp', '.clf', '.bdp', '.bdl', '.bsf', '.ccg', '.cmf', '.ccf')

        if output_ext in pipeworks_exts:
            self.status_text.insert(tk.END, f"\n=== Building New Pipeworks Bundle ===\n")
            self.status_text.insert(tk.END, f"Source directory: {source_dir}\n")
            self.status_text.update()
            builder = PipeworksParser(output_path)
            try:
                custom_alignments = {}
                for type_id, var in self.alignment_vars.items():
                    value = var.get()
                    if value != 'N/A':
                        try:
                            custom_alignments[type_id] = int(value)
                        except ValueError:
                            pass
                success = builder.build_pipeworks_from_directory(source_dir, output_path, custom_alignments)
                if success:
                    self.status_text.insert(tk.END, f"\nPipeworks bundle created successfully!\n")
                    self.status_text.insert(tk.END, f"Output: {output_path}\n")
                    messagebox.showinfo("Success", f"Pipeworks bundle created successfully!\n\nOutput: {output_path}")
                    self.output_text_callback(f"\nPipeworks bundle created successfully: {output_path}\n")
                else:
                    self.status_text.insert(tk.END, "\nFailed to create Pipeworks bundle. Extract the source with this version of GZBuildr first so a rebuild manifest is available.\n")
                    messagebox.showerror(
                        "Missing Manifest",
                        "Cannot safely build a Pipeworks bundle from this folder.\n\n"
                        "Please extract the original bundle with this version of GZBuildr first, then build from the generated bundle folder."
                    )
                return
            except Exception as e:
                self.status_text.insert(tk.END, f"\nError creating Pipeworks bundle: {e}\n")
                messagebox.showerror("Error", f"Failed to create Pipeworks bundle:\n{e}")
                import traceback
                traceback.print_exc()
                return

        def log(text):
            self.status_text.insert(tk.END, text)
            self.status_text.see(tk.END)
            self.status_text.update()

        try:
            build_vol_from_directory(source_dir, output_path, log)
            messagebox.showinfo("Success", f"VOL bundle created successfully!\n\nOutput: {output_path}")
            self.output_text_callback(f"\nVOL bundle created successfully: {output_path}\n")
        except Exception as e:
            self.status_text.insert(tk.END, f"\nError creating VOL bundle: {e}\n")
            messagebox.showerror("Error", f"Failed to create VOL bundle:\n{e}")
            import traceback
            traceback.print_exc()

    def destroy(self):
        """Destroy window"""
        self.window.destroy()


class PipeworksGUI:
    def __init__(self, root):
        self.root = root
        self.settings = load_app_settings()
        self._restoring_last_input = False
        self.theme_mode = self.settings.get("theme_mode", "dark")
        self.root.title("GZBuildr - Bundle Manager")
        self.root.geometry("800x700")

        self.parser = None
        self.parsed_files = []
        self.child_windows = []  # Track all child windows
        self.bundle_files = []  # List of bundle files when directory selected
        self.current_bundle_dir = None  # Current directory path
        self.last_extract_dir = None  # Track last extraction directory for auto-populating rebuild
        self._zip_temp_dirs = []  # Temp dirs created for ZIP extraction
        self._current_zip_source = None  # ZIP path if currently selected item came from a ZIP
        self._current_zip_bundle = None  # Extracted bundle path from current ZIP
        self.extract_selection_bundle_key = None
        self.extract_selection_file_nums = set()
        self.text_mode = None  # 'bsf', 'txt', 'ifc', 'ifl', 'xfg', 'prx', 'edf', 'pvm', 'char_data', 'level_data', or 'skeleton_type3'
        self.text_source_path = None
        self.bundle_entry_edit = None
        self.bundle_entry_session = None
        self.texture_preview_session = None
        self.texture_preview_entry = None
        self.texture_preview_image = None
        self.static_mesh_preview_session = None
        self.static_mesh_preview_entry = None
        self.static_mesh_preview_viewer = None
        self.static_mesh_export_parts = []
        self.fdf_font_preview_image = None
        self._updating_bundle_dropdown = False
        self.bundle_search_generation = 0
        self.bundle_search_window = None
        self.bundle_search_results = []

        self._disable_combobox_mousewheel()

        # Set up main window close handler
        self.root.protocol("WM_DELETE_WINDOW", self.on_main_window_close)

        # Bring main window to front when clicked
        self.root.after(100, self.root.lift)
        self.root.after(100, self.root.focus_force)

        # Main container
        main_frame = ttk.Frame(root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        # Configure grid weights
        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(3, weight=1)

        # File input section
        input_frame = ttk.LabelFrame(main_frame, text="Input Bundle / Directory / Script", padding="5")
        input_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        input_frame.columnconfigure(0, weight=1)

        self.file_path_var = tk.StringVar()
        self.file_entry = ttk.Entry(input_frame, textvariable=self.file_path_var)
        self.file_entry.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))

        # Make entry look readonly but still accept drag-and-drop
        self.file_entry.configure(state='readonly')

        browse_btn = ttk.Button(input_frame, text="Browse", command=self.browse_file)
        browse_btn.grid(row=0, column=1, padx=(0, 5))

        folder_btn = ttk.Button(input_frame, text="Folder", command=self.browse_directory)
        folder_btn.grid(row=0, column=2)

        # Buttons frame
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=1, column=0, pady=(0, 10))

        self.extract_btn = ttk.Button(button_frame, text="Extract", command=self.extract_files, state=tk.DISABLED)
        self.extract_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.rebuild_btn = ttk.Button(button_frame, text="Rebuild", command=self.rebuild_bdg, state=tk.DISABLED)
        self.rebuild_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.build_btn = ttk.Button(button_frame, text="Build", command=self.open_build_menu)
        self.build_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.settings_btn = ttk.Button(button_frame, text="Settings", command=self.open_settings_window)
        self.settings_btn.pack(side=tk.LEFT)

        self.editor_back_btn = ttk.Button(button_frame, text="Back", command=self.back_to_bundle_view)
        self.editor_back_btn.pack(side=tk.LEFT, padx=(5, 0))
        self.editor_back_btn.pack_forget()

        # Bundle selection frame (for directory mode)
        self.bundle_select_frame = ttk.Frame(main_frame)
        self.bundle_select_frame.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        self.bundle_select_frame.columnconfigure(1, weight=1)

        self.bundle_label = ttk.Label(self.bundle_select_frame, text="Bundle:")
        self.bundle_label.grid(row=0, column=0, padx=(0, 5))

        self.bundle_dropdown = ttk.Combobox(self.bundle_select_frame, state='readonly')
        self.bundle_dropdown.grid(row=0, column=1, sticky=(tk.W, tk.E))
        self.bundle_dropdown.bind('<<ComboboxSelected>>', self.on_bundle_selected)

        self.syntax_progress_var = tk.DoubleVar(value=0.0)
        self.syntax_progress_bar = ttk.Progressbar(
            self.bundle_select_frame,
            variable=self.syntax_progress_var,
            maximum=100.0,
            mode='determinate',
        )
        self.syntax_progress_bar.grid(row=0, column=1, sticky=(tk.W, tk.E))
        self.syntax_progress_bar.grid_remove()
        self.syntax_progress_active = False
        self.syntax_progress_restore = None

        self.bundle_entry_back_btn = ttk.Button(self.bundle_select_frame, text="Back", command=self.back_to_bundle_view)
        self.bundle_entry_back_btn.grid(row=0, column=2, padx=(5, 0))
        self.hide_editor_back_button()

        # Hide bundle selector by default
        self.bundle_select_frame.grid_remove()

        # Output section
        self.output_frame = ttk.LabelFrame(main_frame, text="Output", padding="5")
        self.output_frame.grid(row=3, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.output_frame.columnconfigure(0, weight=1)
        self.output_frame.rowconfigure(0, weight=1)

        # Output text area with scrollbar
        output_text_frame, self.output_text = create_dark_scrolled_text(
            self.output_frame,
            show_horizontal=True,
            show_diff_marker=True,
            wrap=tk.NONE,
            width=80,
            height=25,
            font=('Consolas', 9),
            undo=True,
            autoseparators=True,
            maxundo=-1
        )
        output_text_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.output_text.tag_configure("find_match", background="#f59f00", foreground="black")
        self.syntax_highlight_after_id = None
        self.syntax_lazy_after_id = None
        self.syntax_lazy_generation = 0
        self.syntax_highlighted_intervals = []
        self.syntax_view_after_id = None
        self.syntax_prefetch_after_id = None
        self.syntax_prefetch_target = None
        self._syntax_pattern_cache = None
        self.character_data_decode_generation = 0
        self.editor_load_generation = 0
        self.loading_text_editor = False
        self.editor_original_text = ""
        self.editor_original_lines = []
        self.monster_data_disassembly_active = False
        self.monster_data_editable_text = None
        self.monster_data_editable_baseline = None
        self.monster_data_disassembly_baseline = None
        self.monster_data_disassembly_generation = 0
        self.editor_diff_after_id = None
        self.editor_diff_marks = {}
        self.editor_manual_diff_marks = {}
        self.editor_deleted_anchor_hints = {}
        self.editor_restored_deleted_chunks = set()
        self.editor_diff_tooltip = None
        self.root_toc_fold_tags = {}
        self.root_toc_jump_targets = {}
        self.root_toc_jump_marks = []
        self.pvm_global_folds = {}
        self.editor_diff_canvas = getattr(self.output_text, "_diff_marker_canvas", None)
        self.output_text._diff_marker_scroll_callback = self._draw_editor_diff_markers
        self.output_text._syntax_scroll_callback = self.schedule_visible_editor_syntax
        self.configure_syntax_tags()
        self.configure_editor_diff_tags()
        self._setup_editor_diff_marker_bindings()

        self.find_var = tk.StringVar()
        self.find_frame = tk.Frame(self.output_frame, bd=1, relief=tk.SOLID, bg=APP_BG, highlightbackground=APP_BORDER)
        find_font = ('TkDefaultFont', 8)
        self.find_entry = tk.Entry(
            self.find_frame,
            textvariable=self.find_var,
            width=28,
            font=find_font,
            bd=1,
            relief=tk.SUNKEN,
            bg=APP_TEXT_BG,
            fg=APP_TEXT_FG,
            insertbackground=APP_TEXT_FG,
            selectbackground=APP_TEXT_SELECT_BG,
            selectforeground=APP_TEXT_SELECT_FG,
        )
        self.find_entry.pack(side=tk.LEFT, padx=(2, 2), pady=1)
        tk.Button(
            self.find_frame,
            text="Find",
            command=self.find_next_in_editor,
            width=4,
            font=find_font,
            padx=1,
            pady=0,
            bg=APP_BUTTON_BG,
            fg=APP_TEXT_FG,
            activebackground=APP_BUTTON_ACTIVE_BG,
            activeforeground=APP_TEXT_FG,
        ).pack(side=tk.LEFT, padx=(0, 1), pady=1)
        tk.Button(
            self.find_frame,
            text="X",
            command=self.hide_find_bar,
            width=2,
            font=find_font,
            padx=1,
            pady=0,
            bg=APP_BUTTON_BG,
            fg=APP_TEXT_FG,
            activebackground=APP_BUTTON_ACTIVE_BG,
            activeforeground=APP_TEXT_FG,
        ).pack(side=tk.LEFT, padx=(0, 1), pady=1)
        self.find_entry.bind("<Return>", lambda _event: self.find_next_in_editor())
        self.find_entry.bind("<Escape>", lambda _event: self.hide_find_bar())
        self.root.bind("<Configure>", lambda _event: self._position_find_bar() if self.find_frame.winfo_ismapped() else None)
        self.root.bind_all("<Control-f>", self._on_editor_find_hotkey)
        self.root.bind_all("<Control-F>", self._on_editor_find_hotkey)

        self.output_text.bind("<Control-s>", self._on_editor_save_hotkey)
        self.output_text.bind("<Control-S>", self._on_editor_save_hotkey)
        self.output_text.bind("<Control-z>", self._on_editor_undo_hotkey)
        self.output_text.bind("<Control-Z>", self._on_editor_undo_hotkey)
        self.output_text.bind("<Control-y>", self._on_editor_redo_hotkey)
        self.output_text.bind("<Control-Y>", self._on_editor_redo_hotkey)
        self.output_text.bind("<Control-f>", self._on_editor_find_hotkey)
        self.output_text.bind("<Control-F>", self._on_editor_find_hotkey)
        self.output_text.bind("<KeyRelease>", self._on_editor_key_release)
        self.output_text.bind("<<Modified>>", self._on_editor_text_modified)
        self.output_text.bind("<<Paste>>", lambda _event: self.root.after(1, lambda: self.refresh_visible_editor_formatting(force_syntax=True)))
        self.output_text.bind("<<Cut>>", lambda _event: self.root.after(1, lambda: self.refresh_visible_editor_formatting(force_syntax=True)))
        self.output_text.bind("<ButtonRelease>", lambda _event: self._draw_editor_diff_markers())
        self.output_text.bind("<Configure>", lambda _event: self.root.after_idle(self.refresh_visible_editor_formatting))
        self.output_text.tag_bind("root_table_header", "<Enter>", lambda _event: self.output_text.config(cursor="hand2"))
        self.output_text.tag_bind("root_table_header", "<Leave>", lambda _event: self.output_text.config(cursor=""))
        self.output_text.tag_bind("root_table_header", "<Button-1>", self._on_root_table_header_click)
        self.output_text.tag_bind("pvm_fold_header", "<Enter>", lambda _event: self.output_text.config(cursor="hand2"))
        self.output_text.tag_bind("pvm_fold_header", "<Leave>", lambda _event: self.output_text.config(cursor=""))
        self.output_text.tag_bind("pvm_fold_header", "<Button-1>", self._on_root_table_header_click)

        # Enable drag and drop (must be after output_text is created)
        self.setup_drag_drop()
        self.root.after_idle(self.show_find_bar)
        apply_button_outline(self.root)
        self.root.after(100, self.restore_last_input)
        self.root.after(1200, self.begin_startup_update_check)

    def get_last_initial_dir(self):
        last_path = self.settings.get("last_input_path", "")
        if last_path:
            if os.path.isdir(last_path):
                return last_path
            if os.path.isfile(last_path):
                return os.path.dirname(last_path)
        return self.current_bundle_dir or os.path.expanduser("~")

    def _disable_combobox_mousewheel(self):
        def block_scroll(event=None):
            return "break"

        for sequence in ("<MouseWheel>", "<Button-4>", "<Button-5>"):
            try:
                self.root.bind_class("TCombobox", sequence, block_scroll, add="+")
            except Exception:
                pass

    def show_editor_back_button(self):
        try:
            self.bundle_entry_back_btn.grid_remove()
        except Exception:
            pass
        if not self.editor_back_btn.winfo_manager():
            self.editor_back_btn.pack(side=tk.LEFT, padx=(5, 0))

    def hide_editor_back_button(self):
        try:
            self.bundle_entry_back_btn.grid_remove()
        except Exception:
            pass
        self.editor_back_btn.pack_forget()

    def toggle_theme(self):
        self.theme_mode = "light" if self.theme_mode == "dark" else "dark"
        self.set_theme_mode(self.theme_mode)

    def set_theme_mode(self, mode):
        self.theme_mode = mode if mode in THEME_PALETTES else "dark"
        self.settings["theme_mode"] = self.theme_mode
        save_app_settings(self.settings)
        configure_app_theme(self.root, self.theme_mode)
        self.configure_syntax_tags()
        self._refresh_bundle_entry_link_colors()
        self.configure_editor_diff_tags()
        self.start_lazy_syntax_highlight(clear_existing=False)
        self.schedule_editor_diff_update()
        self.apply_theme_to_open_windows()
        self.configure_editor_diff_tags()

    def apply_theme_to_open_windows(self):
        targets = [self.root]
        try:
            targets.extend(child for child in self.root.winfo_children() if child.winfo_class() == "Toplevel")
        except Exception:
            pass
        for window in self.child_windows:
            if window not in targets:
                targets.append(window)
        for window in targets:
            try:
                apply_runtime_theme(window)
                apply_button_outline(window)
                set_dark_title_bar(window)
            except Exception:
                pass

    def show_update_result(self, result=None, error=None, parent=None, button=None, show_all=True):
        parent = parent or self.root
        try:
            if not parent.winfo_exists():
                return
        except Exception:
            return
        try:
            if button is not None and button.winfo_exists():
                button.config(text="Check Updates", state=tk.NORMAL)
        except Exception:
            pass

        if error is not None:
            if show_all:
                messagebox.showerror("Update Check", str(error), parent=parent)
            return

        result = result or {}
        status = result.get("status")
        latest = result.get("latest_tag") or "unknown"
        if status == "update":
            if result.get("reason") == "checksum":
                detail = (
                    f"A newer GZBuildr {APP_VERSION} build is available.\n\n"
                    "The release version is the same, but the downloadable EXE contains a mini-fix."
                )
            else:
                detail = (
                    "A new GZBuildr release is available.\n\n"
                    f"Installed: {APP_VERSION}\n"
                    f"Latest: {latest}"
                )
            if messagebox.askyesno("Update Available", detail + "\n\nOpen the download page?", parent=parent):
                webbrowser.open(result.get("download_url") or result.get("release_url") or REPOSITORY_URL)
            return

        if not show_all:
            return
        if status == "current":
            hash_note = "\nThe executable hash also matches the release asset." if result.get("checksum_checked") else ""
            messagebox.showinfo(
                "GZBuildr Is Current",
                f"GZBuildr {APP_VERSION} is up to date.{hash_note}",
                parent=parent,
            )
        elif status == "ahead":
            messagebox.showinfo(
                "Development Build",
                f"This build ({APP_VERSION}) is newer than the latest release ({latest}).",
                parent=parent,
            )
        elif status == "no_release":
            messagebox.showinfo("Update Check", "No published GZBuildr release was found.", parent=parent)
        else:
            messagebox.showwarning(
                "Update Check",
                f"Could not compare version {APP_VERSION} with release tag {latest}.",
                parent=parent,
            )

    def begin_update_check(self, parent=None, button=None, show_all=True):
        parent = parent or self.root
        if not HAS_UPDATE_CHECKER or check_for_updates is None:
            self.show_update_result(
                error="The GZBuildr update checker is missing.",
                parent=parent,
                button=button,
                show_all=show_all,
            )
            return
        if button is not None:
            try:
                button.config(text="Checking...", state=tk.DISABLED)
            except Exception:
                pass

        def worker():
            try:
                result = check_for_updates()
            except Exception as exc:
                self.root.after(
                    0,
                    lambda exc=exc: self.show_update_result(
                        error=exc, parent=parent, button=button, show_all=show_all
                    ),
                )
                return
            self.root.after(
                0,
                lambda result=result: self.show_update_result(
                    result=result, parent=parent, button=button, show_all=show_all
                ),
            )

        threading.Thread(target=worker, daemon=True).start()

    def begin_startup_update_check(self):
        self.begin_update_check(parent=self.root, show_all=UPDATE_CHECK_SHOW_ALL_RESULTS)

    def open_settings_window(self):
        self.settings = load_app_settings()
        self.theme_mode = self.settings.get("theme_mode", self.theme_mode)
        window = tk.Toplevel(self.root)
        set_window_icon(window)
        window.title("Settings")
        window.transient(self.root)
        window.resizable(False, False)

        frame = ttk.Frame(window, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)

        theme_frame = ttk.LabelFrame(frame, text="Theme", padding="8")
        theme_frame.pack(fill=tk.X, pady=(0, 8))
        theme_var = tk.StringVar(value=self.theme_mode)

        def apply_theme_choice():
            self.set_theme_mode(theme_var.get())
            apply_runtime_theme(window)
            apply_button_outline(window)

        ttk.Radiobutton(theme_frame, text="Dark", variable=theme_var, value="dark", command=apply_theme_choice).pack(side=tk.LEFT, padx=(0, 12))
        ttk.Radiobutton(theme_frame, text="Light", variable=theme_var, value="light", command=apply_theme_choice).pack(side=tk.LEFT)

        def begin_update_check():
            self.begin_update_check(parent=window, button=update_btn, show_all=True)

        guide_url = "https://docs.google.com/document/d/1RUNoN5BRV3ffKtD6eFLpz6YigDBNTD5PU3UafYJerOc/edit?usp=sharing"
        guide_btn = ttk.Button(theme_frame, text="Guide", command=lambda: webbrowser.open(guide_url))
        guide_btn.pack(side=tk.RIGHT)
        update_btn = ttk.Button(theme_frame, text="Check Updates", command=begin_update_check)
        update_btn.pack(side=tk.RIGHT, padx=(0, 6))

        folders_frame = ttk.LabelFrame(frame, text="Folders", padding="8")
        folders_frame.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(folders_frame, text="Open Logs", command=lambda: open_folder(get_logs_dir())).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(folders_frame, text="Open Temp", command=lambda: open_folder(get_temp_dir())).pack(side=tk.LEFT, padx=(0, 6))

        def clear_logs():
            ensure_app_dirs()
            for child in get_logs_dir().iterdir():
                try:
                    if child.is_dir():
                        shutil.rmtree(child, ignore_errors=True)
                    else:
                        child.unlink(missing_ok=True)
                except Exception:
                    pass
            messagebox.showinfo("Logs Cleared", "Log files cleared.", parent=window)

        def clear_temp():
            clear_app_temp_contents()
            messagebox.showinfo("Temp Cleared", "Temporary files cleared.", parent=window)

        ttk.Button(folders_frame, text="Clear Logs", command=clear_logs).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(folders_frame, text="Clear Temp", command=clear_temp).pack(side=tk.LEFT)

        presets_frame = ttk.LabelFrame(frame, text="Block Alignment Presets", padding="8")
        presets_frame.pack(fill=tk.BOTH, expand=True)
        presets_frame.columnconfigure(0, weight=1)

        preset_list = tk.Listbox(
            presets_frame,
            height=6,
            bg=APP_TEXT_BG,
            fg=APP_TEXT_FG,
            selectbackground=APP_TEXT_SELECT_BG,
            selectforeground=APP_TEXT_SELECT_FG,
            highlightbackground=APP_BORDER,
        )
        preset_list.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 6))

        preset_scroll = ttk.Scrollbar(presets_frame, orient=tk.VERTICAL, command=preset_list.yview)
        preset_list.configure(yscrollcommand=preset_scroll.set)
        preset_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S), padx=(0, 6))

        preset_buttons = ttk.Frame(presets_frame)
        preset_buttons.grid(row=0, column=2, sticky=tk.N)

        def refresh_presets():
            self.settings = load_app_settings()
            preset_list.delete(0, tk.END)
            for name in sorted(self.settings.get("alignment_presets", {}).keys(), key=str.lower):
                preset_list.insert(tk.END, name)

        def delete_selected_preset():
            selection = preset_list.curselection()
            if not selection:
                return
            name = preset_list.get(selection[0])
            if not messagebox.askyesno("Delete Preset", f"Delete preset '{name}'?", parent=window):
                return
            self.settings = load_app_settings()
            self.settings.get("alignment_presets", {}).pop(name, None)
            save_app_settings(self.settings)
            refresh_presets()

        ttk.Button(preset_buttons, text="Delete", command=delete_selected_preset).pack(fill=tk.X, pady=(0, 5))
        ttk.Button(preset_buttons, text="Close", command=window.destroy).pack(fill=tk.X)
        refresh_presets()

        credits_label = tk.Label(
            frame,
            text="Developer: Akira Ryuzaki (Digitzaki) | QuickBMS/.BSF: DylanRocket",
            font=("Segoe UI", 8),
            bg=APP_BG,
            fg=APP_TEXT_FG,
        )
        credits_label.pack(anchor=tk.W, pady=(4, 0))

        apply_runtime_theme(window)
        apply_button_outline(window)

        window.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - window.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - window.winfo_height()) // 2
        window.geometry(f"+{max(0, x)}+{max(0, y)}")

    def save_last_input(self, path, mode, bundle_selection=""):
        if self._restoring_last_input:
            return
        self.settings["last_input_path"] = path or ""
        self.settings["last_input_mode"] = mode or ""
        self.settings["last_bundle_selection"] = bundle_selection or ""
        save_app_settings(self.settings)

    def restore_last_input(self):
        path = self.settings.get("last_input_path", "")
        mode = self.settings.get("last_input_mode", "")
        if not path or not os.path.exists(path):
            return
        self._restoring_last_input = True
        try:
            if mode == "directory" and os.path.isdir(path):
                selection = self.settings.get("last_bundle_selection", "")
                select_file = os.path.join(path, selection) if selection else None
                self.load_directory(path, select_file=select_file)
            elif os.path.isfile(path) and path.lower().endswith(SUPPORTED_BUNDLE_EXTENSIONS):
                self.load_bundle_file(path)
        finally:
            self._restoring_last_input = False

    def update_extract_selection_context(self, filepath):
        bundle_key = os.path.abspath(filepath).lower() if filepath else ""
        if bundle_key != self.extract_selection_bundle_key:
            self.extract_selection_bundle_key = bundle_key
            self.extract_selection_file_nums = set()

    def remember_extract_selection(self, selected_file_nums):
        self.extract_selection_file_nums = set(selected_file_nums or [])

    def _on_editor_save_hotkey(self, event=None):
        if not self.text_mode:
            return None
        self.save_text_editor_file()
        return "break"

    def _on_editor_undo_hotkey(self, event=None):
        if not self.text_mode:
            return None
        try:
            self.output_text.edit_undo()
            self.schedule_editor_diff_update()
        except tk.TclError:
            pass
        return "break"

    def _on_editor_redo_hotkey(self, event=None):
        if not self.text_mode:
            return None
        try:
            self.output_text.edit_redo()
            self.schedule_editor_diff_update()
        except tk.TclError:
            pass
        return "break"

    def _on_editor_find_hotkey(self, event=None):
        self.open_find_dialog()
        return "break"

    def _on_editor_key_release(self, event=None):
        if not self.text_mode:
            return None
        if event is not None and event.keysym in {"Shift_L", "Shift_R", "Control_L", "Control_R", "Alt_L", "Alt_R"}:
            return None
        self.schedule_syntax_highlight()
        self.schedule_editor_diff_update()
        if self.text_mode == "camera_path":
            self.root.after_idle(self._refresh_camera_degree_comment)
        return None

    def _refresh_camera_degree_comment(self):
        if self.text_mode != "camera_path" or self.loading_text_editor:
            return
        try:
            line_index = self.output_text.index(tk.INSERT).split(".", 1)[0]
            start = f"{line_index}.0"
            end = f"{line_index}.end"
            line = self.output_text.get(start, end)
            match = re.match(
                r"^(\s*@0x[0-9A-Fa-f]+\s+float\s+Frame\[\d+\]\.FieldOfView\s*=\s*)"
                r"([^;#]+)(;)(?:\s*#.*)?$",
                line,
            )
            if not match:
                return
            radians = float(match.group(2).strip())
            refreshed = f"{match.group(1)}{match.group(2).strip()};  # {math.degrees(radians):.3f} degrees"
            if refreshed == line:
                return
            insert_offset = int(self.output_text.index(tk.INSERT).split(".", 1)[1])
            self.output_text.delete(start, end)
            self.output_text.insert(start, refreshed)
            self.output_text.mark_set(tk.INSERT, f"{line_index}.{min(insert_offset, len(refreshed))}")
        except (ValueError, tk.TclError):
            return

    def _on_editor_text_modified(self, event=None):
        try:
            if not self.output_text.edit_modified():
                return None
            self.output_text.edit_modified(False)
        except tk.TclError:
            return None
        if not self.text_mode or self.loading_text_editor:
            return None
        self.syntax_highlighted_intervals = []
        self.root.after_idle(lambda: self.refresh_visible_editor_formatting(force_syntax=True))
        if self.text_mode == "palette":
            self.root.after_idle(self._tag_palette_color_swatches)
        return None

    def _visible_editor_range(self):
        try:
            start_index = self.output_text.index("@0,0 linestart")
            end_index = self.output_text.index(f"@0,{self.output_text.winfo_height()} lineend")
            return start_index, end_index
        except Exception:
            return "1.0", tk.END

    def schedule_visible_editor_syntax(self):
        if not self.text_mode or self.loading_text_editor:
            return
        if self.syntax_view_after_id is not None:
            return
        self.syntax_view_after_id = self.root.after(0, self.refresh_visible_editor_syntax)

    def _syntax_interval_is_highlighted(self, start_line, end_line):
        return any(start <= start_line and end_line <= finish for start, finish in self.syntax_highlighted_intervals)

    def _syntax_uncovered_intervals(self, start_line, end_line):
        uncovered = []
        cursor = start_line
        for start, finish in self.syntax_highlighted_intervals:
            if finish < cursor:
                continue
            if start > end_line:
                break
            if start > cursor:
                uncovered.append((cursor, min(end_line, start - 1)))
            cursor = max(cursor, finish + 1)
            if cursor > end_line:
                break
        if cursor <= end_line:
            uncovered.append((cursor, end_line))
        return uncovered

    def _record_syntax_interval(self, start_line, end_line):
        intervals = self.syntax_highlighted_intervals + [(start_line, end_line)]
        merged = []
        for start, finish in sorted(intervals):
            if merged and start <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], finish))
            else:
                merged.append((start, finish))
        self.syntax_highlighted_intervals = merged

    def refresh_visible_editor_syntax(self, force=False):
        self.syntax_view_after_id = None
        if not self.text_mode:
            return
        start_index, end_index = self._visible_editor_range()
        try:
            visible_start = int(start_index.split(".", 1)[0])
            visible_end = int(end_index.split(".", 1)[0])
            total_lines = int(self.output_text.index("end-1c").split(".", 1)[0])
        except (ValueError, tk.TclError):
            self._apply_syntax_highlight_range(start_index, end_index)
            return
        if force:
            pending_intervals = [(visible_start, visible_end)]
        else:
            pending_intervals = self._syntax_uncovered_intervals(visible_start, visible_end)
        for highlight_start, highlight_end in pending_intervals:
            self._apply_syntax_highlight_range(f"{highlight_start}.0", f"{highlight_end}.end")
            self._record_syntax_interval(highlight_start, highlight_end)
        buffer_lines = max(180, (visible_end - visible_start + 1) * 6)
        self.syntax_prefetch_target = (
            max(1, visible_start - buffer_lines),
            min(total_lines, visible_end + buffer_lines),
        )
        self._schedule_syntax_prefetch()

    def _schedule_syntax_prefetch(self):
        if self.syntax_prefetch_after_id is not None or not self.text_mode or self.loading_text_editor:
            return
        self.syntax_prefetch_after_id = self.root.after(2, self._run_syntax_prefetch)

    def _run_syntax_prefetch(self):
        self.syntax_prefetch_after_id = None
        if not self.text_mode or self.loading_text_editor or not self.syntax_prefetch_target:
            return
        target_start, target_end = self.syntax_prefetch_target
        pending = self._syntax_uncovered_intervals(target_start, target_end)
        if not pending:
            return
        start_line, end_line = pending[0]
        end_line = min(end_line, start_line + 39)
        self._apply_syntax_highlight_range(f"{start_line}.0", f"{end_line}.end")
        self._record_syntax_interval(start_line, end_line)
        self._schedule_syntax_prefetch()

    def refresh_visible_editor_formatting(self, force_syntax=False):
        if not self.text_mode:
            return
        self.refresh_visible_editor_syntax(force=force_syntax)
        if self._editor_diff_disabled():
            self._clear_editor_diff_marks()
            return
        if self._use_visible_diff_mode():
            self.update_visible_editor_diff_marks()
        else:
            self.schedule_editor_diff_update()

    def configure_editor_diff_tags(self):
        if APP_THEME_MODE == "dark":
            added_bg = "#123a5c"
            changed_bg = "#16472f"
            canvas_bg = "#111827"
        else:
            added_bg = "#dbeafe"
            changed_bg = "#dcfce7"
            canvas_bg = APP_TEXT_BG
        self.output_text.tag_configure("diff_added_line", background=added_bg)
        self.output_text.tag_configure("diff_changed_line", background=changed_bg)
        if self.editor_diff_canvas is not None:
            self.editor_diff_canvas.configure(bg=canvas_bg)

    def _setup_editor_diff_marker_bindings(self):
        if self.editor_diff_canvas is None:
            return
        self.editor_diff_canvas.bind("<Configure>", lambda _event: self._draw_editor_diff_markers())
        self.editor_diff_canvas.bind("<Motion>", self._on_editor_diff_marker_motion)
        self.editor_diff_canvas.bind("<Leave>", lambda _event: self._hide_editor_diff_tooltip())
        self.editor_diff_canvas.bind("<Button-1>", self._on_editor_diff_marker_click)
        self.editor_diff_canvas.bind("<Button-3>", self._on_editor_diff_marker_right_click)

    def _clear_editor_diff_marks(self):
        if self._use_visible_diff_mode() and self.editor_diff_marks:
            for line_no in list(self.editor_diff_marks):
                self.output_text.tag_remove("diff_added_line", f"{line_no}.0", f"{line_no}.end")
                self.output_text.tag_remove("diff_changed_line", f"{line_no}.0", f"{line_no}.end")
        else:
            self.output_text.tag_remove("diff_added_line", "1.0", tk.END)
            self.output_text.tag_remove("diff_changed_line", "1.0", tk.END)
        self.editor_diff_marks = {}
        if self.editor_diff_canvas is not None:
            self.editor_diff_canvas.delete("all")
        self._hide_editor_diff_tooltip()

    def _editor_diff_disabled(self):
        return self.text_mode in {"char_data", "level_data"}

    @staticmethod
    def _normalize_editor_text(text):
        return str(text or '').replace('\r\n', '\n').replace('\r', '\n').rstrip('\n') + '\n'

    def _sync_editor_diff_baseline(self, text=None):
        source = text if text is not None else self._current_editor_text()
        self.editor_original_text = self._normalize_editor_text(source)
        self.editor_original_lines = self.editor_original_text.splitlines()
        self.editor_deleted_anchor_hints = {}
        self.editor_restored_deleted_chunks = set()
        self._clear_editor_diff_marks()

    def schedule_editor_diff_update(self):
        if self.loading_text_editor or self._editor_diff_disabled():
            self._clear_editor_diff_marks()
            return
        if self.editor_diff_after_id is not None:
            try:
                self.root.after_cancel(self.editor_diff_after_id)
            except Exception:
                pass
        self.editor_diff_after_id = self.root.after(120, self.update_editor_diff_marks)

    def _editor_total_lines(self):
        try:
            return max(1, int(str(self.output_text.index("end-1c")).split(".", 1)[0]))
        except Exception:
            return 1

    def _use_visible_diff_mode(self, total_lines=None):
        return False

    def _visible_editor_line_range(self, margin=300):
        try:
            start_line = int(str(self.output_text.index("@0,0 linestart")).split(".", 1)[0])
            end_line = int(str(self.output_text.index(f"@0,{self.output_text.winfo_height()} lineend")).split(".", 1)[0])
        except Exception:
            start_line, end_line = 1, min(self._editor_total_lines(), 200)
        total_lines = self._editor_total_lines()
        return max(1, start_line - margin), min(total_lines, end_line + margin)

    def update_visible_editor_diff_marks(self):
        self._clear_editor_diff_marks()
        if not self.text_mode or self._editor_diff_disabled():
            return
        start_line, end_line = self._visible_editor_line_range()
        try:
            current_lines = self.output_text.get(f"{start_line}.0", f"{end_line}.end").splitlines()
        except Exception:
            current_lines = []
        original_lines = self.editor_original_lines[start_line - 1:end_line]
        total_lines = self._editor_total_lines()

        marks = {}

        def ensure_mark(line_no):
            return marks.setdefault(line_no, {"type": None})

        def add_deleted_mark(line_no, deleted_text, jump_line):
            if not deleted_text.strip() or deleted_text in self.editor_restored_deleted_chunks:
                return
            line_no = min(max(line_no, 1), total_lines)
            mark = ensure_mark(line_no)
            existing_deleted_text = mark.get("deleted_text")
            mark["deleted_text"] = f"{existing_deleted_text}\n{deleted_text}" if existing_deleted_text and existing_deleted_text != deleted_text else deleted_text
            mark["under_line"] = line_no
            mark["jump_line"] = min(max(jump_line, 1), total_lines)
            if not mark.get("type"):
                mark["type"] = "deleted"

        matcher = difflib.SequenceMatcher(None, original_lines, current_lines, autojunk=False)
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                continue
            if tag == "insert":
                for current_index in range(j1, j2):
                    ensure_mark(start_line + current_index)["type"] = "added"
                continue
            if tag == "delete":
                anchor = start_line + j1 - 1
                deleted_text = "\n".join(original_lines[i1:i2])
                add_deleted_mark(anchor, deleted_text, anchor + 1)
                continue
            if tag == "replace":
                original_count = i2 - i1
                current_count = j2 - j1
                if current_count > original_count and original_count > 0:
                    matched_current_indexes = set()
                    unmatched_original_indexes = []
                    for original_offset, original_index in enumerate(range(i1, i2)):
                        best_current_index = None
                        best_score = -1
                        expected_current_index = j1 + original_offset
                        for current_index in range(j1, j2):
                            if current_index in matched_current_indexes:
                                continue
                            similarity = difflib.SequenceMatcher(None, original_lines[original_index], current_lines[current_index]).ratio()
                            score = similarity - abs(current_index - expected_current_index) * 0.02
                            if score > best_score:
                                best_score = score
                                best_current_index = current_index
                        if best_current_index is not None and best_score >= 0.45:
                            matched_current_indexes.add(best_current_index)
                            line_no = start_line + best_current_index
                            mark = ensure_mark(line_no)
                            mark["type"] = "changed"
                            mark["original_text"] = original_lines[original_index]
                        else:
                            unmatched_original_indexes.append(original_index)
                    for current_index in range(j1, j2):
                        if current_index not in matched_current_indexes:
                            ensure_mark(start_line + current_index)["type"] = "added"
                    if unmatched_original_indexes:
                        anchor = start_line + j1 - 1
                        deleted_text = "\n".join(original_lines[index] for index in unmatched_original_indexes)
                        add_deleted_mark(anchor, deleted_text, anchor + 1)
                    continue

                paired_count = min(original_count, current_count)
                for offset in range(paired_count):
                    original_index = i1 + offset
                    current_index = j1 + offset
                    line_no = start_line + current_index
                    similarity = difflib.SequenceMatcher(None, original_lines[original_index], current_lines[current_index]).ratio()
                    if similarity < 0.45:
                        ensure_mark(line_no)["type"] = "added"
                        add_deleted_mark(max(1, line_no - 1), original_lines[original_index], line_no)
                    else:
                        mark = ensure_mark(line_no)
                        mark["type"] = "changed"
                        mark["original_text"] = original_lines[original_index]
                for current_index in range(j1 + paired_count, j2):
                    ensure_mark(start_line + current_index)["type"] = "added"
                if original_count > current_count:
                    anchor = start_line + j1 + paired_count - 1
                    deleted_text = "\n".join(original_lines[i1 + paired_count:i2])
                    add_deleted_mark(anchor, deleted_text, anchor + 1)

        for line_no, mark in marks.items():
            if mark.get("type") == "added":
                self.output_text.tag_add("diff_added_line", f"{line_no}.0", f"{line_no}.end")
            elif mark.get("type") == "changed":
                self.output_text.tag_add("diff_changed_line", f"{line_no}.0", f"{line_no}.end")

        self.output_text.tag_lower("diff_added_line")
        self.output_text.tag_lower("diff_changed_line")
        self.editor_diff_marks = marks
        self.editor_deleted_anchor_hints = {}
        self._draw_editor_diff_markers()

    def update_editor_diff_marks(self):
        self.editor_diff_after_id = None
        if not self.text_mode or self._editor_diff_disabled():
            self._clear_editor_diff_marks()
            return
        total_lines = self._editor_total_lines()
        if self._use_visible_diff_mode(total_lines):
            self.update_visible_editor_diff_marks()
            return
        self._clear_editor_diff_marks()
        original_lines = self.editor_original_lines
        current_lines = self._current_editor_text().splitlines()
        total_lines = max(1, len(current_lines))

        marks = {}

        def ensure_mark(line_no):
            return marks.setdefault(line_no, {"type": None})

        def deleted_chunk_is_back_near(line_no, deleted_text):
            deleted_lines = deleted_text.splitlines()
            if not deleted_lines:
                return False
            preferred_starts = (line_no - 1, line_no, line_no + 1)
            for start in preferred_starts:
                if start < 0 or start + len(deleted_lines) > len(current_lines):
                    continue
                if current_lines[start:start + len(deleted_lines)] == deleted_lines:
                    return True
            return False

        def visible_deleted_anchor(line_no):
            line_no = min(max(line_no, 1), total_lines)
            try:
                current_line = current_lines[line_no - 1]
            except IndexError:
                current_line = ""
            if current_line.strip() or line_no <= 1:
                return line_no
            return line_no - 1

        def add_deleted_mark(line_no, deleted_text, jump_line):
            if not deleted_text.strip():
                return
            if deleted_text in self.editor_restored_deleted_chunks:
                return
            line_no = self.editor_deleted_anchor_hints.get(deleted_text, line_no)
            line_no = visible_deleted_anchor(line_no)
            if deleted_chunk_is_back_near(line_no, deleted_text):
                return
            mark = ensure_mark(line_no)
            existing_deleted_text = mark.get("deleted_text")
            if existing_deleted_text and existing_deleted_text != deleted_text:
                mark["deleted_text"] = existing_deleted_text + "\n" + deleted_text
            else:
                mark["deleted_text"] = deleted_text
            mark["under_line"] = line_no
            mark["jump_line"] = min(max(jump_line, 1), total_lines)
            if not mark.get("type"):
                mark["type"] = "deleted"

        matcher = difflib.SequenceMatcher(None, original_lines, current_lines, autojunk=False)
        for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
            if tag == "equal":
                continue
            if tag == "insert":
                for line_no in range(j1 + 1, j2 + 1):
                    ensure_mark(line_no)["type"] = "added"
            elif tag == "replace":
                original_count = _i2 - _i1
                current_count = j2 - j1
                if current_count > original_count and original_count > 0:
                    matched_current_indexes = set()
                    unmatched_original_indexes = []
                    for original_offset, original_index in enumerate(range(_i1, _i2)):
                        best_current_index = None
                        best_score = -1
                        expected_current_index = j1 + original_offset
                        for current_index in range(j1, j2):
                            if current_index in matched_current_indexes:
                                continue
                            similarity = difflib.SequenceMatcher(None, original_lines[original_index], current_lines[current_index]).ratio()
                            distance_penalty = abs(current_index - expected_current_index) * 0.02
                            score = similarity - distance_penalty
                            if score > best_score:
                                best_score = score
                                best_current_index = current_index
                        if best_current_index is not None and best_score >= 0.45:
                            matched_current_indexes.add(best_current_index)
                            line_no = best_current_index + 1
                            mark = ensure_mark(line_no)
                            mark["type"] = "changed"
                            mark["original_text"] = original_lines[original_index]
                        else:
                            unmatched_original_indexes.append(original_index)
                    for current_index in range(j1, j2):
                        if current_index not in matched_current_indexes:
                            ensure_mark(current_index + 1)["type"] = "added"
                    if unmatched_original_indexes:
                        underline_line = min(max(j1, 1), total_lines)
                        jump_line = min(max(j1 + 1, 1), total_lines)
                        deleted_text = "\n".join(original_lines[index] for index in unmatched_original_indexes)
                        add_deleted_mark(underline_line, deleted_text, jump_line)
                    continue
                if original_count > current_count and current_count > 0:
                    first_ratio = difflib.SequenceMatcher(None, original_lines[_i1], current_lines[j1]).ratio()
                    last_ratio = difflib.SequenceMatcher(None, original_lines[_i2 - 1], current_lines[j1]).ratio()
                    if last_ratio > first_ratio:
                        deleted_count = original_count - current_count
                        underline_line = min(max(j1, 1), total_lines)
                        jump_line = min(max(j1 + 1, 1), total_lines)
                        deleted_text = "\n".join(original_lines[_i1:_i1 + deleted_count])
                        add_deleted_mark(underline_line, deleted_text, jump_line)
                        for offset, line_no in enumerate(range(j1 + 1, j2 + 1)):
                            mark = ensure_mark(line_no)
                            mark["type"] = "changed"
                            original_index = _i1 + deleted_count + offset
                            if original_index < _i2:
                                mark["original_text"] = original_lines[original_index]
                        continue
                paired_count = min(original_count, current_count)
                for offset, line_no in enumerate(range(j1 + 1, j1 + paired_count + 1)):
                    original_index = _i1 + offset
                    similarity = difflib.SequenceMatcher(None, original_lines[original_index], current_lines[line_no - 1]).ratio()
                    if similarity < 0.45:
                        ensure_mark(line_no)["type"] = "added"
                        underline_line = min(max(line_no - 1, 1), total_lines)
                        add_deleted_mark(underline_line, original_lines[original_index], line_no)
                        continue
                    mark = ensure_mark(line_no)
                    mark["type"] = "changed"
                    if original_index < _i2:
                        mark["original_text"] = original_lines[original_index]
                for line_no in range(j1 + paired_count + 1, j2 + 1):
                    ensure_mark(line_no)["type"] = "added"
                if original_count > current_count:
                    underline_line = min(max(j1 + paired_count, 1), total_lines)
                    jump_line = min(max(underline_line + 1, 1), total_lines)
                    deleted_text = "\n".join(original_lines[_i1 + paired_count:_i2])
                    add_deleted_mark(underline_line, deleted_text, jump_line)
            elif tag == "delete":
                underline_line = min(max(j1, 1), total_lines)
                jump_line = min(max(j1 + 1, 1), total_lines)
                deleted_text = "\n".join(original_lines[_i1:_i2])
                add_deleted_mark(underline_line, deleted_text, jump_line)

        for line_no, mark in marks.items():
            change_type = mark.get("type")
            if change_type == "added":
                self.output_text.tag_add("diff_added_line", f"{line_no}.0", f"{line_no}.end")
            elif change_type == "changed":
                self.output_text.tag_add("diff_changed_line", f"{line_no}.0", f"{line_no}.end")

        self.output_text.tag_lower("diff_added_line")
        self.output_text.tag_lower("diff_changed_line")
        self.editor_diff_marks = marks
        self.editor_deleted_anchor_hints = {
            mark["deleted_text"]: line_no
            for line_no, mark in marks.items()
            if isinstance(mark, dict) and mark.get("deleted_text")
        }
        self.editor_restored_deleted_chunks.intersection_update(self.editor_deleted_anchor_hints.keys())
        self._draw_editor_diff_markers()

    def _editor_diff_colors(self):
        if APP_THEME_MODE == "dark":
            return {
                "added": "#60a5fa",
                "changed": "#22c55e",
                "deleted": "#ef4444",
            }
        return {
            "added": "#2563eb",
            "changed": "#16a34a",
            "deleted": "#dc2626",
        }

    def _draw_editor_diff_markers(self):
        if self.editor_diff_canvas is None:
            return
        canvas = self.editor_diff_canvas
        canvas.delete("all")
        if not self.text_mode or self._editor_diff_disabled() or not self.editor_diff_marks:
            return
        try:
            height = max(1, canvas.winfo_height())
            width = max(4, canvas.winfo_width())
            total_lines = max(1, int(str(self.output_text.index("end-1c")).split(".", 1)[0]))
        except Exception:
            return
        colors = self._editor_diff_colors()
        marker_height = max(3, min(9, height // max(1, total_lines)))
        for line_no, mark in sorted(self.editor_diff_marks.items()):
            change_type = mark.get("type") if isinstance(mark, dict) else mark
            has_delete = isinstance(mark, dict) and bool(mark.get("deleted_text"))
            y = int(((line_no - 1) / total_lines) * max(1, height - marker_height))
            if has_delete and change_type in ("added", "changed"):
                midpoint = max(2, width // 2)
                canvas.create_rectangle(
                    1,
                    y,
                    midpoint,
                    y + marker_height,
                    fill=colors.get(change_type, colors["changed"]),
                    outline="",
                    tags=(f"line:{line_no}",),
                )
                canvas.create_rectangle(
                    midpoint,
                    y,
                    width - 1,
                    y + marker_height,
                    fill=colors["deleted"],
                    outline="",
                    tags=(f"line:{line_no}",),
                )
            else:
                draw_type = "deleted" if has_delete else change_type
                canvas.create_rectangle(
                    1,
                    y,
                    width - 1,
                    y + marker_height,
                    fill=colors.get(draw_type, colors["changed"]),
                    outline="",
                    tags=(f"line:{line_no}",),
                )

    def _restore_deleted_editor_line(self, line_no):
        deleted_text = self._editor_diff_deleted_text(line_no)
        if not deleted_text:
            return
        insert_text = "\n" + deleted_text
        self.output_text.insert(f"{line_no}.end", insert_text)
        self.editor_deleted_anchor_hints.pop(deleted_text, None)
        self.editor_restored_deleted_chunks.add(deleted_text)
        mark = self.editor_diff_marks.get(line_no)
        if isinstance(mark, dict):
            mark.pop("deleted_text", None)
        restored_line_count = max(1, len(deleted_text.splitlines()))
        for restored_line in range(line_no, line_no + restored_line_count + 1):
            restored_mark = self.editor_diff_marks.get(restored_line)
            if isinstance(restored_mark, dict):
                restored_mark.pop("deleted_text", None)
        self.output_text.mark_set(tk.INSERT, f"{line_no + 1}.0")
        self.output_text.see(f"{line_no + 1}.0")
        self.output_text.focus_set()
        restored_line_count = max(1, len(deleted_text.splitlines()))
        refresh_end_line = line_no + restored_line_count + 1
        self._apply_syntax_highlight_range(f"{line_no + 1}.0", f"{refresh_end_line}.end")
        self.update_editor_diff_marks()

    def _restore_changed_editor_line(self, line_no):
        original_text = self._editor_diff_original_text(line_no)
        if not original_text:
            return
        self.output_text.delete(f"{line_no}.0", f"{line_no}.end")
        self.output_text.insert(f"{line_no}.0", original_text)
        mark = self.editor_diff_marks.get(line_no)
        if isinstance(mark, dict):
            mark.pop("original_text", None)
            if mark.get("type") == "changed":
                mark["type"] = None
        self.output_text.mark_set(tk.INSERT, f"{line_no}.end")
        self.output_text.see(f"{line_no}.0")
        self.output_text.focus_set()
        self._apply_syntax_highlight_range(f"{line_no}.0", f"{line_no}.end")
        self.update_editor_diff_marks()

    def _editor_diff_marker_at_y(self, y):
        if self.editor_diff_canvas is None or not self.editor_diff_marks:
            return None, None
        item = self.editor_diff_canvas.find_closest(4, y)
        if not item:
            return None, None
        bbox = self.editor_diff_canvas.bbox(item[0])
        if not bbox or y < bbox[1] - 3 or y > bbox[3] + 3:
            return None, None
        line_no = None
        change_type = None
        for tag in self.editor_diff_canvas.gettags(item[0]):
            if tag.startswith("line:"):
                line_no = int(tag.split(":", 1)[1])
        mark = self.editor_diff_marks.get(line_no)
        if isinstance(mark, dict):
            change_type = mark.get("type")
            if mark.get("deleted_text") and not change_type:
                change_type = "deleted"
        return line_no, change_type

    def _editor_diff_deleted_text(self, line_no):
        mark = self.editor_diff_marks.get(line_no)
        if isinstance(mark, dict):
            return mark.get("deleted_text", "")
        return ""

    def _editor_diff_original_text(self, line_no):
        mark = self.editor_diff_marks.get(line_no)
        if isinstance(mark, dict):
            return mark.get("original_text", "")
        return ""

    def _editor_diff_jump_line(self, line_no):
        mark = self.editor_diff_marks.get(line_no)
        if isinstance(mark, dict):
            return mark.get("jump_line", line_no)
        return line_no

    def _on_editor_diff_marker_motion(self, event):
        line_no, change_type = self._editor_diff_marker_at_y(event.y)
        if not line_no or not change_type:
            self._hide_editor_diff_tooltip()
            return
        tooltip_lines = []
        if change_type == "added":
            tooltip_lines.append(f"Added Line {line_no}")
        elif change_type == "changed":
            tooltip_lines.append(f"Changed Line {line_no}")
            original_text = self._editor_diff_original_text(line_no)
            if original_text:
                tooltip_lines.append(original_text)
        deleted_text = self._editor_diff_deleted_text(line_no)
        if deleted_text:
            if tooltip_lines:
                tooltip_lines.append("---------------")
            preview = deleted_text.replace("\t", "    ")
            if len(preview) > 220:
                preview = preview[:217] + "..."
            tooltip_lines.append(f"Deleted Line Under {line_no}")
            tooltip_lines.append(preview)
        if not tooltip_lines:
            tooltip_lines.append(f"Edited line {line_no}")
        label = "\n".join(tooltip_lines)
        self._show_editor_diff_tooltip(event.x_root + 12, event.y_root + 12, label)

    def _on_editor_diff_marker_click(self, event):
        line_no, _change_type = self._editor_diff_marker_at_y(event.y)
        if not line_no:
            return
        jump_line = self._editor_diff_jump_line(line_no)
        self.output_text.mark_set(tk.INSERT, f"{jump_line}.0")
        self.output_text.see(f"{jump_line}.0")
        self.output_text.focus_set()

    def _on_editor_diff_marker_right_click(self, event):
        line_no, _change_type = self._editor_diff_marker_at_y(event.y)
        if not line_no:
            return
        self._hide_editor_diff_tooltip()
        if self._editor_diff_deleted_text(line_no):
            self._restore_deleted_editor_line(line_no)
            return
        if self._editor_diff_original_text(line_no):
            self._restore_changed_editor_line(line_no)

    def _show_editor_diff_tooltip(self, x, y, text):
        if self.editor_diff_tooltip is None:
            tip = tk.Toplevel(self.root)
            tip.withdraw()
            tip.overrideredirect(True)
            tip.attributes("-topmost", True)
            label = tk.Label(
                tip,
                text=text,
                bg="#111827",
                fg="#ffffff",
                padx=6,
                pady=3,
                font=("TkDefaultFont", 8),
            )
            label.pack()
            self.editor_diff_tooltip = (tip, label)
        tip, label = self.editor_diff_tooltip
        label.configure(text=text)
        tip.geometry(f"+{x}+{y}")
        tip.deiconify()

    def _hide_editor_diff_tooltip(self):
        if self.editor_diff_tooltip is None:
            return
        tip, _label = self.editor_diff_tooltip
        try:
            tip.withdraw()
        except Exception:
            pass

    def configure_syntax_tags(self):
        if APP_THEME_MODE == "dark":
            colors = {
                "syntax_comment": "#7dd3fc",
                "syntax_string": "#fbbf24",
                "syntax_number": "#fde68a",
                "syntax_keyword": "#93c5fd",
                "syntax_type": "#5eead4",
                "syntax_row_type": "#5eead4",
                "syntax_section": "#f472b6",
                "syntax_offset": "#fb7185",
                "syntax_value_string": "#fb7185",
                "syntax_field": "#a7f3d0",
                "syntax_code": "#f9a8d4",
                "syntax_operator": "#cbd5e1",
                "syntax_atom": "#fde68a",
                "syntax_root": "#e879f9",
                "syntax_member": "#22d3ee",
                "syntax_asset": "#fb923c",
                "syntax_reference": "#fb923c",
                "syntax_variable": APP_TEXT_FG,
                "syntax_function": "#86efac",
                "syntax_parameter": "#fb923c",
                "syntax_block": "#fb923c",
                "syntax_method": "#22d3ee",
                "syntax_method_deep": "#fb7185",
                "syntax_markup_bracket": "#94a3b8",
                "syntax_markup_tag": "#60a5fa",
                "syntax_markup_attribute": "#c084fc",
                "syntax_markup_text": "#86efac",
                "syntax_markup_number": "#fde68a",
            }
        else:
            colors = {
                "syntax_comment": "#047857",
                "syntax_string": "#b45309",
                "syntax_number": "#7c3aed",
                "syntax_keyword": "#1d4ed8",
                "syntax_type": "#0f766e",
                "syntax_row_type": "#0f766e",
                "syntax_section": "#be185d",
                "syntax_offset": "#be123c",
                "syntax_value_string": "#be123c",
                "syntax_field": "#047857",
                "syntax_code": "#be185d",
                "syntax_operator": "#4b5563",
                "syntax_atom": "#92400e",
                "syntax_root": "#7e22ce",
                "syntax_member": "#0369a1",
                "syntax_asset": "#c2410c",
                "syntax_reference": "#c2410c",
                "syntax_variable": APP_TEXT_FG,
                "syntax_function": "#15803d",
                "syntax_parameter": "#c2410c",
                "syntax_block": "#c2410c",
                "syntax_method": "#0369a1",
                "syntax_method_deep": "#be123c",
                "syntax_markup_bracket": "#64748b",
                "syntax_markup_tag": "#1d4ed8",
                "syntax_markup_attribute": "#7e22ce",
                "syntax_markup_text": "#15803d",
                "syntax_markup_number": "#7c3aed",
            }
        for tag, color in colors.items():
            self.output_text.tag_configure(tag, foreground=color)
        self.output_text.tag_configure("decompile_type", foreground=colors["syntax_type"])
        self.output_text.tag_configure("decompile_field", foreground=colors["syntax_member"])
        self.output_text.tag_configure("decompile_number", foreground=colors["syntax_number"])
        self.output_text.tag_configure("decompile_name", foreground=colors["syntax_root"])
        self.output_text.tag_configure("decompile_hidden", elide=True)
        self.output_text.tag_configure("root_table_header", foreground=colors["syntax_offset"], underline=True)
        self.output_text.tag_configure("pvm_fold_header", foreground=colors["syntax_block"], underline=True)
        for tag in (
            "syntax_field", "syntax_variable", "syntax_root", "syntax_member",
            "syntax_number", "syntax_value_string", "syntax_asset", "syntax_reference",
            "syntax_operator", "syntax_function", "syntax_method", "syntax_method_deep", "syntax_parameter", "syntax_keyword", "syntax_block", "syntax_type", "syntax_row_type", "syntax_code",
            "syntax_markup_bracket", "syntax_markup_tag", "syntax_markup_attribute", "syntax_markup_text",
            "syntax_string", "syntax_comment", "syntax_offset", "syntax_markup_number", "root_table_header", "find_match",
            "decompile_type", "decompile_field", "decompile_number", "decompile_name", "decompile_hidden",
        ):
            self.output_text.tag_raise(tag)

    def _syntax_tag_names(self):
        return (
            "syntax_comment",
            "syntax_string",
            "syntax_number",
            "syntax_keyword",
            "syntax_type",
            "syntax_row_type",
            "syntax_section",
            "syntax_offset",
            "syntax_value_string",
            "syntax_field",
            "syntax_code",
            "syntax_operator",
            "syntax_atom",
            "syntax_root",
            "syntax_member",
            "syntax_asset",
            "syntax_reference",
            "syntax_variable",
            "syntax_function",
            "syntax_parameter",
            "syntax_block",
            "syntax_method",
            "syntax_method_deep",
            "syntax_markup_bracket",
            "syntax_markup_tag",
            "syntax_markup_attribute",
            "syntax_markup_text",
            "syntax_markup_number",
            "decompile_type",
            "decompile_field",
            "decompile_number",
            "decompile_name",
            "decompile_hidden",
        )

    def _highlight_monsterdata_disassembly(self, text, add_range):
        block_re = re.compile(
            r"^[ \t]*(moves|move|events|event|action_tree|node|transition|condition|command_stream|command|unowned_events|table)\b",
            re.MULTILINE,
        )
        for match in block_re.finditer(text):
            add_range("syntax_block", match.start(1), match.end(1))
        for match in re.finditer(r'(?:(?:@[0-9A-Fa-fx]+\s+)|(?:->\s*))"([^"]*)"', text):
            add_range("syntax_root", match.start(1), match.end(1))
        for match in re.finditer(r"@0x[0-9A-Fa-f]+", text):
            add_range("syntax_offset", match.start(), match.end())
        for match in re.finditer(r"^[ \t]+@0x[0-9A-Fa-f]+\s+([^;{}\n]+?)\s*$", text, re.MULTILINE):
            add_range("decompile_name", match.start(1), match.end(1))
        opcode_re = re.compile(
            r"^[ \t]*(@0x[0-9A-Fa-f]+\s+)(opcode)\s+"
            r"([-+]?(?:0x[0-9A-Fa-f]+|\d+))\s+([A-Za-z_][A-Za-z0-9_]*)",
            re.MULTILINE,
        )
        for match in opcode_re.finditer(text):
            indent_length = len(match.group(0)) - len(match.group(0).lstrip(" \t"))
            add_range("decompile_hidden", match.start() + indent_length, match.start(2))
            add_range("syntax_keyword", match.start(2), match.end(2))
            add_range("decompile_number", match.start(3), match.end(3))
            add_range("syntax_function", match.start(4), match.end(4))
        record_re = re.compile(
            r"^[ \t]*@0x[0-9A-Fa-f]+\s+(field|operand)\s+"
            r"([A-Za-z0-9_]+(?:\[[0-9A-Fa-fxX]+\])?)\s+(.+?)\s*(=)\s*(.*?);[ \t]*$",
            re.MULTILINE,
        )
        numeric_re = re.compile(r"[-+]?(?:0x[0-9A-Fa-f]+|\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?")
        for match in record_re.finditer(text):
            line_prefix = text[match.start():match.start(3)]
            indent_length = len(line_prefix) - len(line_prefix.lstrip(" \t"))
            add_range("decompile_hidden", match.start() + indent_length, match.start(3))
            add_range("decompile_field", match.start(3), match.end(3))
            add_range("syntax_operator", match.start(4), match.end(4))
            value = match.group(5).strip()
            value_start = match.start(5) + len(match.group(5)) - len(match.group(5).lstrip())
            if numeric_re.fullmatch(value) or all(numeric_re.fullmatch(part.strip()) for part in value.split(",")):
                tag = "decompile_number"
            elif match.group(2) == "string":
                tag = "syntax_string"
            elif match.group(2) == "ref":
                tag = "syntax_reference"
            else:
                tag = "syntax_atom"
            add_range(tag, value_start, value_start + len(value))
        for match in re.finditer(r"->|[{};=]", text):
            add_range("syntax_operator", match.start(), match.end())

    def clear_root_table_folds(self):
        for header_tag, content_tag in getattr(self, "root_toc_fold_tags", {}).items():
            try:
                self.output_text.tag_delete(header_tag)
                self.output_text.tag_delete(content_tag)
            except Exception:
                pass
        self.root_toc_fold_tags = {}
        for tag in getattr(self, "root_toc_jump_targets", {}):
            try:
                self.output_text.tag_delete(tag)
            except Exception:
                pass
        for mark in getattr(self, "root_toc_jump_marks", []):
            try:
                self.output_text.mark_unset(mark)
            except Exception:
                pass
        self.root_toc_jump_targets = {}
        self.root_toc_jump_marks = []
        for header_tag, fold in getattr(self, "pvm_global_folds", {}).items():
            for tag in (header_tag, fold["content"], fold["open"], fold["close"]):
                try:
                    self.output_text.tag_delete(tag)
                except Exception:
                    pass
        self.pvm_global_folds = {}
        try:
            self.output_text.tag_remove("root_table_header", "1.0", tk.END)
            self.output_text.tag_remove("pvm_fold_header", "1.0", tk.END)
        except Exception:
            pass

    def setup_root_table_folds(self):
        self.clear_root_table_folds()
        if self.text_mode not in {"char_data", "level_data", "prx", "pvm", "skeleton_type3"}:
            return
        try:
            document_lines = self.output_text.get("1.0", "end-1c").splitlines()
        except Exception:
            return
        fold_index = 0
        line_index = 0
        total_lines = len(document_lines)
        if self.text_mode == "skeleton_type3":
            collapsed_sections = {
                "[Skeleton.NameRefs]",
                "[Skeleton4.NodeRecordPointers]",
            }
            for header_index, header_text in enumerate(document_lines):
                if header_text.strip() not in collapsed_sections:
                    continue
                content_end = next(
                    (
                        candidate
                        for candidate in range(header_index + 1, total_lines)
                        if document_lines[candidate].strip().startswith("[")
                    ),
                    total_lines,
                )
                header_tag = f"skeleton_header_{fold_index}"
                content_tag = f"skeleton_fold_{fold_index}"
                line_no = header_index + 1
                self.output_text.tag_add("root_table_header", f"{line_no}.0", f"{line_no}.end")
                self.output_text.tag_add(header_tag, f"{line_no}.0", f"{line_no}.end")
                if content_end > header_index + 1:
                    fold_end = content_end if not document_lines[content_end - 1].strip() else content_end + 1
                    self.output_text.tag_add(content_tag, f"{line_no + 1}.0", f"{fold_end}.0")
                    self.output_text.tag_configure(content_tag, elide=True)
                    self.root_toc_fold_tags[header_tag] = content_tag
                fold_index += 1
            return
        if self.text_mode == "char_data" and self.monster_data_disassembly_active:
            targets = {}
            target_re = re.compile(r'^move\s+@0x([0-9A-Fa-f]+)\s+"([^"]+)"\s*\{')
            for target_index, target_text in enumerate(document_lines):
                match = target_re.match(target_text.strip())
                if match:
                    targets[int(match.group(1), 16)] = target_index + 1
            for header_index, header_text in enumerate(document_lines):
                if header_text.strip() != "moves [Open][Close]":
                    continue
                brace_index = header_index + 1
                close_index = next(
                    (candidate for candidate in range(brace_index + 1, total_lines) if document_lines[candidate].strip() == "}"),
                    None,
                )
                if close_index is None:
                    break
                line_no = header_index + 1
                header_tag = "monster_moves_header"
                content_tag = "monster_moves_content"
                open_tag = "monster_moves_open_label"
                close_tag = "monster_moves_close_label"
                open_start = header_text.index("[Open]")
                close_start = header_text.index("[Close]")
                self.output_text.tag_add("pvm_fold_header", f"{line_no}.0", f"{line_no}.end")
                self.output_text.tag_add(header_tag, f"{line_no}.0", f"{line_no}.end")
                self.output_text.tag_add(open_tag, f"{line_no}.{open_start}", f"{line_no}.{open_start + 6}")
                self.output_text.tag_add(close_tag, f"{line_no}.{close_start}", f"{line_no}.{close_start + 7}")
                self.output_text.tag_add(content_tag, f"{brace_index + 1}.0", f"{close_index + 2}.0")
                self.output_text.tag_configure(content_tag, elide=True)
                self.output_text.tag_configure(open_tag, elide=False)
                self.output_text.tag_configure(close_tag, elide=True)
                label_color = self.output_text.tag_cget("syntax_block", "foreground")
                self.output_text.tag_configure(open_tag, foreground=label_color)
                self.output_text.tag_configure(close_tag, foreground=label_color)
                self.pvm_global_folds[header_tag] = {
                    "content": content_tag,
                    "open": open_tag,
                    "close": close_tag,
                }
                entry_re = re.compile(r"^\s*@0x([0-9A-Fa-f]+)\s+(.+?)\s*$")
                for entry_index in range(brace_index + 1, close_index):
                    match = entry_re.match(document_lines[entry_index])
                    if not match:
                        continue
                    target_line = targets.get(int(match.group(1), 16))
                    if target_line is None:
                        continue
                    tag = f"root_toc_jump_{len(self.root_toc_jump_targets)}"
                    mark = f"root_toc_target_{len(self.root_toc_jump_targets)}"
                    entry_line = entry_index + 1
                    offset_start = document_lines[entry_index].index("@0x")
                    offset_end = offset_start + len(f"@0x{match.group(1)}")
                    name_start = match.start(2)
                    name_end = match.end(2)
                    self.output_text.tag_add("decompile_name", f"{entry_line}.{name_start}", f"{entry_line}.{name_end}")
                    self.output_text.tag_add("root_table_header", f"{entry_line}.{offset_start}", f"{entry_line}.{offset_end}")
                    self.output_text.tag_add(tag, f"{entry_line}.{offset_start}", f"{entry_line}.{offset_end}")
                    self.output_text.mark_set(mark, f"{target_line}.0")
                    self.output_text.mark_gravity(mark, tk.LEFT)
                    self.root_toc_jump_targets[tag] = mark
                    self.root_toc_jump_marks.append(mark)
                break
            return
        if self.text_mode == "pvm":
            for header_index, header_text in enumerate(document_lines):
                if header_text.strip() != "globals [Open][Close]":
                    continue
                brace_index = header_index + 1
                if brace_index >= total_lines or document_lines[brace_index].strip() != "{":
                    continue
                depth = 0
                close_index = None
                for candidate in range(brace_index, total_lines):
                    depth += document_lines[candidate].count("{")
                    depth -= document_lines[candidate].count("}")
                    if depth == 0:
                        close_index = candidate
                        break
                if close_index is None:
                    continue
                line_no = header_index + 1
                header_tag = "pvm_globals_header"
                content_tag = "pvm_globals_content"
                open_tag = "pvm_globals_open_label"
                close_tag = "pvm_globals_close_label"
                open_start = header_text.index("[Open]")
                close_start = header_text.index("[Close]")
                header_start = header_text.index("globals")
                self.output_text.tag_add("pvm_fold_header", f"{line_no}.{header_start}", f"{line_no}.end")
                self.output_text.tag_add(header_tag, f"{line_no}.{header_start}", f"{line_no}.end")
                self.output_text.tag_add(open_tag, f"{line_no}.{open_start}", f"{line_no}.{open_start + 6}")
                self.output_text.tag_add(close_tag, f"{line_no}.{close_start}", f"{line_no}.{close_start + 7}")
                self.output_text.tag_add(content_tag, f"{brace_index + 1}.0", f"{close_index + 2}.0")
                self.output_text.tag_configure(content_tag, elide=True)
                self.output_text.tag_configure(open_tag, elide=False)
                self.output_text.tag_configure(close_tag, elide=True)
                label_color = self.output_text.tag_cget("syntax_block", "foreground")
                self.output_text.tag_configure(open_tag, foreground=label_color)
                self.output_text.tag_configure(close_tag, foreground=label_color)
                self.pvm_global_folds[header_tag] = {
                    "content": content_tag,
                    "open": open_tag,
                    "close": close_tag,
                }
                break
            return

        if self.text_mode == "prx":
            targets = {}
            target_re = re.compile(r"^property_set\s+(.+?)\s*\{\s*#\s*table\s+0x([0-9A-Fa-f]+)")
            for target_index, target_text in enumerate(document_lines):
                match = target_re.match(target_text.strip())
                if match:
                    targets[(int(match.group(2), 16), match.group(1).strip())] = target_index + 1

            in_table_index = False
            entry_re = re.compile(r"^@0x([0-9A-Fa-f]+)\s+(.+?)\s*$")
            for entry_index, entry_text in enumerate(document_lines):
                stripped = entry_text.strip()
                if stripped == "[RootTables.PRXTables]":
                    in_table_index = True
                    continue
                if not in_table_index:
                    continue
                if not stripped or stripped.startswith("["):
                    break
                match = entry_re.match(stripped)
                if not match:
                    continue
                target_line = targets.get((int(match.group(1), 16), match.group(2).strip()))
                if target_line is None:
                    continue
                tag = f"root_toc_jump_{len(self.root_toc_jump_targets)}"
                mark = f"root_toc_target_{len(self.root_toc_jump_targets)}"
                line_no = entry_index + 1
                offset_end = len(f"@0x{match.group(1)}")
                self.output_text.tag_add("root_table_header", f"{line_no}.0", f"{line_no}.{offset_end}")
                self.output_text.tag_add(tag, f"{line_no}.0", f"{line_no}.{offset_end}")
                self.output_text.mark_set(mark, f"{target_line}.0")
                self.output_text.mark_gravity(mark, tk.LEFT)
                self.root_toc_jump_targets[tag] = mark
                self.root_toc_jump_marks.append(mark)
            return

        while line_index < total_lines:
            text = document_lines[line_index].strip()
            if not re.match(r"^\[RootTables\.[^\]]+\]$", text):
                line_index += 1
                continue
            line_no = line_index + 1
            header_tag = f"root_toc_header_{fold_index}"
            content_tag = f"root_toc_fold_{fold_index}"
            self.output_text.tag_add("root_table_header", f"{line_no}.0", f"{line_no}.end")
            self.output_text.tag_add(header_tag, f"{line_no}.0", f"{line_no}.end")

            content_start_index = line_index + 1
            content_end_index = content_start_index
            while content_end_index < total_lines:
                content_text = document_lines[content_end_index].strip()
                if not content_text:
                    break
                if content_text.startswith("["):
                    break
                content_end_index += 1
            if content_end_index > content_start_index:
                content_start_line = content_start_index + 1
                content_end_line = content_end_index + 1
                self.output_text.tag_add(content_tag, f"{content_start_line}.0", f"{content_end_line}.0")
                self.output_text.tag_configure(content_tag, elide=True)
                self.root_toc_fold_tags[header_tag] = content_tag
                fold_index += 1
            line_index = max(content_end_index, line_index + 1)

    def _on_root_table_header_click(self, event):
        try:
            index = self.output_text.index(f"@{event.x},{event.y}")
            header_tag = next(
                (
                    tag
                    for tag in self.output_text.tag_names(index)
                    if tag in self.root_toc_fold_tags
                    or tag in self.root_toc_jump_targets
                    or tag in self.pvm_global_folds
                ),
                None,
            )
            if header_tag is None:
                return "break"
            jump_mark = self.root_toc_jump_targets.get(header_tag)
            if jump_mark is not None:
                self.output_text.mark_set(tk.INSERT, jump_mark)
                self.output_text.see(jump_mark)
                self.output_text.focus_set()
                return "break"
            pvm_fold = self.pvm_global_folds.get(header_tag)
            if pvm_fold is not None:
                is_closed = str(self.output_text.tag_cget(pvm_fold["content"], "elide")).lower() in {"1", "true", "yes"}
                self.output_text.tag_configure(pvm_fold["content"], elide=not is_closed)
                self.output_text.tag_configure(pvm_fold["open"], elide=is_closed)
                self.output_text.tag_configure(pvm_fold["close"], elide=not is_closed)
                self.root.after_idle(self.refresh_visible_editor_syntax)
                return "break"
            content_tag = self.root_toc_fold_tags[header_tag]
            current = str(self.output_text.tag_cget(content_tag, "elide")).lower() in {"1", "true", "yes"}
            self.output_text.tag_configure(content_tag, elide=not current)
            self.root.after_idle(self.refresh_visible_editor_syntax)
            return "break"
        except Exception:
            return "break"

    def schedule_syntax_highlight(self):
        if self.syntax_highlight_after_id is not None:
            try:
                self.root.after_cancel(self.syntax_highlight_after_id)
            except Exception:
                pass
        self.syntax_highlight_after_id = self.root.after(80, self.apply_syntax_highlight)

    def cancel_lazy_syntax_highlight(self):
        self.syntax_lazy_generation += 1
        if self.syntax_view_after_id is not None:
            try:
                self.root.after_cancel(self.syntax_view_after_id)
            except Exception:
                pass
            self.syntax_view_after_id = None
        if self.syntax_prefetch_after_id is not None:
            try:
                self.root.after_cancel(self.syntax_prefetch_after_id)
            except Exception:
                pass
            self.syntax_prefetch_after_id = None
        self.syntax_prefetch_target = None
        if self.syntax_lazy_after_id is not None:
            try:
                self.root.after_cancel(self.syntax_lazy_after_id)
            except Exception:
                pass
            self.syntax_lazy_after_id = None
        self._end_syntax_progress()

    def _begin_syntax_progress(self, total_lines):
        if self.syntax_progress_active:
            return
        self.syntax_progress_active = True
        self.syntax_progress_restore = {
            "frame": bool(self.bundle_select_frame.winfo_ismapped()),
            "dropdown": bool(self.bundle_dropdown.winfo_ismapped()),
            "label": self.bundle_label.cget("text"),
        }
        self.syntax_progress_var.set(0.0)
        self.bundle_select_frame.grid()
        self.bundle_dropdown.grid_remove()
        self.bundle_label.config(text="Highlight:")
        self.syntax_progress_bar.grid(row=0, column=1, sticky=(tk.W, tk.E))
        self.syntax_progress_bar.configure(maximum=max(1.0, float(total_lines)))
        self.root.update_idletasks()

    def _begin_busy_progress(self, label="Loading:"):
        if self.syntax_progress_active:
            self._end_syntax_progress()
        self.syntax_progress_active = True
        self.syntax_progress_restore = {
            "frame": bool(self.bundle_select_frame.winfo_ismapped()),
            "dropdown": bool(self.bundle_dropdown.winfo_ismapped()),
            "label": self.bundle_label.cget("text"),
        }
        self.syntax_progress_var.set(0.0)
        self.bundle_select_frame.grid()
        self.bundle_dropdown.grid_remove()
        self.bundle_label.config(text=label)
        self.syntax_progress_bar.configure(mode='indeterminate', maximum=100.0)
        self.syntax_progress_bar.grid(row=0, column=1, sticky=(tk.W, tk.E))
        self.syntax_progress_bar.start(12)
        self.root.update_idletasks()

    def _update_syntax_progress(self, completed_lines, total_lines):
        if not self.syntax_progress_active:
            return
        self.syntax_progress_bar.configure(maximum=max(1.0, float(total_lines)))
        self.syntax_progress_var.set(min(float(completed_lines), float(total_lines)))

    def _end_syntax_progress(self):
        if not getattr(self, "syntax_progress_active", False):
            return
        restore = self.syntax_progress_restore or {}
        self.syntax_progress_active = False
        self.syntax_progress_restore = None
        try:
            self.syntax_progress_bar.stop()
        except Exception:
            pass
        self.syntax_progress_bar.configure(mode='determinate', maximum=100.0)
        self.syntax_progress_bar.grid_remove()
        self.syntax_progress_var.set(0.0)
        self.bundle_label.config(text=restore.get("label", "Bundle:"))
        if restore.get("dropdown", True):
            self.bundle_dropdown.grid(row=0, column=1, sticky=(tk.W, tk.E))
        else:
            self.bundle_dropdown.grid_remove()
        if not restore.get("frame", True):
            self.bundle_select_frame.grid_remove()
        if self.bundle_entry_session and self.bundle_entry_edit:
            self._setup_bundle_entry_selector(self.bundle_entry_edit.get("entry", {}))
        elif self.texture_preview_session and self.texture_preview_entry:
            self._setup_texture_preview_selector(self.texture_preview_entry)
        elif self.static_mesh_preview_session and self.static_mesh_preview_entry:
            self._setup_static_mesh_preview_selector(self.static_mesh_preview_entry)

    def start_lazy_syntax_highlight(self, clear_existing=False):
        self.cancel_lazy_syntax_highlight()
        self.syntax_highlighted_intervals = []
        if clear_existing:
            for tag in self._syntax_tag_names():
                self.output_text.tag_remove(tag, "1.0", tk.END)
        if not self.text_mode:
            return
        self.syntax_lazy_after_id = self.root.after_idle(self.refresh_visible_editor_syntax)

    def start_visible_syntax_highlight_only(self):
        self.cancel_lazy_syntax_highlight()
        self.syntax_highlighted_intervals = []
        if self.text_mode:
            self.root.after_idle(self.refresh_visible_editor_syntax)

    def _current_syntax_line_bounds(self):
        try:
            line = int(str(self.output_text.index(tk.INSERT)).split(".", 1)[0])
        except Exception:
            return "1.0", "end-1c"
        return f"{line}.0", f"{line}.end"

    def apply_syntax_highlight(self):
        self.syntax_highlight_after_id = None
        if not self.text_mode:
            return
        start_index, end_index = self._current_syntax_line_bounds()
        self._apply_syntax_highlight_range(start_index, end_index)

    def _apply_syntax_highlight_range(self, start_index, end_index):
        if not self.text_mode:
            return
        text = self.output_text.get(start_index, end_index)
        if not text:
            return
        for tag in self._syntax_tag_names():
            self.output_text.tag_remove(tag, start_index, end_index)

        if self._syntax_pattern_cache is None:
            self._syntax_pattern_cache = [
            ("syntax_section", re.compile(r"^\[[^\]\n]+\]", re.MULTILINE)),
            ("syntax_field", re.compile(r"^[ \t]*(?!@?0x[0-9A-Fa-f]+\b)@?[A-Za-z0-9_][A-Za-z0-9_.:]*", re.MULTILINE)),
            ("syntax_code", re.compile(r"\[[A-Za-z0-9?]{1,4}\]")),
            ("syntax_offset", re.compile(r"(?<![A-Za-z0-9_])@?0x[0-9A-Fa-f]+")),
            ("syntax_keyword", re.compile(
                r"\b(?:if|else|for|while|do|switch|case|default|return|break|continue|"
                r"class|struct|enum|function|extern|const|static|public|private|protected|virtual|new|delete|"
                r"true|false|null|None|and|or|not|constant)\b"
            )),
            ("syntax_type", re.compile(
                r"\b(?:void|bool|char|short|int|long|float|double|string|u8|u16|u24|u32|"
                r"s8|s16|s32|vec2|vec3|vec4|Point3)\b"
            )),
            ("syntax_number", re.compile(r"(?<![A-Za-z0-9_.])[-+]?(?:\d+\.\d*|\.\d+|\d+)(?:[eE][-+]?\d+)?(?![A-Za-z0-9_.])")),
            ("syntax_operator", re.compile(r"[{}=?:|]")),
            ("syntax_string", re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', re.DOTALL)),
            ("syntax_comment", re.compile(r"/\*.*?\*/|//[^\n]*|(?<![A-Za-z0-9_])#[^\n]*|;[^\n]*", re.DOTALL)),
            ]
        patterns = list(self._syntax_pattern_cache)
        if self.text_mode in ("bsf", "edf"):
            patterns.insert(
                -3,
                ("syntax_atom", re.compile(r"\b(?:[A-Z][A-Za-z0-9_]{2,}|[A-Za-z]+_[A-Za-z0-9_]+)\b")),
            )

        tag_ranges = {tag: [] for tag in self._syntax_tag_names()}

        def add_range(tag, start, end):
            tag_ranges[tag].extend((f"{start_index}+{start}c", f"{start_index}+{end}c"))

        for tag, pattern in patterns:
            for match in pattern.finditer(text):
                add_range(tag, match.start(), match.end())

        if self.text_mode == "ifl":
            ifl_line_re = re.compile(r"^[ \t]*([^\s#;]+)(?:[ \t]+([-+]?\d+))?[ \t]*$", re.MULTILINE)
            for match in ifl_line_re.finditer(text):
                add_range("syntax_asset", match.start(1), match.end(1))
                if match.group(2) is not None:
                    add_range("syntax_markup_number", match.start(2), match.end(2))

        if self.text_mode in ("xfg", "ifc"):
            markup_comment_re = re.compile(r"<!--.*?-->", re.DOTALL)
            for match in markup_comment_re.finditer(text):
                add_range("syntax_comment", match.start(), match.end())

            markup_tag_re = re.compile(
                r"<(?![!?])(/?)([A-Za-z_][A-Za-z0-9_.:-]*)([^<>]*?)(/?)>",
                re.DOTALL,
            )
            attribute_re = re.compile(
                r"([A-Za-z_][A-Za-z0-9_.:-]*)(\s*=\s*)(\"(?:\\.|[^\"\\])*\"|'(?:\\.|[^'\\])*')",
                re.DOTALL,
            )
            for match in markup_tag_re.finditer(text):
                opening_end = match.start(2)
                add_range("syntax_markup_bracket", match.start(), opening_end)
                add_range("syntax_markup_tag", match.start(2), match.end(2))
                closing_start = match.end() - (2 if match.group(4) else 1)
                add_range("syntax_markup_bracket", closing_start, match.end())
                attributes = match.group(3)
                attributes_start = match.start(3)
                for attribute in attribute_re.finditer(attributes):
                    add_range(
                        "syntax_markup_attribute",
                        attributes_start + attribute.start(1),
                        attributes_start + attribute.end(1),
                    )
                    add_range(
                        "syntax_operator",
                        attributes_start + attribute.start(2),
                        attributes_start + attribute.end(2),
                    )

            markup_text_re = re.compile(r">([^<]+)<")
            numeric_markup_re = re.compile(
                r"[-+]?(?:0x[0-9A-Fa-f]+|\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?"
            )
            asset_markup_re = re.compile(
                r"[^\s<>]+\.(?:edf|prx|pvm|pwk|bsf|txt|xfg|ifc|ifl|resource)",
                re.IGNORECASE,
            )
            for match in markup_text_re.finditer(text):
                raw_value = match.group(1)
                leading = len(raw_value) - len(raw_value.lstrip())
                value = raw_value.strip()
                if not value:
                    continue
                value_start = match.start(1) + leading
                value_end = value_start + len(value)
                if numeric_markup_re.fullmatch(value):
                    add_range("syntax_markup_number", value_start, value_end)
                elif asset_markup_re.search(value):
                    add_range("syntax_asset", value_start, value_end)
                else:
                    add_range("syntax_markup_text", value_start, value_end)

        if self.text_mode in ("prx", "txt", "xfg", "ifc", "char_data", "level_data", "skeleton_type3"):
            def key_member_split(key):
                if key.startswith(("StartupRefs.", "StringRefs.")):
                    return key.find(".")
                return key.rfind(".")

            row_type_re = re.compile(r"^@0x[0-9A-Fa-f]+\s+([A-Za-z0-9_\[\]xXa-fA-F]+)", re.MULTILINE)
            for match in row_type_re.finditer(text):
                add_range("syntax_row_type", match.start(1), match.end(1))
            row_key_re = re.compile(r"^@0x[0-9A-Fa-f]+\s+[A-Za-z0-9_\[\]xXa-fA-F]+\s+([^\s=]+)\s*=", re.MULTILINE)
            for match in row_key_re.finditer(text):
                key = match.group(1)
                dot_index = key_member_split(key)
                if dot_index > 0:
                    root_start = match.start(1)
                    is_first_split_prefix = key.startswith(("StartupRefs.", "StringRefs."))
                    is_stringref_asset = key.startswith("StringRefs.") and re.search(r"\.(?:edf|prx|pvm|pwk|bsf|txt|xfg|ifc|ifl)$", key, re.IGNORECASE)
                    member_start = match.start(1) + dot_index + (1 if is_first_split_prefix else 0)
                    root_end = member_start if is_first_split_prefix else match.start(1) + dot_index
                    add_range("syntax_root", root_start, root_end)
                    member_tag = "syntax_asset" if is_stringref_asset else "syntax_member"
                    add_range(member_tag, member_start, match.end(1))
                else:
                    add_range("syntax_root", match.start(1), match.end(1))
            bare_key_re = re.compile(r"^[ \t]*([A-Za-z_][A-Za-z0-9_.:-]*)\s*=", re.MULTILINE)
            for match in bare_key_re.finditer(text):
                key = match.group(1)
                dot_index = key_member_split(key)
                if dot_index > 0:
                    root_start = match.start(1)
                    is_first_split_prefix = key.startswith(("StartupRefs.", "StringRefs."))
                    is_stringref_asset = key.startswith("StringRefs.") and re.search(r"\.(?:edf|prx|pvm|pwk|bsf|txt|xfg|ifc|ifl)$", key, re.IGNORECASE)
                    member_start = match.start(1) + dot_index + (1 if is_first_split_prefix else 0)
                    root_end = member_start if is_first_split_prefix else match.start(1) + dot_index
                    add_range("syntax_root", root_start, root_end)
                    member_tag = "syntax_asset" if is_stringref_asset else "syntax_member"
                    add_range(member_tag, member_start, match.end(1))
                else:
                    add_range("syntax_root", match.start(1), match.end(1))
            string_value_re = re.compile(r"^@0x[0-9A-Fa-f]+\s+string\s+[^\n=]+\s=\s(.+)$", re.MULTILINE)
            for match in string_value_re.finditer(text):
                add_range("syntax_value_string", match.start(1), match.end(1))
            named_ref_value_re = re.compile(
                r"^@0x[0-9A-Fa-f]+\s+ref\s+[^\n=]+\s=\s(?![-+]?(?:0x[0-9A-Fa-f]+|\d+)\s*$)(.+)$",
                re.MULTILINE,
            )
            for match in named_ref_value_re.finditer(text):
                add_range("syntax_value_string", match.start(1), match.end(1))
            asset_value_re = re.compile(
                r"^@0x[0-9A-Fa-f]+\s+[A-Za-z0-9_\[\]xXa-fA-F]+\s+[^\n=]+\s=\s.*?"
                r"((?:[A-Za-z0-9_./-]+[ \t]+)*[A-Za-z0-9_./-]+\.(?:edf|prx|pvm|pwk|bsf|txt|xfg|ifc|ifl))\b",
                re.IGNORECASE | re.MULTILINE,
            )
            for match in asset_value_re.finditer(text):
                add_range("syntax_asset", match.start(1), match.end(1))
            if self.text_mode == "prx":
                property_set_re = re.compile(r"^[ \t]*(property_set)\s+([^\s{]+)", re.MULTILINE)
                for match in property_set_re.finditer(text):
                    add_range("syntax_keyword", match.start(1), match.end(1))
                    add_range("syntax_root", match.start(2), match.end(2))

                property_re = re.compile(
                    r"^[ \t]*(float|int|string)\s+(.+?\S)\s*=\s*(.*?)\s*;[ \t]*$",
                    re.MULTILINE,
                )
                for match in property_re.finditer(text):
                    add_range("syntax_type", match.start(1), match.end(1))
                    add_range("syntax_member", match.start(2), match.end(2))
                    if match.group(1) == "string":
                        add_range("syntax_string", match.start(3), match.end(3))

                reference_re = re.compile(
                    r"^[ \t]*(ref)\s+(.+?\S)\s*(->)\s*([^;\n]*?\S)\s*;",
                    re.MULTILINE,
                )
                for match in reference_re.finditer(text):
                    add_range("syntax_type", match.start(1), match.end(1))
                    add_range("syntax_member", match.start(2), match.end(2))
                    add_range("syntax_operator", match.start(3), match.end(3))
                    add_range("syntax_reference", match.start(4), match.end(4))
            else:
                compact_value_re = re.compile(
                    r"^[ \t]*(?:(?:float|int|int_alt|string)\s+)?[^=\n]+=\s*(?![-+]?(?:0x[0-9A-Fa-f]+|\d+(?:\.\d*)?|\.\d+)(?:[eE][-+]?\d+)?\s*(?:#.*)?$)([^#\n]*\S)",
                    re.MULTILINE,
                )
                for match in compact_value_re.finditer(text):
                    add_range("syntax_value_string", match.start(1), match.end(1))
                    asset_match = re.search(
                        r"((?:[A-Za-z0-9_./-]+[ \t]+)*[A-Za-z0-9_./-]+\.(?:edf|prx|pvm|pwk|bsf|txt|xfg|ifc|ifl))\b",
                        match.group(1),
                        re.IGNORECASE,
                    )
                    if asset_match:
                        asset_start = match.start(1) + asset_match.start(1)
                        asset_end = match.start(1) + asset_match.end(1)
                        add_range("syntax_asset", asset_start, asset_end)
            root_re = re.compile(r"^@?0x[0-9A-Fa-f]+\s+([^\n]+)$", re.MULTILINE)
            for match in root_re.finditer(text):
                add_range("syntax_root", match.start(1), match.end(1))
                if self.text_mode == "prx":
                    dot_index = match.group(1).rfind(".")
                    if dot_index > 0:
                        add_range("syntax_member", match.start(1) + dot_index + 1, match.end(1))

        if self.text_mode == "char_data" and self.monster_data_disassembly_active:
            self._highlight_monsterdata_disassembly(text, add_range)

        if self.text_mode == "pvm":
            module_re = re.compile(r"^[ \t]*(module)\s+([A-Za-z_][A-Za-z0-9_]*)", re.MULTILINE)
            for match in module_re.finditer(text):
                add_range("syntax_block", match.start(1), match.end(1))
                add_range("syntax_root", match.start(2), match.end(2))

            block_name_re = re.compile(r"^[ \t]*(globals|code)\b", re.MULTILINE)
            for match in block_name_re.finditer(text):
                add_range("syntax_block", match.start(1), match.end(1))

            identifier_re = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
            for match in identifier_re.finditer(text):
                add_range("syntax_variable", match.start(), match.end())

            function_decl_re = re.compile(
                r"^[ \t]*(function)\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)",
                re.MULTILINE,
            )
            for match in function_decl_re.finditer(text):
                add_range("syntax_keyword", match.start(1), match.end(1))
                add_range("syntax_function", match.start(2), match.end(2))
                parameter_text = match.group(3)
                parameter_base = match.start(3)
                for part in re.finditer(r"[^,]+", parameter_text):
                    names = list(re.finditer(r"[A-Za-z_][A-Za-z0-9_]*", part.group(0)))
                    if not names:
                        continue
                    name = names[-1]
                    add_range(
                        "syntax_parameter",
                        parameter_base + part.start() + name.start(),
                        parameter_base + part.start() + name.end(),
                    )

            declaration_re = re.compile(
                r"^[ \t]*(?:(extern)\s+)?([A-Za-z_][A-Za-z0-9_]*(?:-ref|\[\]\d+)?)\s+([A-Za-z_][A-Za-z0-9_]*)\s*;",
                re.MULTILINE,
            )
            for match in declaration_re.finditer(text):
                if match.group(1):
                    add_range("syntax_keyword", match.start(1), match.end(1))
                add_range("syntax_type", match.start(2), match.end(2))
                add_range("syntax_variable", match.start(3), match.end(3))

            call_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?=\()")
            control_words = {"if", "else", "for", "while", "switch", "return", "function"}
            close_levels = {}

            def matching_paren(open_index):
                depth = 0
                quote = None
                escaped = False
                for cursor in range(open_index, len(text)):
                    char = text[cursor]
                    if quote is not None:
                        if escaped:
                            escaped = False
                        elif char == "\\":
                            escaped = True
                        elif char == quote:
                            quote = None
                        continue
                    if char in {"'", '"'}:
                        quote = char
                    elif char == "(":
                        depth += 1
                    elif char == ")":
                        depth -= 1
                        if depth == 0:
                            return cursor
                return None

            for match in call_re.finditer(text):
                if match.group(1) in control_words:
                    continue
                level = 0
                if match.start(1) > 0 and text[match.start(1) - 1] == ".":
                    receiver_end = match.start(1) - 2
                    while receiver_end >= 0 and text[receiver_end].isspace():
                        receiver_end -= 1
                    if receiver_end >= 0 and text[receiver_end] == ")":
                        level = (close_levels.get(receiver_end, 0) + 1) % 3
                    else:
                        receiver_match = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*$", text[:receiver_end + 1])
                        if receiver_match and re.match(r"g[A-Z]", receiver_match.group(1)):
                            level = 1
                tag = ("syntax_function", "syntax_method", "syntax_method_deep")[level]
                add_range(tag, match.start(1), match.end(1))
                open_index = text.find("(", match.end(1))
                if open_index >= 0:
                    close_index = matching_paren(open_index)
                    if close_index is not None:
                        close_levels[close_index] = level

            global_re = re.compile(r"\bg[A-Z][A-Za-z0-9_]*\b")
            for match in global_re.finditer(text):
                add_range("syntax_root", match.start(), match.end())

            pvm_operator_re = re.compile(r"->|==|!=|<=|>=|\+\+|--|&&|\|\||[+\-*/%<>=!&|]")
            for match in pvm_operator_re.finditer(text):
                add_range("syntax_operator", match.start(), match.end())

        # Tk accepts any number of index pairs in one tag command. Batching here
        # avoids one Python/Tcl round trip for every token in large exports.
        for tag, indices in tag_ranges.items():
            for offset in range(0, len(indices), 400):
                batch = indices[offset:offset + 400]
                self.output_text.tk.call(self.output_text._w, "tag", "add", tag, *batch)

    def open_bundle_search(self):
        if not self.parser or not self.parsed_files:
            messagebox.showinfo("Bundle Search", "Open a bundle before searching.")
            return
        if self.bundle_search_window and self.bundle_search_window.winfo_exists():
            self.bundle_search_window.deiconify()
            self.bundle_search_window.lift()
            return

        window = tk.Toplevel(self.root)
        window.title("Bundle Search")
        window.geometry("720x430")
        window.transient(self.root)
        self.bundle_search_window = window
        frame = ttk.Frame(window, padding=10)
        frame.pack(fill=tk.BOTH, expand=True)
        query_var = tk.StringVar()
        query_entry = ttk.Entry(frame, textvariable=query_var)
        query_entry.pack(fill=tk.X)
        status_var = tk.StringVar(value="Searches entry names and embedded text across the current bundle.")
        ttk.Label(frame, textvariable=status_var).pack(fill=tk.X, pady=(5, 5))
        results = tk.Listbox(
            frame,
            activestyle="dotbox",
            bg=APP_TEXT_BG,
            fg=APP_TEXT_FG,
            selectbackground=APP_TEXT_SELECT_BG,
            selectforeground=APP_TEXT_SELECT_FG,
        )
        scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=results.yview)
        results.configure(yscrollcommand=scrollbar.set)
        results.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        def close_window():
            self.bundle_search_generation += 1
            self.bundle_search_window = None
            window.destroy()

        def run_search(_event=None):
            query = query_var.get().strip()
            if not query:
                return
            self.bundle_search_generation += 1
            generation = self.bundle_search_generation
            results.delete(0, tk.END)
            status_var.set("Searching in the background...")
            parser = self.parser
            entries = [dict(entry) for entry in self.parsed_files]
            query_folded = query.casefold()

            def worker():
                found = []
                for entry in entries:
                    name = str(entry.get("name", ""))
                    if query_folded in name.casefold():
                        found.append((entry, query, f"Name: {name}"))
                    try:
                        blob = parser.read_bytes(entry.get("offset", 0), entry.get("size", 0))
                    except Exception:
                        continue
                    # Latin-1 keeps a one-to-one byte mapping while still exposing embedded ASCII.
                    text = bytes(blob).decode("latin-1", errors="ignore")
                    position = text.casefold().find(query_folded)
                    if position >= 0:
                        start = max(0, position - 35)
                        end = min(len(text), position + len(query) + 55)
                        context = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in text[start:end])
                        context = re.sub(r"\s+", " ", context).strip()
                        found.append((entry, query, f"@0x{position:X}: {context}"))

                def finish():
                    if generation != self.bundle_search_generation or not window.winfo_exists():
                        return
                    self.bundle_search_results = found
                    for entry, _term, context in found:
                        results.insert(tk.END, f"{entry.get('name', '')}    {context}")
                    status_var.set(f"{len(found)} result(s). Double-click to open.")
                self.root.after(0, finish)

            threading.Thread(target=worker, daemon=True).start()

        def open_result(_event=None):
            selection = results.curselection()
            if not selection:
                return
            entry, term, _context = self.bundle_search_results[selection[0]]
            if self._is_editable_bundle_entry(entry):
                self.open_bundle_entry_editor(entry)
                self._schedule_bundle_search_jump(entry, term)
            elif self._is_texture_preview_entry(entry):
                self.open_texture_preview(entry)
            elif self._is_static_mesh_entry(entry):
                self.open_static_mesh_preview(entry)
            else:
                messagebox.showinfo("Bundle Search", "This result is in a binary entry without an editor yet.")

        query_entry.bind("<Return>", run_search)
        results.bind("<Double-Button-1>", open_result)
        results.bind("<Return>", open_result)
        window.protocol("WM_DELETE_WINDOW", close_window)
        query_entry.focus_set()

    def _schedule_bundle_search_jump(self, entry, term, attempts=40):
        def jump(remaining):
            current = self.bundle_entry_edit.get("entry", {}) if self.bundle_entry_edit else {}
            same_entry = (
                current.get("file_num") == entry.get("file_num")
                and current.get("offset") == entry.get("offset")
            )
            if same_entry and self.text_mode and not self.loading_text_editor:
                self.find_var.set(term)
                self.output_text.mark_set(tk.INSERT, "1.0")
                self.find_next_in_editor()
                return
            if remaining > 0:
                self.root.after(100, lambda: jump(remaining - 1))
        jump(attempts)

    def open_find_dialog(self):
        self.show_find_bar()

    def _position_find_bar(self):
        self.root.update_idletasks()
        self.find_frame.place(relx=1.0, x=-24, y=3, anchor=tk.NE)
        self.find_frame.lift()

    def show_find_bar(self):
        self._position_find_bar()
        selected = self.output_text.get(tk.SEL_FIRST, tk.SEL_LAST) if self.output_text.tag_ranges(tk.SEL) else ""
        if selected and "\n" not in selected:
            self.find_var.set(selected)
        self.find_entry.focus_set()
        self.find_entry.select_range(0, tk.END)

    def hide_find_bar(self):
        self.output_text.tag_remove("find_match", "1.0", tk.END)
        self.find_frame.place_forget()
        self.output_text.focus_set()

    def clear_find_bar(self):
        self.find_var.set("")
        self.output_text.tag_remove("find_match", "1.0", tk.END)
        self.output_text.focus_set()

    def _hide_find_bar_completely(self):
        self.find_var.set("")
        self.output_text.tag_remove("find_match", "1.0", tk.END)
        self.find_frame.place_forget()

    def find_next_in_editor(self):
        query = self.find_var.get()
        if not query:
            return
        self.output_text.tag_remove("find_match", "1.0", tk.END)
        start = self.output_text.index(tk.INSERT)
        match = self.output_text.search(query, f"{start}+1c", tk.END, nocase=True)
        if not match:
            match = self.output_text.search(query, "1.0", tk.END, nocase=True)
        if match:
            end = f"{match}+{len(query)}c"
            self.output_text.tag_add("find_match", match, end)
            self.output_text.mark_set(tk.INSERT, end)
            self.output_text.see(match)
        else:
            self.root.bell()

    def setup_drag_drop(self):
        """Setup drag and drop functionality for the file entry"""
        if HAS_DND:
            # Using tkinterdnd2
            try:
                for widget in (self.file_entry, self.output_text, self.root):
                    widget.drop_target_register(DND_FILES)
                    widget.dnd_bind('<<Drop>>', self.on_drop_tkdnd)
                self.output_text.insert(tk.END, "Drag-and-drop enabled\n")
                print("Drag-and-drop enabled (tkinterdnd2)")
            except Exception as e:
                self.output_text.insert(tk.END, f"Failed to setup drag-and-drop: {e}\n")
                print(f"Failed to setup drag-and-drop: {e}")
        else:
            # Show message that drag-and-drop is not available
            self.output_text.insert(tk.END, "\nDrag-and-drop not available.\n")
            self.output_text.insert(tk.END, "To enable, install: pip install tkinterdnd2\n\n")
            print("\nDrag-and-drop not available.")
            print("To enable, install: pip install tkinterdnd2")

    def on_drop_tkdnd(self, event):
        """Handle file drop event from tkinterdnd2"""
        try:
            # Get the file path from the event
            files = event.data

            # Handle different drop data formats
            if isinstance(files, str):
                # Parse the file path - tkinterdnd2 returns paths in curly braces
                filepath = files.strip()

                # Handle multiple files (space-separated, each in braces)
                # Example: "{C:/path/file1.bdg} {C:/path/file2.bdg}"
                if filepath.startswith('{'):
                    # Extract first file from braces
                    end_brace = filepath.find('}')
                    if end_brace > 0:
                        filepath = filepath[1:end_brace]
                    else:
                        filepath = filepath[1:]  # Remove leading brace only

                # Normalize path separators and resolve any path issues
                filepath = os.path.normpath(filepath)

                # Remove any remaining curly braces
                filepath = filepath.replace('{', '').replace('}', '')

            else:
                return

            if (
                self.texture_preview_session
                and self.texture_preview_entry
                and os.path.isfile(filepath)
                and filepath.lower().endswith('.png')
            ):
                self._replace_texture_preview_png_from_path(filepath)
                return

            # Accept a directory drop or a direct bundle drop
            if os.path.isdir(filepath):
                self.file_path_var.set(filepath)
                self.output_text.insert(tk.END, f"Directory loaded via drag-drop: {filepath}\n")
                self.load_directory(filepath)
            elif os.path.isfile(filepath) and filepath.lower().endswith(SUPPORTED_BUNDLE_EXTENSIONS):
                self.output_text.insert(tk.END, f"Bundle loaded via drag-drop: {filepath}\n")
                self.load_bundle_file(filepath)
            else:
                self.output_text.insert(tk.END, "Please drop a bundle file or directory.\n")
                print(f"Dropped path is not a supported bundle or directory: {filepath}")
        except Exception as e:
            self.output_text.insert(tk.END, f"Error handling drop: {e}\n")
            print(f"Error handling drop: {e}")
            import traceback
            traceback.print_exc()

    def browse_file(self):
        """Open the normal Windows file picker for direct bundle files."""
        initialdir = self.get_last_initial_dir()
        selected = _dialog(
            self.root,
            filedialog.askopenfilename,
            title="Select Bundle File",
            initialdir=initialdir,
            filetypes=[
                ("All Files", "*.*"),
                ("BDG Bundles", "*.bdg"),
                ("CMG Bundles", "*.cmg"),
                ("CMP Bundles", "*.cmp"),
                ("CLP Bundles", "*.clp"),
                ("CLF Bundles", "*.clf"),
                ("BDP Bundles", "*.bdp"),
                ("BDL Bundles", "*.bdl"),
                ("BSF Bundles", "*.bsf"),
                ("PWK VM Scripts", "*.pvm"),
                ("PRX Scripts", "*.prx"),
                ("EDF Particles", "*.edf"),
                ("LOC Localization", "*.loc"),
                ("VOL Bundles", "*.vol"),
                ("Text Scripts", "*.txt"),
                ("IFC Files", "*.ifc"),
                ("IFL Files", "*.ifl"),
                ("XFG Files", "*.xfg"),
                ("CCG Bundles", "*.ccg"),
                ("CMF Bundles", "*.cmf"),
                ("CCF Bundles", "*.ccf"),
                ("ZIP Archives", "*.zip"),
            ],
        )
        if not selected:
            return

        if os.path.isfile(selected) and selected.lower().endswith(SUPPORTED_BUNDLE_EXTENSIONS):
            self.load_bundle_file(selected)
        else:
            messagebox.showwarning("Unsupported", "Please select a supported bundle file.")

    def browse_directory(self):
        """Open the normal Windows folder picker for directory/bulk workflows."""
        initialdir = self.get_last_initial_dir()
        directory = _dialog(
            self.root,
            filedialog.askdirectory,
            title="Select Bundle Directory",
            initialdir=initialdir,
        )
        if directory:
            self.load_directory(directory)

    def _extract_zip_bundle(self, zip_path):
        """
        Extract the first supported bundle from a ZIP into a temp dir.
        Returns (temp_dir, extracted_bundle_path) or (None, None) on failure.
        Temp dir is tracked for cleanup on close.
        """
        if not zipfile.is_zipfile(zip_path):
            messagebox.showerror("Invalid ZIP", f"Not a valid ZIP file: {zip_path}")
            return None, None

        bundle_extensions = ('.bdg', '.cmg', '.cmp', '.clp', '.clf', '.bdp', '.bdl', '.bsf', '.vol', '.ccg', '.cmf', '.ccf')
        ensure_app_dirs()
        temp_dir = tempfile.mkdtemp(prefix="gzbuildr_zip_", dir=str(get_temp_dir()))
        self._zip_temp_dirs.append(temp_dir)
        extracted = []

        with zipfile.ZipFile(zip_path, 'r') as zf:
            for member in zf.namelist():
                if member.lower().endswith(bundle_extensions):
                    dest = zf.extract(member, temp_dir)
                    extracted.append(dest)

        if not extracted:
            messagebox.showinfo("No Bundles in ZIP",
                "No supported bundle files found inside the ZIP.\n"
                "Supported: .bdg .cmg .cmp .clp .clf .bdp .bdl .bsf .vol .ccg .cmf .ccf")
            shutil.rmtree(temp_dir, ignore_errors=True)
            self._zip_temp_dirs.remove(temp_dir)
            return None, None

        return temp_dir, extracted[0]

    def load_directory(self, directory, select_file=None):
        """Load all bundle and ZIP files from a directory, including subdirectories"""
        self._cancel_character_data_decode()
        self.cancel_lazy_syntax_highlight()
        self.current_bundle_dir = directory
        self.file_path_var.set(directory)
        self.parser = None
        self.parsed_files = []
        self.text_mode = None
        self.text_source_path = None
        self._hide_find_bar_completely()
        self.show_find_bar()
        self.bundle_entry_session = None
        self.extract_btn.config(text="Extract")
        self.rebuild_btn.config(text="Rebuild")
        self.extract_btn.config(state=tk.DISABLED)
        self.rebuild_btn.config(state=tk.DISABLED)
        self._clear_editor_diff_marks()

        self.bundle_files = []

        for root, dirs, files in os.walk(directory):
            dirs.sort(key=str.lower)
            for filename in sorted(files, key=str.lower):
                if filename.lower().endswith(SUPPORTED_BUNDLE_EXTENSIONS):
                    self.bundle_files.append(os.path.join(root, filename))

        if not self.bundle_files:
            messagebox.showinfo("No Bundles Found",
                "No bundle or ZIP files found in selected directory.")
            self.bundle_select_frame.grid_remove()
            return

        self.bundle_label.config(text="Bundle:")
        self.bundle_label.grid()
        self.bundle_dropdown.grid()
        self.hide_editor_back_button()
        bundle_names = [
            os.path.relpath(f, directory) for f in self.bundle_files
        ]
        self.bundle_dropdown['values'] = bundle_names

        # Pre-select the file the user picked, if provided
        if select_file:
            select_rel = os.path.relpath(select_file, directory)
            if select_rel in bundle_names:
                self.bundle_dropdown.current(bundle_names.index(select_rel))
            else:
                self.bundle_dropdown.current(0)
        else:
            self.bundle_dropdown.current(0)

        self.bundle_select_frame.grid()

        self.on_bundle_selected(None)
        selected_rel = self.bundle_dropdown.get()
        self.save_last_input(directory, "directory", selected_rel)

        self.output_text.insert(tk.END, f"Found {len(self.bundle_files)} file(s) in directory:\n")
        for name in bundle_names:
            self.output_text.insert(tk.END, f"  - {name}\n")
        self.output_text.insert(tk.END, "\n")

    def load_bundle_file(self, filepath):
        """Load one bundle directly without showing the directory bundle selector."""
        self._cancel_character_data_decode()
        self.cancel_lazy_syntax_highlight()
        self._cleanup_zip_temps()
        original_path = filepath
        self.current_bundle_dir = os.path.dirname(filepath)
        self.bundle_files = []
        self.bundle_entry_session = None
        self._current_zip_source = None
        self._current_zip_bundle = None
        self.bundle_label.config(text="Bundle:")
        self.hide_editor_back_button()
        self.bundle_select_frame.grid_remove()
        if filepath.lower().endswith('.zip'):
            temp_dir, bundle_path = self._extract_zip_bundle(filepath)
            if not bundle_path:
                return
            self._current_zip_source = filepath
            self._current_zip_bundle = bundle_path
            filepath = bundle_path
        self.file_path_var.set(filepath)
        self.parse_file()
        self.save_last_input(original_path, "file")

    def _cleanup_zip_temps(self):
        """Remove all previously extracted ZIP temp directories"""
        for temp_dir in self._zip_temp_dirs[:]:
            try:
                shutil.rmtree(temp_dir, ignore_errors=True)
            except Exception:
                pass
        self._zip_temp_dirs.clear()
        self._current_zip_source = None
        self._current_zip_bundle = None

    def on_bundle_selected(self, event):
        """Handle bundle selection from dropdown"""
        if self.texture_preview_session:
            self.on_texture_preview_selected(event)
            return
        if self.static_mesh_preview_session:
            self.on_static_mesh_preview_selected(event)
            return
        if self.bundle_entry_session:
            self.on_bundle_entry_selected(event)
            return

        if not self.bundle_files:
            return

        selected_index = self.bundle_dropdown.current()
        if selected_index < 0:
            return

        selected_file = self.bundle_files[selected_index]
        selected_rel = os.path.relpath(selected_file, self.current_bundle_dir) if self.current_bundle_dir else ""

        # Clean up temp dirs from any previous ZIP extraction before loading new bundle
        self._cleanup_zip_temps()

        if selected_file.lower().endswith('.zip'):
            # Extract bundle from ZIP into temp dir, then parse it
            try:
                temp_dir, bundle_path = self._extract_zip_bundle(selected_file)
                if bundle_path is None:
                    return
                self.output_text.insert(tk.END,
                    f"ZIP: {os.path.basename(selected_file)} -> {os.path.basename(bundle_path)}\n")
                # Store the actual bundle path but remember it came from a ZIP
                self._current_zip_source = selected_file
                self._current_zip_bundle = bundle_path
                self.file_path_var.set(bundle_path)
            except Exception as e:
                messagebox.showerror("ZIP Error", f"Failed to open ZIP:\n{e}")
                return
        else:
            self._current_zip_source = None
            self._current_zip_bundle = None
            self.file_path_var.set(selected_file)

        self.parse_file()
        if self.current_bundle_dir:
            self.save_last_input(self.current_bundle_dir, "directory", selected_rel)

    def parse_file(self):
        """Parse the selected file and display results"""
        self._cancel_character_data_decode()
        self.cancel_lazy_syntax_highlight()
        filepath = self.file_path_var.get()

        if not filepath:
            self.output_text.delete(1.0, tk.END)
            self._clear_editor_diff_marks()
            self.output_text.insert(tk.END, "Please select a file first.\n")
            return

        if not os.path.exists(filepath):
            self.output_text.delete(1.0, tk.END)
            self._clear_editor_diff_marks()
            self.output_text.insert(tk.END, "File does not exist.\n")
            return

        ext = os.path.splitext(filepath)[1].lower()
        if ext == '.pvm':
            try:
                data = Path(filepath).read_bytes()
            except Exception:
                data = b''
            if HAS_PVM_SCRIPT_TOOL and is_pwk_vm_module and is_pwk_vm_module(data):
                self.load_text_editor_file(filepath, ext)
                return

        if ext in ('.bsf', '.txt', '.ifc', '.ifl', '.xfg', '.prx', '.edf', '.loc'):
            self.load_text_editor_file(filepath, ext)
            return

        self.update_extract_selection_context(filepath)
        self.text_mode = None
        self.text_source_path = None
        self.bundle_entry_edit = None
        self._hide_find_bar_completely()
        self.show_find_bar()
        self.texture_preview_session = None
        self.texture_preview_entry = None
        self.texture_preview_image = None
        self.static_mesh_preview_session = None
        self.static_mesh_preview_entry = None
        self.static_mesh_export_parts = []
        if self.static_mesh_preview_viewer:
            self.static_mesh_preview_viewer.destroy()
        self.static_mesh_preview_viewer = None
        if not self.bundle_entry_session and not self.bundle_files:
            self.bundle_label.config(text="Bundle:")
            self.bundle_label.grid()
            self.bundle_dropdown.grid()
            self.hide_editor_back_button()
            self.bundle_select_frame.grid_remove()
        self.extract_btn.config(text="Extract", command=self.extract_files)
        self.rebuild_btn.config(text="Rebuild")
        if not self.rebuild_btn.winfo_manager():
            self.rebuild_btn.pack(side=tk.LEFT, padx=(0, 5), before=self.build_btn)
        self._clear_editor_diff_marks()

        # Clear output
        self.output_text.delete(1.0, tk.END)
        self.output_text.insert(tk.END, f"Parsing: {os.path.basename(filepath)}\n")

        # Add warning for PS2 bundle files
        if filepath.lower().endswith(('.cmp', '.clp', '.bdp', '.bsf')):
            self.output_text.insert(tk.END, "\n⚠ WARNING: PS2 has a Bundle limit of 2,130KB. \n")
        elif filepath.lower().endswith(('.clf',)):
            self.output_text.insert(tk.END, "\n[Xbox Bundle (.clf)]\n")
        elif filepath.lower().endswith(('.bdl',)):
            self.output_text.insert(tk.END, "\n[Xbox Bundle (.bdl)]\n")
        elif filepath.lower().endswith(('.ccg',)):
            self.output_text.insert(tk.END, "\n[GameCube Stage Bundle (.ccg)]\n")
        elif filepath.lower().endswith(('.cmf', '.ccf')):
            self.output_text.insert(tk.END, "\n[Xbox DAMM Bundle (.cmf/.ccf)]\n")

        self.output_text.insert(tk.END, "=" * 80 + "\n\n")

        # Parse file
        self.parser = PipeworksParser(filepath)
        results = self.parser.parse()

        # Display results
        if results and "error" in results[0]:
            self.output_text.insert(tk.END, results[0]["error"] + "\n")
            self.parsed_files = []
            self.extract_btn.config(state=tk.DISABLED)
            self.rebuild_btn.config(state=tk.DISABLED)
        else:
            self.parsed_files = results

            # Header
            header = f"{'NameID':<8} {'File #':<8} {'File Name':<40} {'Offset':<12} {'Size':<12}\n"
            separator = "-" * 90 + "\n"
            self.output_text.insert(tk.END, header)
            self.output_text.insert(tk.END, separator)

            # Data rows
            for entry in results:
                bundle_index = entry.get('string_id', entry.get('file_num', ''))
                file_num = entry['file_num']
                name = entry['name']
                offset = entry['offset']  # Use actual offset for all bundle types
                size = entry['size']

                row = f"{bundle_index:<8} {file_num:<8} {name:<40} {offset:<12} {size:<12}\n"
                row_start = self.output_text.index("end-1c")
                self.output_text.insert(tk.END, row)
                if self._is_editable_bundle_entry(entry):
                    name_start = f"{row_start}+18c"
                    name_end = f"{name_start}+{len(name)}c"
                    tag = f"bundle_entry_link_{file_num}"
                    self.output_text.tag_add(tag, name_start, name_end)
                    self.output_text.tag_configure(tag, foreground=self._bundle_entry_link_color(entry), underline=True)
                    self.output_text.tag_bind(tag, "<Enter>", lambda _event: self.output_text.config(cursor="hand2"))
                    self.output_text.tag_bind(tag, "<Leave>", lambda _event: self.output_text.config(cursor=""))
                    self.output_text.tag_bind(tag, "<Button-1>", lambda _event, e=entry: self.open_bundle_entry_editor(e))
                elif self._is_texture_preview_entry(entry):
                    name_start = f"{row_start}+18c"
                    name_end = f"{name_start}+{len(name)}c"
                    tag = f"texture_entry_link_{file_num}_{entry.get('raw_offset', 0)}"
                    self.output_text.tag_add(tag, name_start, name_end)
                    self.output_text.tag_configure(tag, foreground=self._bundle_entry_link_color(entry), underline=True)
                    self.output_text.tag_bind(tag, "<Enter>", lambda _event: self.output_text.config(cursor="hand2"))
                    self.output_text.tag_bind(tag, "<Leave>", lambda _event: self.output_text.config(cursor=""))
                    self.output_text.tag_bind(tag, "<Button-1>", lambda _event, e=entry: self.open_texture_preview(e))
                elif self._is_static_mesh_entry(entry):
                    name_start = f"{row_start}+18c"
                    name_end = f"{name_start}+{len(name)}c"
                    tag = f"static_mesh_link_{file_num}_{entry.get('raw_offset', 0)}"
                    self.output_text.tag_add(tag, name_start, name_end)
                    self.output_text.tag_configure(tag, foreground=self._bundle_entry_link_color(entry), underline=True)
                    self.output_text.tag_bind(tag, "<Enter>", lambda _event: self.output_text.config(cursor="hand2"))
                    self.output_text.tag_bind(tag, "<Leave>", lambda _event: self.output_text.config(cursor=""))
                    self.output_text.tag_bind(tag, "<Button-1>", lambda _event, e=entry: self.open_static_mesh_preview(e))

            self.output_text.insert(tk.END, "\n")
            self.output_text.insert(tk.END, f"Total entries: {len(results)}\n")

            # Enable actions that require a parsed bundle
            self.extract_btn.config(state=tk.NORMAL)
            self.rebuild_btn.config(state=tk.NORMAL)

    def _is_editable_bundle_entry(self, entry):
        if self._is_palette_entry(entry):
            return True
        if entry.get('is_resource'):
            return False
        name = str(entry.get('name', '')).replace('\\', '/')
        lower_name = name.lower()
        return (
            lower_name.endswith(EDITABLE_ENTRY_EXTENSIONS)
            or self._is_character_data_entry(entry)
            or self._is_level_data_entry(entry)
            or self._is_skeleton_type3_entry(entry)
            or self._is_camera_path_entry(entry)
            or self._is_fdf_entry(entry)
            or self._is_material_entry(entry)
        )

    def _is_material_entry(self, entry):
        return bool(
            HAS_MATERIAL_TEXT_TOOL
            and not entry.get('is_resource')
            and entry.get('file_type') == 6
            and entry.get('size', 0) >= 0x38
        )

    def _is_palette_entry(self, entry):
        return bool(
            HAS_PALETTE_TEXT_TOOL
            and entry.get('is_resource')
            and entry.get('file_type') == 13
            and entry.get('size', 0) >= 64
        )

    def _is_static_mesh_entry(self, entry):
        basic_match = bool(
            HAS_STATIC_MESH_VIEWER
            and not entry.get('is_resource')
            and entry.get('file_type') == 0
            and entry.get('size', 0) > 0
        )
        if not basic_match or not self.parser:
            return False
        if Path(str(getattr(self.parser, 'filepath', ''))).suffix.lower() in {'.cmg', '.cmf', '.ccf'}:
            return False
        entry_basename = Path(str(entry.get('name', '')).replace('\\', '/')).name
        if (
            not self.parser.is_big_endian
            and re.search(r'(?:^|_)bip\d*(?:_|$)', entry_basename, re.IGNORECASE)
        ):
            return False
        resource_entry = next(
            (
                candidate
                for candidate in self.parsed_files
                if candidate.get('is_resource')
                and candidate.get('file_type') == 0
                and candidate.get('file_num') == entry.get('file_num')
                and candidate.get('size', 0) > 0
            ),
            None,
        )
        if resource_entry is None:
            return False
        data_size = len(getattr(self.parser, 'file_data', b'') or b'')
        for item in (entry, resource_entry):
            offset = int(item.get('offset', -1))
            size = int(item.get('size', 0))
            if offset < 0 or size <= 0 or offset + size > data_size:
                return False
        try:
            entry_index = next(index for index, item in enumerate(self.parsed_files) if (
                item is entry or (
                    item.get('file_num') == entry.get('file_num')
                    and not item.get('is_resource')
                    and item.get('file_type') == 0
                )
            ))
        except StopIteration:
            return False
        index = entry_index - 1
        while index >= 0 and self.parsed_files[index].get('is_resource'):
            index -= 1
        is_run_root = index < 0 or self.parsed_files[index].get('file_type') != 0
        if not is_run_root:
            return False

        hierarchy_name = self._static_mesh_hierarchy_name_for_entry(entry)
        directional_match = re.match(r'^(.*)_(?:FRONT|BACK)$', hierarchy_name, re.IGNORECASE)
        if directional_match:
            base_hierarchy = directional_match.group(1).lower()
            if any(
                not candidate.get('is_resource')
                and candidate.get('file_type') == 0
                and candidate.get('file_num') != entry.get('file_num')
                and self._static_mesh_hierarchy_name_for_entry(candidate).lower() == base_hierarchy
                for candidate in self.parsed_files
            ):
                return False
        return True

    def _is_camera_path_entry(self, entry):
        return not entry.get('is_resource') and entry.get('file_type') == 21

    def _is_fdf_entry(self, entry):
        if entry.get('is_resource'):
            return False
        name = str(entry.get('name', '')).replace('\\', '/').lower()
        return name.endswith('.fdf')

    def _bundle_entry_link_color(self, entry):
        if APP_THEME_MODE == "dark":
            colors = {
                "texture": "#4ade80",
                "data": "#c084fc",
                "script": "#fb7185",
                "effect": "#fb923c",
                "mesh": "#facc15",
                "default": "#64b5f6",
            }
        else:
            colors = {
                "texture": "#15803d",
                "data": "#7e22ce",
                "script": "#be123c",
                "effect": "#c2410c",
                "mesh": "#a16207",
                "default": "#1d4ed8",
            }

        if self._is_texture_preview_entry(entry) or self._is_palette_entry(entry):
            return colors["texture"]
        if self._is_static_mesh_entry(entry):
            return colors["mesh"]
        if self._is_material_entry(entry):
            return colors["default"]
        if (
            self._is_character_data_entry(entry)
            or self._is_level_data_entry(entry)
            or self._is_skeleton_type3_entry(entry)
            or self._is_camera_path_entry(entry)
            or self._is_fdf_entry(entry)
        ):
            return colors["data"]

        name = str(entry.get('name', '')).replace('\\', '/').lower()
        if name.endswith(('.prx', '.loc', '.bsf', '.ifc', '.ifl')):
            return colors["script"]
        if name.endswith('.edf'):
            return colors["effect"]
        return colors["default"]

    def _refresh_bundle_entry_link_colors(self):
        for entry in getattr(self, "parsed_files", []) or []:
            file_num = entry.get('file_num')
            if self._is_editable_bundle_entry(entry):
                tag = f"bundle_entry_link_{file_num}"
            elif self._is_texture_preview_entry(entry):
                tag = f"texture_entry_link_{file_num}_{entry.get('raw_offset', 0)}"
            elif self._is_static_mesh_entry(entry):
                tag = f"static_mesh_link_{file_num}_{entry.get('raw_offset', 0)}"
            else:
                continue
            try:
                self.output_text.tag_configure(
                    tag, foreground=self._bundle_entry_link_color(entry)
                )
            except Exception:
                pass

    def _is_skeleton_type3_entry(self, entry):
        if entry.get('is_resource') or not HAS_SKELETON_TYPE3_TOOL:
            return False
        try:
            if int(entry.get("file_type", -1)) not in {3, 4}:
                return False
        except Exception:
            return False
        return "SKELETON" in str(entry.get("name", "")).upper()

    def _is_character_data_entry(self, entry):
        if entry.get('is_resource'):
            return False
        name = str(entry.get('name', '')).replace('\\', '/').lower()
        return name in {CHARACTER_DATA_ENTRY_NAME, MONSTER_DATA_ENTRY_NAME} or CMG_MONSTER_DATA_RE.match(name) is not None

    def _is_level_data_entry(self, entry):
        if entry.get('is_resource'):
            return False
        try:
            if int(entry.get("file_type", -1)) != 2:
                return False
        except Exception:
            return False
        base_name = Path(str(entry.get("name", "")).replace("\\", "/")).name.lower()
        return HAS_LEVEL_DATA_TOOL and (base_name == "leveldata" or re.match(r"^\d{3}leveldata$", base_name) is not None)

    def _character_data_tool_for_entry(self, entry):
        if entry.get('is_resource'):
            return None
        name = str(entry.get('name', '')).replace('\\', '/').lower()
        if name == CHARACTER_DATA_ENTRY_NAME and HAS_CHARACTER_DATA_TOOL:
            return CHARACTER_DATA_TOOL
        if name == MONSTER_DATA_ENTRY_NAME and HAS_MONSTER_DATA_TOOL:
            return MONSTER_DATA_TOOL
        if CMG_MONSTER_DATA_RE.match(name) is not None and HAS_CMG_DATA_TOOL:
            return CMG_DATA_TOOL
        if self._is_level_data_entry(entry) and HAS_LEVEL_DATA_TOOL:
            return LEVEL_DATA_TOOL
        return None

    def _character_data_label_for_entry(self, entry):
        name = str(entry.get('name', '')).replace('\\', '/').lower()
        if name == MONSTER_DATA_ENTRY_NAME:
            return "000MONSTER_DATA"
        if CMG_MONSTER_DATA_RE.match(name) is not None:
            return Path(str(entry.get("name", "MONSTER_DATA")).replace("\\", "/")).name or "MONSTER_DATA"
        if self._is_level_data_entry(entry):
            return Path(str(entry.get("name", "LevelData")).replace("\\", "/")).name or "LevelData"
        return "Character_Data"

    def _is_texture_preview_entry(self, entry):
        return bool(
            entry.get('is_resource')
            and entry.get('file_type') == 9
            and entry.get('size', 0) > 0
        )

    def open_static_mesh_preview(self, entry):
        if not self.parser or not self._is_static_mesh_entry(entry):
            return
        resource_entry = next(
            (
                candidate
                for candidate in self.parsed_files
                if candidate.get('is_resource')
                and candidate.get('file_type') == 0
                and candidate.get('file_num') == entry.get('file_num')
                and candidate.get('size', 0) > 0
            ),
            None,
        )
        if resource_entry is None:
            messagebox.showerror("Static Mesh Preview", "This type-0 entry has no paired resource data.", parent=self.root)
            return
        try:
            main_data = bytes(self.parser.read_bytes(entry['offset'], entry['size']))
            resource_data = bytes(self.parser.read_bytes(resource_entry['offset'], resource_entry['size']))
            if self.static_mesh_preview_viewer:
                self.static_mesh_preview_viewer.destroy()
            if not self.static_mesh_preview_session:
                self.static_mesh_preview_session = {
                    "bundle_path": self.parser.filepath,
                    "entries": [dict(item) for item in self.parsed_files if self._is_static_mesh_entry(item)],
                    "return_context": self._bundle_editor_return_context(self.parser.filepath),
                }
            self.static_mesh_preview_entry = dict(entry)
            self.text_mode = None
            self.text_source_path = None
            self.bundle_entry_edit = None
            self._hide_find_bar_completely()
            self._setup_static_mesh_preview_selector(entry)
            self.extract_btn.config(text="Export", command=self.export_static_mesh_preview, state=tk.NORMAL)
            self.rebuild_btn.pack_forget()
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete(1.0, tk.END)
            self.output_text.edit_reset()
            self.output_text.edit_modified(False)
            self._clear_editor_diff_marks()
            display_name = str(entry.get('name', 'type-0 mesh')).replace('\\', '/')
            self.output_text.insert(
                tk.END,
                f"Static mesh: {display_name}\n"
                "[Some Objects may not be handled correctly yet]\n\n",
            )
            connected_group = [entry] + self._static_mesh_connected_entries(entry)
            part_transforms = {}
            ordered_parts = sorted(
                connected_group,
                key=lambda part: next((index for index, item in enumerate(self.parsed_files) if (
                    not item.get('is_resource') and item.get('file_type') == 0
                    and item.get('file_num') == part.get('file_num')
                )), len(self.parsed_files)),
            )
            native_runs = []
            for part in ordered_parts:
                if not native_runs:
                    native_runs.append([part])
                    continue
                previous = native_runs[-1][-1]
                previous_index = next(index for index, item in enumerate(self.parsed_files) if (
                    not item.get('is_resource') and item.get('file_type') == 0
                    and item.get('file_num') == previous.get('file_num')
                ))
                part_index = next(index for index, item in enumerate(self.parsed_files) if (
                    not item.get('is_resource') and item.get('file_type') == 0
                    and item.get('file_num') == part.get('file_num')
                ))
                separators = [
                    item for item in self.parsed_files[previous_index + 1:part_index]
                    if not item.get('is_resource') and item.get('file_type') != 0
                ]
                if separators:
                    native_runs.append([part])
                else:
                    native_runs[-1].append(part)
            for native_run in native_runs:
                part_transforms.update(self._static_mesh_part_transforms(native_run))
            hierarchy_name = self._static_mesh_hierarchy_name_for_entry(entry).lower()
            if hierarchy_name == 'super_maser_tank':
                rear_part = next((
                    part for part in connected_group
                    if Path(str(part.get('name', '')).replace('\\', '/')).name.lower().endswith('super_maser_tank_back')
                ), None)
                front_part = next((
                    part for part in connected_group
                    if Path(str(part.get('name', '')).replace('\\', '/')).name.lower().endswith('super_maser_tank_front')
                ), None)

                def mesh_y_bounds(part):
                    if part is None:
                        return None
                    resource = next((
                        candidate for candidate in self.parsed_files
                        if candidate.get('is_resource')
                        and candidate.get('file_type') == 0
                        and candidate.get('file_num') == part.get('file_num')
                    ), None)
                    if resource is None:
                        return None
                    mesh = STATIC_MESH_VIEWER.decode_static_mesh(
                        bytes(self.parser.read_bytes(part['offset'], part['size'])),
                        bytes(self.parser.read_bytes(resource['offset'], resource['size'])),
                        bool(self.parser.is_big_endian),
                        gx_variant=self._static_mesh_gx_variant(),
                    )
                    values = [vertex[1] for vertex in mesh.vertices]
                    return (min(values), max(values)) if values else None

                rear_bounds = mesh_y_bounds(rear_part)
                front_bounds = mesh_y_bounds(front_part)
                if rear_bounds and front_bounds:
                    front_offset = rear_bounds[1] - front_bounds[0]
                    attachment = [
                        [1.0, 0.0, 0.0, 0.0],
                        [0.0, 1.0, 0.0, front_offset],
                        [0.0, 0.0, 1.0, 0.0],
                        [0.0, 0.0, 0.0, 1.0],
                    ]
                    identity = [
                        [1.0, 0.0, 0.0, 0.0],
                        [0.0, 1.0, 0.0, 0.0],
                        [0.0, 0.0, 1.0, 0.0],
                        [0.0, 0.0, 0.0, 1.0],
                    ]
                    for part in connected_group:
                        if self._static_mesh_hierarchy_name_for_entry(part).lower() == 'super_maser_tank_front':
                            file_num = part.get('file_num')
                            part_transforms[file_num] = self._static_mesh_matrix_multiply(
                                attachment, part_transforms.get(file_num, identity)
                            )
            part_textures = {part.get('file_num'): self._static_mesh_texture_for_entry(part) for part in connected_group}
            self.static_mesh_export_parts = []
            for part in connected_group:
                part_resource = next((
                    candidate for candidate in self.parsed_files
                    if candidate.get('is_resource')
                    and candidate.get('file_type') == 0
                    and candidate.get('file_num') == part.get('file_num')
                    and candidate.get('size', 0) > 0
                ), None)
                if part_resource is None:
                    continue
                self.static_mesh_export_parts.append({
                    'name': Path(str(part.get('name', 'mesh')).replace('\\', '/')).name,
                    'main': bytes(self.parser.read_bytes(part['offset'], part['size'])),
                    'resource': bytes(self.parser.read_bytes(part_resource['offset'], part_resource['size'])),
                    'transform': part_transforms.get(part.get('file_num')),
                    'materials': part_textures.get(part.get('file_num')),
                })
            connected_parts = []
            for part_entry in connected_group:
                if part_entry.get('file_num') == entry.get('file_num'):
                    continue
                part_resource = next(
                    (
                        candidate for candidate in self.parsed_files
                        if candidate.get('is_resource')
                        and candidate.get('file_type') == 0
                        and candidate.get('file_num') == part_entry.get('file_num')
                        and candidate.get('size', 0) > 0
                    ),
                    None,
                )
                if part_resource is not None:
                    connected_parts.append((
                        bytes(self.parser.read_bytes(part_entry['offset'], part_entry['size'])),
                        bytes(self.parser.read_bytes(part_resource['offset'], part_resource['size'])),
                        part_transforms.get(part_entry.get('file_num')),
                        part_textures.get(part_entry.get('file_num')),
                    ))
            self.static_mesh_preview_viewer = STATIC_MESH_VIEWER.embed_viewer(
                self.output_text,
                main_data,
                resource_data,
                bool(self.parser.is_big_endian),
                palette=THEME_PALETTES.get(APP_THEME_MODE, THEME_PALETTES['dark']),
                connected_parts=connected_parts,
                mesh_transform=part_transforms.get(entry.get('file_num')),
                texture=part_textures.get(entry.get('file_num')),
                gx_variant=self._static_mesh_gx_variant(),
            )
        except Exception as exc:
            messagebox.showerror("Static Mesh Preview", str(exc), parent=self.root)

    @staticmethod
    def _static_mesh_export_name(value, fallback='mesh'):
        cleaned = re.sub(r'[^A-Za-z0-9_.-]+', '_', str(value)).strip('._')
        return cleaned or fallback

    def export_static_mesh_preview(self):
        parts = list(getattr(self, 'static_mesh_export_parts', []) or [])
        if not parts:
            messagebox.showerror("Export Static Mesh", "No preview mesh is available to export.", parent=self.root)
            return
        parent = filedialog.askdirectory(title="Choose folder for OBJ export", parent=self.root)
        if not parent:
            return
        entry_name = Path(str((self.static_mesh_preview_entry or {}).get('name', 'mesh')).replace('\\', '/')).name
        export_name = self._static_mesh_export_name(entry_name)
        export_dir = Path(parent) / export_name
        export_dir.mkdir(parents=True, exist_ok=True)
        obj_path = export_dir / f"{export_name}.obj"
        mtl_path = export_dir / f"{export_name}.mtl"

        obj_lines = [f"mtllib {mtl_path.name}", ""]
        mtl_lines = []
        vertex_base = 1
        uv_base = 1
        written_materials = set()
        written_textures = {}
        used_texture_names = set()
        for part_index, part in enumerate(parts):
            mesh = STATIC_MESH_VIEWER.decode_static_mesh(
                part['main'], part['resource'], bool(self.parser.is_big_endian), part.get('materials'),
                self._static_mesh_gx_variant(),
            )
            mesh = STATIC_MESH_VIEWER.transform_mesh(mesh, part.get('transform'))
            group_name = self._static_mesh_export_name(part.get('name'), f"part_{part_index + 1}")
            obj_lines.extend((f"o {group_name}", f"g {group_name}"))
            # OBJ is Y-up; Blender maps this Y offset onto its Z-up stage height.
            obj_lines.extend(f"v {x:.9g} {z + 15.0:.9g} {-y:.9g}" for x, y, z in mesh.vertices)
            if mesh.uvs:
                obj_lines.extend(f"vt {u:.9g} {1.0 - v:.9g}" for u, v in mesh.uvs)

            active_material = None
            for face_index, face in enumerate(mesh.faces):
                material_id = mesh.face_materials[face_index] if mesh.face_materials else None
                options = part.get('materials') or {}
                material = options.get(material_id, {}) if isinstance(options, dict) else {}
                opacity = float(material.get('opacity', 1.0))
                if opacity <= 0.001:
                    continue
                material_key = f"{group_name}_{material_id if material_id is not None else 'default'}"
                if material_key != active_material:
                    obj_lines.append(f"usemtl {material_key}")
                    active_material = material_key
                if material_key not in written_materials:
                    mtl_lines.extend((f"newmtl {material_key}", "Kd 1.0 1.0 1.0", f"d {opacity:.6g}"))
                    image = material.get('image')
                    if image is not None:
                        texture_key = id(image)
                        texture_name = written_textures.get(texture_key)
                        if texture_name is None:
                            source_name = material.get('name') or f"texture_{len(written_textures) + 1}"
                            texture_name = self._static_mesh_export_name(source_name, 'texture') + '.png'
                            candidate = texture_name
                            suffix = 2
                            while candidate in used_texture_names:
                                candidate = f"{Path(texture_name).stem}_{suffix}.png"
                                suffix += 1
                            texture_name = candidate
                            image.convert('RGBA').save(export_dir / texture_name)
                            written_textures[texture_key] = texture_name
                            used_texture_names.add(texture_name)
                        mtl_lines.append(f"map_Kd {texture_name}")
                    mtl_lines.append("")
                    written_materials.add(material_key)
                uv_face = mesh.uv_faces[face_index] if mesh.uv_faces else face
                if mesh.uvs:
                    values = [f"{vertex_base + vertex}/{uv_base + uv}" for vertex, uv in zip(face, uv_face)]
                else:
                    values = [str(vertex_base + vertex) for vertex in face]
                obj_lines.append("f " + " ".join(values))
            obj_lines.append("")
            vertex_base += len(mesh.vertices)
            uv_base += len(mesh.uvs or [])

        obj_path.write_text('\n'.join(obj_lines) + '\n', encoding='utf-8')
        mtl_path.write_text('\n'.join(mtl_lines) + '\n', encoding='utf-8')
        messagebox.showinfo(
            "Export Static Mesh",
            f"Exported {len(parts)} submesh{'es' if len(parts) != 1 else ''} to:\n{export_dir}",
            parent=self.root,
        )

    def _static_mesh_connected_entries(self, selected_entry):
        """Return adjacent type-0 mains in the same native model part run."""
        if self._static_mesh_gx_variant() == 'ps2' and PS2_STATIC_MESH is not None:
            return PS2_STATIC_MESH.connected_entries(self.parsed_files, selected_entry)
        if self._static_mesh_gx_variant() == 'gamecube' and GAMECUBE_STATIC_MESH is not None:
            return GAMECUBE_STATIC_MESH.connected_entries(self.parsed_files, selected_entry)
        try:
            selected_index = self.parsed_files.index(selected_entry)
        except ValueError:
            selected_index = next(
                (index for index, item in enumerate(self.parsed_files) if (
                    item.get('file_num') == selected_entry.get('file_num')
                    and not item.get('is_resource')
                    and item.get('file_type') == 0
                )),
                -1,
            )
        if selected_index < 0:
            return []

        first = selected_index
        while first > 0:
            candidate = self.parsed_files[first - 1]
            if candidate.get('is_resource'):
                first -= 1
                continue
            if candidate.get('file_type') != 0:
                break
            first -= 1

        group = []
        index = first
        while index < len(self.parsed_files):
            candidate = self.parsed_files[index]
            if candidate.get('is_resource'):
                index += 1
                continue
            if candidate.get('file_type') != 0:
                break
            group.append(candidate)
            index += 1
        selected_hierarchy = self._static_mesh_hierarchy_name_for_entry(selected_entry)
        family_match = re.match(r'^(.*?)(?:_(?:FRONT|BACK))?$', selected_hierarchy, re.IGNORECASE)
        family = family_match.group(1).lower() if family_match else selected_hierarchy.lower()
        has_directional_companion = any(
            not candidate.get('is_resource') and candidate.get('file_type') == 0
            and self._static_mesh_hierarchy_name_for_entry(candidate).lower() in {
                family + '_front', family + '_back'
            }
            for candidate in self.parsed_files
        )
        directional_group = selected_hierarchy.lower().endswith(('_front', '_back')) or has_directional_companion
        if directional_group:
            for candidate in self.parsed_files:
                if candidate.get('is_resource') or candidate.get('file_type') != 0:
                    continue
                candidate_name = Path(str(candidate.get('name', '')).replace('\\', '/')).name.lower()
                if not candidate_name.startswith(family):
                    continue
                hierarchy_name = self._static_mesh_hierarchy_name_for_entry(candidate).lower()
                if hierarchy_name == family or hierarchy_name in {family + '_front', family + '_back'}:
                    if not any(item.get('file_num') == candidate.get('file_num') for item in group):
                        group.append(candidate)
            allowed_hierarchies = {family, family + '_front', family + '_back'}
            group = [
                candidate for candidate in group
                if Path(str(candidate.get('name', '')).replace('\\', '/')).name.lower().startswith(family)
                and self._static_mesh_hierarchy_name_for_entry(candidate).lower() in allowed_hierarchies
            ]
        return [candidate for candidate in group if candidate.get('file_num') != selected_entry.get('file_num')]

    def _static_mesh_hierarchy_name_for_entry(self, entry):
        if self._static_mesh_gx_variant() == 'ps2' and PS2_STATIC_MESH is not None:
            return PS2_STATIC_MESH.owner_name(self.parsed_files, entry)
        if self._static_mesh_gx_variant() == 'gamecube' and GAMECUBE_STATIC_MESH is not None:
            return GAMECUBE_STATIC_MESH.owner_name(self.parsed_files, entry)
        try:
            index = next(index for index, item in enumerate(self.parsed_files) if (
                not item.get('is_resource') and item.get('file_type') == 0
                and item.get('file_num') == entry.get('file_num')
            ))
        except StopIteration:
            return ''
        for candidate in reversed(self.parsed_files[:index]):
            if candidate.get('is_resource'):
                continue
            if candidate.get('file_type') == 3:
                return Path(str(candidate.get('name', '')).replace('\\', '/')).name
        return ''

    @staticmethod
    def _static_mesh_matrix_multiply(left, right):
        return [
            [sum(left[row][axis] * right[axis][column] for axis in range(4)) for column in range(4)]
            for row in range(4)
        ]

    def _static_mesh_part_transforms(self, group):
        if not group:
            return {}
        if self._static_mesh_gx_variant() == 'ps2' and PS2_STATIC_MESH is not None:
            return PS2_STATIC_MESH.part_transforms(self.parser, self.parsed_files, group)
        if self._static_mesh_gx_variant() == 'gamecube':
            return self._static_mesh_gamecube_part_transforms(group)
        indices = [
            index for index, item in enumerate(self.parsed_files)
            if any(item is member or (
                item.get('file_num') == member.get('file_num')
                and not item.get('is_resource')
                and item.get('file_type') == 0
            ) for member in group)
        ]
        if not indices:
            return {}
        hierarchy = next(
            (
                item for item in reversed(self.parsed_files[:min(indices)])
                if not item.get('is_resource') and item.get('file_type') == 3
            ),
            None,
        )
        if hierarchy is None:
            return {}
        try:
            blob = bytes(self.parser.read_bytes(hierarchy['offset'], hierarchy['size']))
            strings = [value.decode('latin1', errors='replace') for value in self.parser._read_pipeworks_string_entries()]
            root_offset = struct.unpack_from('>I', blob, 0x1C)[0]
            nodes = {}
            visited = set()

            def walk(relative):
                if relative in visited or relative < 0 or relative + 0x30 > len(blob):
                    return
                visited.add(relative)
                node_index, parent, child_count, name_index = struct.unpack_from('>4i', blob, relative)
                if not (0 <= child_count <= 128 and 0 <= name_index < len(strings)):
                    return
                qx, qy, qz, qw = struct.unpack_from('>4f', blob, relative + 0x10)
                tx, ty, tz = struct.unpack_from('>3f', blob, relative + 0x20)
                norm = qx*qx + qy*qy + qz*qz + qw*qw
                scale = 2.0 / norm if norm > 1.0e-12 else 0.0
                xx, yy, zz = qx*qx*scale, qy*qy*scale, qz*qz*scale
                xy, xz, yz = qx*qy*scale, qx*qz*scale, qy*qz*scale
                wx, wy, wz = qw*qx*scale, qw*qy*scale, qw*qz*scale
                local = [
                    [1.0-yy-zz, xy-wz, xz+wy, tx],
                    [xy+wz, 1.0-xx-zz, yz-wx, ty],
                    [xz-wy, yz+wx, 1.0-xx-yy, tz],
                    [0.0, 0.0, 0.0, 1.0],
                ]
                nodes[node_index] = {'parent': parent, 'name': strings[name_index], 'local': local}
                for child in struct.unpack_from('>' + ('I' * child_count), blob, relative + 0x30):
                    walk(child)

            walk(root_offset)
            globals_by_index = {}

            def global_matrix(index):
                if index in globals_by_index:
                    return globals_by_index[index]
                node = nodes[index]
                parent = node['parent']
                result = node['local']
                if parent in nodes:
                    result = self._static_mesh_matrix_multiply(global_matrix(parent), result)
                globals_by_index[index] = result
                return result

            named = {node['name'].lower(): global_matrix(index) for index, node in nodes.items()}
            transforms = {}
            for part in group:
                basename = Path(str(part.get('name', '')).replace('\\', '/')).name.lower()
                matches = [(name, matrix) for name, matrix in named.items() if basename.endswith(name)]
                if matches:
                    transforms[part.get('file_num')] = max(matches, key=lambda match: len(match[0]))[1]
            return transforms
        except Exception:
            return {}

    def _static_mesh_gamecube_part_transforms(self, group):
        if GAMECUBE_STATIC_MESH is None:
            return {}
        try:
            return GAMECUBE_STATIC_MESH.part_transforms(self.parser, self.parsed_files, group)
        except Exception:
            return {}

    def _static_mesh_gamecube_part_transforms_legacy(self, group):
        indices = [
            index for index, item in enumerate(self.parsed_files)
            if any(item is member or (
                item.get('file_num') == member.get('file_num')
                and not item.get('is_resource')
                and item.get('file_type') == 0
            ) for member in group)
        ]
        if not indices:
            return {}
        hierarchy_index = next((
            index for index in range(min(indices) - 1, -1, -1)
            if not self.parsed_files[index].get('is_resource')
            and self.parsed_files[index].get('file_type') == 3
        ), None)
        if hierarchy_index is None:
            return {}
        type4 = next((
            item for item in self.parsed_files[hierarchy_index + 1:min(len(self.parsed_files), hierarchy_index + 5)]
            if not item.get('is_resource') and item.get('file_type') == 4
        ), None)
        if type4 is None:
            return {}
        try:
            hierarchy = self.parsed_files[hierarchy_index]
            skeleton = bytes(self.parser.read_bytes(hierarchy['offset'], hierarchy['size']))
            animation = bytes(self.parser.read_bytes(type4['offset'], type4['size']))
            strings = [value.decode('latin1', errors='replace') for value in self.parser._read_pipeworks_string_entries()]
            node_count = struct.unpack_from('>I', skeleton, 0x20)[0]
            node_offsets = struct.unpack_from('>I', skeleton, 0x2C)[0]
            animation_count = struct.unpack_from('>I', animation, 0x2C)[0]
            animation_offsets = struct.unpack_from('>I', animation, 0x30)[0]
            if not (0 < node_count <= animation_count < 512):
                return {}
            nodes = {}
            for table_index in range(node_count):
                relative = struct.unpack_from('>I', skeleton, node_offsets + table_index * 4)[0]
                if relative + 0x10 > len(skeleton):
                    continue
                node_index, parent, _child_count, name_index = struct.unpack_from('>4i', skeleton, relative)
                if not (0 <= node_index < animation_count and 0 <= name_index < len(strings)):
                    continue
                transform_relative = struct.unpack_from('>I', animation, animation_offsets + node_index * 4)[0]
                if transform_relative + 0x40 > len(animation):
                    continue
                tx, ty, tz = struct.unpack_from('>3f', animation, transform_relative + 0x18)
                qx, qy, qz, qw = struct.unpack_from('>4f', animation, transform_relative + 0x30)
                norm = qx*qx + qy*qy + qz*qz + qw*qw
                scale = 2.0 / norm if norm > 1.0e-12 else 0.0
                xx, yy, zz = qx*qx*scale, qy*qy*scale, qz*qz*scale
                xy, xz, yz = qx*qy*scale, qx*qz*scale, qy*qz*scale
                wx, wy, wz = qw*qx*scale, qw*qy*scale, qw*qz*scale
                local = [
                    [1.0-yy-zz, xy-wz, xz+wy, tx],
                    [xy+wz, 1.0-xx-zz, yz-wx, ty],
                    [xz-wy, yz+wx, 1.0-xx-yy, tz],
                    [0.0, 0.0, 0.0, 1.0],
                ]
                nodes[node_index] = {'parent': parent, 'name': strings[name_index], 'local': local}

            globals_by_index = {}

            def global_matrix(index):
                if index in globals_by_index:
                    return globals_by_index[index]
                node = nodes[index]
                is_root = node['parent'] not in nodes or node['parent'] == index
                if is_root:
                    local = node['local']
                    result = [
                        [1.0, 0.0, 0.0, local[0][3]],
                        [0.0, 1.0, 0.0, local[1][3]],
                        [0.0, 0.0, 1.0, local[2][3]],
                        [0.0, 0.0, 0.0, 1.0],
                    ]
                else:
                    result = node['local']
                if not is_root:
                    result = self._static_mesh_matrix_multiply(global_matrix(node['parent']), result)
                globals_by_index[index] = result
                return result

            named = {
                node['name'].lower(): (index, global_matrix(index))
                for index, node in nodes.items()
            }
            transforms = {}
            primary_file_num = group[0].get('file_num') if group else None
            primary_name = str(group[0].get('name', '')).lower() if group else ''
            for part in group:
                basename = Path(str(part.get('name', '')).replace('\\', '/')).name.lower()
                matches = [
                    (name, node_index, matrix)
                    for name, (node_index, matrix) in named.items()
                    if basename.endswith(name)
                ]
                if matches:
                    _name, node_index, matrix = max(matches, key=lambda match: len(match[0]))
                    if part.get('file_num') == primary_file_num:
                        matrix = [
                            [1.0, 0.0, 0.0, matrix[0][3]],
                            [0.0, 1.0, 0.0, matrix[1][3]],
                            [0.0, 0.0, 1.0, matrix[2][3]],
                            [0.0, 0.0, 0.0, 1.0],
                        ]
                    elif 'mothra_mesh_' in primary_name and basename.endswith('wing'):
                        matrix = [list(row) for row in matrix]
                        source_z = list(matrix[2])
                        matrix[1] = source_z
                        matrix[2] = [0.0, 0.0, 0.0, 0.0]
                    transforms[part.get('file_num')] = matrix
            return transforms
        except Exception:
            return {}

    def _static_mesh_texture_for_entry(self, mesh_entry):
        if self._static_mesh_gx_variant() == 'ps2':
            return self._static_mesh_texture_for_ps2_entry(mesh_entry)
        if self._static_mesh_gx_variant() == 'gamecube':
            return self._static_mesh_texture_for_gamecube_entry(mesh_entry)
        return self._static_mesh_texture_for_wii_entry(mesh_entry)

    def _static_mesh_gx_variant(self):
        suffix = Path(str(self.parser.filepath)).suffix.lower()
        if not self.parser.is_big_endian:
            return 'ps2'
        return 'gamecube' if suffix in {'.ccg', '.cmg'} else 'wii'

    def _static_mesh_texture_for_gamecube_entry(self, mesh_entry):
        return self._static_mesh_texture_for_gx_entry(mesh_entry, gamecube=True)

    def _static_mesh_texture_for_wii_entry(self, mesh_entry):
        return self._static_mesh_texture_for_gx_entry(mesh_entry, gamecube=False)

    def _static_mesh_texture_for_ps2_entry(self, mesh_entry):
        if PS2_STATIC_MESH is None:
            return None
        try:
            mesh_data = bytes(self.parser.read_bytes(mesh_entry['offset'], mesh_entry['size']))
            material_entries = {}
            for item in self.parsed_files:
                if item.get('is_resource') or item.get('file_type') != 6 or item.get('size', 0) < 2:
                    continue
                blob = bytes(self.parser.read_bytes(item['offset'], item['size']))
                material_entries[struct.unpack_from('<H', blob, 0)[0]] = (item, blob)
            material_ids = PS2_STATIC_MESH.material_ids(mesh_data, set(material_entries))
            if not material_ids:
                return None
            preview_session = getattr(self, 'static_mesh_preview_session', None)
            decoded_images = (
                preview_session.setdefault('decoded_material_textures', {})
                if preview_session is not None else {}
            )
            material_map = {}
            for material_id in dict.fromkeys(material_ids):
                material_pair = material_entries.get(material_id)
                if material_pair is None:
                    continue
                material_entry, material_blob = material_pair
                texture_candidates = []
                for asset_id in PS2_STATIC_MESH.texture_asset_ids(material_blob):
                    asset_entry = next((
                        item for item in self.parsed_files
                        if not item.get('is_resource')
                        and item.get('string_id') == asset_id
                        and item.get('file_type') in {2, 9}
                    ), None)
                    if asset_entry is None:
                        continue
                    if asset_entry.get('file_type') == 9:
                        candidate_texture = asset_entry
                    else:
                        ifl_data = bytes(self.parser.read_bytes(asset_entry['offset'], asset_entry['size']))
                        lines = ifl_data.decode('ascii', errors='ignore').splitlines()
                        first_frame = lines[0].split()[0] if lines else ''
                        frame_stem = Path(first_frame).stem.lower()
                        candidate_texture = next((
                            item for item in self.parsed_files
                            if not item.get('is_resource') and item.get('file_type') == 9
                            and Path(str(item.get('name', '')).replace('\\', '/')).name.lower() == frame_stem
                        ), None)
                    if candidate_texture is not None and candidate_texture not in texture_candidates:
                        texture_candidates.append(candidate_texture)
                texture_main = None
                largest_area = -1
                for candidate_texture in texture_candidates:
                    candidate_resource = next((
                        item for item in self.parsed_files
                        if item.get('is_resource') and item.get('file_type') == 9
                        and item.get('file_num') == candidate_texture.get('file_num')
                        and item.get('size', 0) > 0
                    ), None)
                    if candidate_resource is None:
                        continue
                    texture_data = bytes(self.parser.read_bytes(
                        candidate_texture['offset'], candidate_texture['size']
                    ))
                    info = self.parser._texture_info_from_main_data(
                        texture_data, candidate_resource.get('size', 0)
                    )
                    area = int(info.get('width', 0)) * int(info.get('height', 0))
                    if area > largest_area:
                        largest_area = area
                        texture_main = candidate_texture
                image = None
                environment_image = None
                if texture_main is not None:
                    texture_resource = next((
                        item for item in self.parsed_files
                        if item.get('is_resource') and item.get('file_type') == 9
                        and item.get('file_num') == texture_main.get('file_num')
                        and item.get('size', 0) > 0
                    ), None)
                    if texture_resource is not None:
                        cache_key = (self.parser.filepath, texture_resource.get('file_num'))
                        image = decoded_images.get(cache_key)
                        if image is None:
                            texture_data = bytes(self.parser.read_bytes(texture_main['offset'], texture_main['size']))
                            resource_data = bytes(self.parser.read_bytes(texture_resource['offset'], texture_resource['size']))
                            info = self.parser._texture_info_from_main_data(texture_data, len(resource_data))
                            info = self.parser._texture_info_with_name_hint(info, str(texture_main.get('name', '')))
                            image = self.parser._decode_ps2_texture_image(resource_data, info, texture_main)
                            decoded_images[cache_key] = image
                    texture_basename = Path(
                        str(texture_main.get('name', '')).replace('\\', '/')
                    ).name.lower()
                    if image is not None and 'cubemap' in texture_basename:
                        environment_image = image
                        image = None
                color = None
                material_opacity = 1.0
                if len(material_blob) >= 0x14:
                    diffuse = struct.unpack_from('<3f', material_blob, 8)
                    if all(math.isfinite(value) for value in diffuse):
                        color = tuple(max(0, min(255, round(value * 255.0))) for value in diffuse)
                if len(material_blob) >= 0x18:
                    native_alpha = struct.unpack_from('<f', material_blob, 0x14)[0]
                    if math.isfinite(native_alpha):
                        material_opacity = max(0.0, min(1.0, native_alpha))
                flags = PS2_STATIC_MESH.material_flags(str(mesh_entry.get('name', '')), material_blob)
                material_name = str(material_entry.get('name', '')).lower()
                mesh_name_lower = str(mesh_entry.get('name', '')).lower()
                if image is not None and (
                    'biggodzillalogo' in material_name
                    or 'billboard' in mesh_name_lower
                    or 'billboard' in material_name
                    or '_sign_' in mesh_name_lower
                    or '/sign_' in material_name
                    or '_sign_' in material_name
                ):
                    image = image.transpose(Image.Transpose.FLIP_LEFT_RIGHT)
                if image is not None and 'foliage' in material_name:
                    foliage = image.convert('RGBA')
                    foliage.putdata([
                        (r, g, b, 0 if max(r, g, b) <= 12 or max(r, g, b) - min(r, g, b) > 40 else a)
                        for r, g, b, a in foliage.getdata()
                    ])
                    image = foliage
                depth_only = 'zwrite' in material_name
                render_flags = struct.unpack_from('<I', material_blob, 4)[0] if len(material_blob) >= 8 else 0
                header_flags = struct.unpack_from('<H', material_blob, 2)[0] if len(material_blob) >= 4 else 0
                alpha_test = bool(render_flags & 0x00100000 and header_flags & 0x0001)
                alpha_source = image if image is not None else environment_image
                explicit_alpha_material = any(
                    token in material_name for token in ('propmap', 'decal')
                )
                has_texture_alpha = bool(
                    (alpha_test or explicit_alpha_material or 'foliage' in material_name)
                    and
                    alpha_source is not None
                    and alpha_source.mode in {'LA', 'RGBA'}
                    and alpha_source.getchannel('A').getextrema() != (255, 255)
                )
                black_key = bool(
                    flags.get('black_key')
                    or ('foliage' in material_name and not has_texture_alpha)
                )
                material_map[material_id] = {
                    'name': material_name,
                    'texture_name': str(texture_main.get('name', '')) if texture_main is not None else None,
                    'image': image,
                    'environment_image': environment_image,
                    'two_sided': bool(flags.get('two_sided')),
                    'black_key': black_key,
                    'texture_alpha': has_texture_alpha,
                    'alpha_test': bool(alpha_test and has_texture_alpha),
                    'vertex_alpha': bool(render_flags & 0x00100000),
                    'opacity': 0.0 if depth_only else (
                        material_opacity
                    ),
                    'uv_set': 0,
                    'uv_transform': PS2_STATIC_MESH.texture_transform(material_blob),
                    'legacy_uv': False,
                    'color': color,
                }
            return material_map or None
        except Exception:
            return None

    def _static_mesh_texture_for_gx_entry(self, mesh_entry, gamecube):
        try:
            mesh_data = bytes(self.parser.read_bytes(mesh_entry['offset'], mesh_entry['size']))
            endian = '>' if self.parser.is_big_endian else '<'
            material_ids = []
            if self.parser.is_big_endian and len(mesh_data) >= 0x38:
                if gamecube:
                    legacy_surface_count = struct.unpack_from('>I', mesh_data, 0)[0]
                    for surface_index in range(min(legacy_surface_count, 1024)):
                        material_offset = 0x84 + surface_index * 0x7C
                        if material_offset + 2 > len(mesh_data):
                            break
                        candidate = struct.unpack_from('>H', mesh_data, material_offset)[0]
                        if candidate and candidate not in material_ids:
                            material_ids.append(candidate)
                else:
                    surface_count = struct.unpack_from('>I', mesh_data, 0x10)[0]
                    for surface_index in range(min(surface_count, 1024)):
                        material_offset = 0x36 + surface_index * 0x60
                        if material_offset + 2 > len(mesh_data):
                            break
                        material_ids.append(struct.unpack_from('>H', mesh_data, material_offset)[0])

            if material_ids:
                mesh_name_lower = str(mesh_entry.get('name', '')).lower()
                material_entries = {}
                texture_main_by_id = {}
                for item in self.parsed_files:
                    if item.get('is_resource') or item.get('size', 0) < 2:
                        continue
                    if item.get('file_type') not in {6, 9}:
                        continue
                    blob = bytes(self.parser.read_bytes(item['offset'], item['size']))
                    if item.get('file_type') == 6:
                        record_id = struct.unpack_from(endian + 'H', blob, 0)[0]
                        material_entries[record_id] = (item, blob)
                    else:
                        metadata = bytes(item.get('metadata_bytes') or b'')
                        if len(metadata) < 8:
                            continue
                        record_id = struct.unpack_from(endian + 'H', metadata, 6)[0]
                        texture_main_by_id[record_id] = item

                material_map = {}
                preview_session = getattr(self, 'static_mesh_preview_session', None)
                decoded_images = (
                    preview_session.setdefault('decoded_material_textures', {})
                    if preview_session is not None else {}
                )
                for material_id in material_ids:
                    material_pair = material_entries.get(material_id)
                    if material_pair is None:
                        continue
                    _material_entry, material_blob = material_pair
                    texture_main = None
                    if gamecube:
                        texture_id = (
                            struct.unpack_from('>H', material_blob, 0x38)[0]
                            if len(material_blob) >= 0x3A else 0
                        )
                        texture_main = texture_main_by_id.get(texture_id)
                        asset_id = texture_id
                        asset_entry = next((
                            candidate for candidate in self.parsed_files
                            if not candidate.get('is_resource')
                            and candidate.get('string_id') == asset_id
                            and candidate.get('file_type') in {2, 9}
                        ), None)
                        if texture_main is None and asset_entry is not None:
                            if asset_entry.get('file_type') == 9:
                                texture_main = asset_entry
                            else:
                                ifl_data = bytes(self.parser.read_bytes(
                                    asset_entry['offset'], asset_entry['size']
                                ))
                                first_frame = ifl_data.decode('ascii', errors='ignore').splitlines()
                                first_frame = first_frame[0].split()[0] if first_frame else ''
                                frame_stem = Path(first_frame).stem.lower()
                                texture_main = next((
                                    candidate for candidate in self.parsed_files
                                    if not candidate.get('is_resource')
                                    and candidate.get('file_type') == 9
                                    and Path(str(candidate.get('name', '')).replace('\\', '/')).name.lower() == frame_stem
                                ), None)
                        if texture_main is None and texture_id:
                            material_index = self.parsed_files.index(_material_entry)
                            for candidate in self.parsed_files[material_index + 1:]:
                                if candidate.get('is_resource'):
                                    continue
                                if candidate.get('file_type') in {0, 6}:
                                    break
                                if candidate.get('file_type') == 9:
                                    texture_main = candidate
                                    break
                    else:
                        texture_id = (
                            struct.unpack_from(endian + 'I', material_blob, 0x38)[0] >> 16
                            if len(material_blob) >= 0x3C else 0
                        )
                        if not texture_id and len(material_blob) >= 0x32:
                            texture_id = struct.unpack_from(endian + 'H', material_blob, 0x30)[0]
                        texture_main = texture_main_by_id.get(texture_id)
                    image = None
                    if texture_main is not None:
                        texture_resource = next((
                            item for item in self.parsed_files
                            if item.get('is_resource')
                            and item.get('file_type') == 9
                            and item.get('file_num') == texture_main.get('file_num')
                            and item.get('size', 0) > 0
                        ), None)
                        if texture_resource is not None:
                            cache_key = (self.parser.filepath, texture_resource.get('file_num'))
                            image = decoded_images.get(cache_key)
                            if image is None:
                                texture_main_data = bytes(self.parser.read_bytes(texture_main['offset'], texture_main['size']))
                                resource_data = bytes(self.parser.read_bytes(texture_resource['offset'], texture_resource['size']))
                                info = self.parser._texture_info_from_main_data(texture_main_data, len(resource_data))
                                info = self.parser._texture_info_with_name_hint(info, str(texture_main.get('name', '')))
                                base_size = self.parser._texture_block_size(info['format'], info['width'], info['height'])
                                image = self.parser._decode_texture_image(
                                    resource_data[:base_size], info['format'], info['width'], info['height']
                                )
                                decoded_images[cache_key] = image
                    material_name = str(_material_entry.get('name', '')).lower()
                    hidden_preview_material = gamecube and any(
                        token in material_name for token in (
                            'freezerayorigin', 'exhaust', 'gouge_zwrite', 'skirt'
                        )
                    )
                    hidden_preview_material = hidden_preview_material or (
                        gamecube and 'skirt' in mesh_name_lower
                    )
                    is_blended_shell = (
                        'inner_reflect' in mesh_name_lower
                        or ('water' in material_name and 'watertower' not in material_name)
                    )
                    force_opaque = material_name.endswith('/tripod_si') or material_name == 'tripod_si'
                    render_flags = struct.unpack_from(endian + 'I', material_blob, 4)[0] if len(material_blob) >= 8 else 0
                    render_mode = render_flags & 0x0F
                    alpha_test = render_mode == 0x0D and not force_opaque
                    alpha_blend = render_mode == 0x0E and not force_opaque
                    is_effect_alpha = alpha_test or alpha_blend
                    native_opacity = 1.0
                    uses_secondary_uv = (
                        not gamecube
                        and (
                            'stone' in material_name
                            or (
                                any(token in material_name for token in ('_win_', 'window'))
                                and 'blend_shell' not in material_name
                            )
                        )
                    )
                    solid_color = None
                    if gamecube and len(material_blob) >= 0x28:
                        diffuse = struct.unpack_from('>4f', material_blob, 0x18)
                        if all(math.isfinite(value) for value in diffuse):
                            solid_color = tuple(
                                max(0, min(255, round(value * 255.0)))
                                for value in diffuse[:3]
                            )
                    is_debug_solid = bool(
                        gamecube
                        and image is None
                        and solid_color is not None
                        and re.search(r'material\s*#\d+', material_name, re.IGNORECASE)
                        and max(solid_color) >= 230
                        and min(solid_color) <= 80
                        and max(solid_color) - min(solid_color) >= 160
                    )
                    gamecube_flags = (
                        GAMECUBE_STATIC_MESH.material_flags(mesh_name_lower, material_blob)
                        if gamecube and GAMECUBE_STATIC_MESH is not None else {}
                    )
                    black_key = bool(gamecube_flags.get('black_key'))
                    color_key = bool(gamecube_flags.get('color_key'))
                    material_map[material_id] = {
                        'name': material_name,
                        'texture_name': str(texture_main.get('name', '')) if texture_main is not None else None,
                        'image': image,
                        'two_sided': bool(gamecube_flags.get('two_sided')) if gamecube else bool(
                            len(material_blob) > 7 and material_blob[7] & 0x01
                        ),
                        'black_key': black_key,
                        'texture_alpha': bool(black_key or color_key or is_effect_alpha),
                        'alpha_test': alpha_test,
                        'vertex_alpha': alpha_blend,
                        'color_key': bool(color_key or (
                            alpha_test and image is not None and image.mode in {'RGB', 'RGBA'}
                            and (image.mode == 'RGB' or image.getchannel('A').getextrema() == (255, 255))
                        )),
                        'opacity': 0.0 if hidden_preview_material or is_debug_solid else (
                            native_opacity if is_effect_alpha else (0.42 if is_blended_shell else 1.0)
                        ),
                        'uv_set': 1 if uses_secondary_uv else 0,
                        'legacy_uv': bool(gamecube_flags.get('legacy_uv')),
                        'color': solid_color,
                    }
                if not gamecube and '_lo_' in mesh_name_lower and material_map:
                    family = mesh_name_lower.split('_lo_', 1)[0].rsplit('/', 1)[-1]
                    roof_pair = next((
                        (candidate, bytes(self.parser.read_bytes(candidate['offset'], candidate['size'])))
                        for candidate in self.parsed_files
                        if not candidate.get('is_resource') and candidate.get('file_type') == 6
                        and family in str(candidate.get('name', '')).lower()
                        and 'roof_blend_shell' in str(candidate.get('name', '')).lower()
                    ), None)
                    if roof_pair is not None:
                        _roof_material, roof_blob = roof_pair
                        roof_material_id = (
                            struct.unpack_from(endian + 'H', roof_blob, 0)[0]
                            if len(roof_blob) >= 2 else None
                        )
                        roof_uv_bounds = None
                        detailed_mesh_entry = next((
                            candidate for candidate in self.parsed_files
                            if not candidate.get('is_resource') and candidate.get('file_type') == 0
                            and str(candidate.get('name', '')).lower().rsplit('/', 1)[-1]
                            == f'{family}_{family}'
                        ), None)
                        if detailed_mesh_entry is not None and STATIC_MESH_VIEWER is not None:
                            detailed_resource = next((
                                candidate for candidate in self.parsed_files
                                if candidate.get('is_resource') and candidate.get('file_type') == 0
                                and candidate.get('file_num') == detailed_mesh_entry.get('file_num')
                                and candidate.get('size', 0) > 0
                            ), None)
                            if detailed_resource is not None:
                                detailed_mesh = STATIC_MESH_VIEWER.decode_static_mesh(
                                    bytes(self.parser.read_bytes(
                                        detailed_mesh_entry['offset'], detailed_mesh_entry['size']
                                    )),
                                    bytes(self.parser.read_bytes(
                                        detailed_resource['offset'], detailed_resource['size']
                                    )),
                                    bool(self.parser.is_big_endian),
                                    gx_variant='wii',
                                )
                                roof_uvs = [
                                    detailed_mesh.uvs[uv_index]
                                    for face_index, uv_face in enumerate(detailed_mesh.uv_faces or [])
                                    if detailed_mesh.face_materials
                                    and detailed_mesh.face_materials[face_index] == roof_material_id
                                    for uv_index in uv_face
                                ]
                                if roof_uvs:
                                    roof_uv_bounds = (
                                        min(uv[0] for uv in roof_uvs), max(uv[0] for uv in roof_uvs),
                                        min(uv[1] for uv in roof_uvs), max(uv[1] for uv in roof_uvs),
                                    )
                        roof_texture_id = (
                            struct.unpack_from(endian + 'I', roof_blob, 0x38)[0] >> 16
                            if len(roof_blob) >= 0x3C else 0
                        )
                        roof_texture = texture_main_by_id.get(roof_texture_id)
                        if roof_texture is not None:
                            roof_resource = next((
                                item for item in self.parsed_files
                                if item.get('is_resource') and item.get('file_type') == 9
                                and item.get('file_num') == roof_texture.get('file_num')
                                and item.get('size', 0) > 0
                            ), None)
                            if roof_resource is not None:
                                cache_key = (self.parser.filepath, roof_resource.get('file_num'))
                                roof_image = decoded_images.get(cache_key)
                                if roof_image is None:
                                    roof_main = bytes(self.parser.read_bytes(roof_texture['offset'], roof_texture['size']))
                                    roof_data = bytes(self.parser.read_bytes(roof_resource['offset'], roof_resource['size']))
                                    roof_info = self.parser._texture_info_from_main_data(roof_main, len(roof_data))
                                    roof_info = self.parser._texture_info_with_name_hint(
                                        roof_info, str(roof_texture.get('name', ''))
                                    )
                                    roof_size = self.parser._texture_block_size(
                                        roof_info['format'], roof_info['width'], roof_info['height']
                                    )
                                    roof_image = self.parser._decode_texture_image(
                                        roof_data[:roof_size], roof_info['format'],
                                        roof_info['width'], roof_info['height']
                                    )
                                    decoded_images[cache_key] = roof_image
                                if roof_image is not None:
                                    for material in material_map.values():
                                        material['roof_image'] = roof_image
                                        material['roof_uv_bounds'] = roof_uv_bounds
                    detailed_mesh_entry = next((
                        candidate for candidate in self.parsed_files
                        if not candidate.get('is_resource') and candidate.get('file_type') == 0
                        and str(candidate.get('name', '')).lower().rsplit('/', 1)[-1]
                        == f'{family}_{family}'
                    ), None)
                    if detailed_mesh_entry is not None and STATIC_MESH_VIEWER is not None:
                        detailed_resource = next((
                            candidate for candidate in self.parsed_files
                            if candidate.get('is_resource') and candidate.get('file_type') == 0
                            and candidate.get('file_num') == detailed_mesh_entry.get('file_num')
                            and candidate.get('size', 0) > 0
                        ), None)
                        if detailed_resource is not None:
                            detailed_mesh = STATIC_MESH_VIEWER.decode_static_mesh(
                                bytes(self.parser.read_bytes(
                                    detailed_mesh_entry['offset'], detailed_mesh_entry['size']
                                )),
                                bytes(self.parser.read_bytes(
                                    detailed_resource['offset'], detailed_resource['size']
                                )),
                                bool(self.parser.is_big_endian),
                                gx_variant='wii',
                            )
                            detailed_materials = self._static_mesh_texture_for_gx_entry(
                                detailed_mesh_entry, False
                            ) or {}
                            counterpart_roofs = {}
                            for face_index, face in enumerate(detailed_mesh.faces):
                                a, b, c = (detailed_mesh.vertices[index] for index in face)
                                ux, uy, uz = (b[index] - a[index] for index in range(3))
                                vx, vy, vz = (c[index] - a[index] for index in range(3))
                                nx, ny, nz = uy*vz-uz*vy, uz*vx-ux*vz, ux*vy-uy*vx
                                normal_length = math.sqrt(nx*nx + ny*ny + nz*nz) or 1.0
                                if abs(nz) / normal_length < 0.9:
                                    continue
                                material_id = (
                                    detailed_mesh.face_materials[face_index]
                                    if detailed_mesh.face_materials else None
                                )
                                detailed_material = detailed_materials.get(material_id) or {}
                                detailed_image = detailed_material.get('image')
                                if detailed_image is None or not detailed_mesh.uv_faces:
                                    continue
                                positions = [
                                    tuple(round(value, 4) for value in detailed_mesh.vertices[index])
                                    for index in face
                                ]
                                uv_face = detailed_mesh.uv_faces[face_index]
                                counterpart_roofs[tuple(sorted(positions))] = {
                                    'image': detailed_image,
                                    'uv_by_position': {
                                        position: detailed_mesh.uvs[uv_face[index]]
                                        for index, position in enumerate(positions)
                                    },
                                }
                            if counterpart_roofs:
                                for material in material_map.values():
                                    material['counterpart_roofs'] = counterpart_roofs
                if material_map:
                    return material_map

            mesh_index = next(index for index, item in enumerate(self.parsed_files) if (
                item.get('file_num') == mesh_entry.get('file_num')
                and not item.get('is_resource')
                and item.get('file_type') == 0
            ))
            start = mesh_index
            while start > 0:
                candidate = self.parsed_files[start - 1]
                if not candidate.get('is_resource') and candidate.get('file_type') in {3, 16}:
                    break
                start -= 1
            textures = [
                item for item in self.parsed_files[start:mesh_index]
                if item.get('is_resource') and item.get('file_type') == 9 and item.get('size', 0) > 0
            ]
            if not textures:
                return None
            mesh_name = Path(str(mesh_entry.get('name', '')).replace('\\', '/')).name.lower()
            mesh_tokens = set(re.findall(r'[a-z0-9]+', mesh_name))
            def texture_score(item):
                texture_tokens = set(re.findall(
                    r'[a-z0-9]+',
                    Path(str(item.get('name', '')).replace('\\', '/')).stem.lower(),
                ))
                shared = mesh_tokens & texture_tokens
                effect_only = {'anim', 'animated', 'glow', 'strobe'}
                unmatched_effects = (texture_tokens & effect_only) - mesh_tokens
                part_matches = shared - {'map', 'texture'}
                map_bonus = 1 if 'map' in texture_tokens and not ({'drill', 'wheel', 'gun', 'barrel'} & mesh_tokens) else 0
                return (
                    len(part_matches) * 4 + map_bonus - len(unmatched_effects) * 8,
                    -len(texture_tokens - mesh_tokens - {'map', 'texture'}),
                    textures.index(item),
                )

            texture = max(textures, key=texture_score)
            main_entry = self.parser._texture_main_entry_for_resource(texture)
            main_data = bytes(self.parser.read_bytes(main_entry['offset'], main_entry['size']))
            resource_data = bytes(self.parser.read_bytes(texture['offset'], texture['size']))
            info = self.parser._texture_info_from_main_data(main_data, len(resource_data))
            info = self.parser._texture_info_with_name_hint(info, str(main_entry.get('name', '')))
            base_size = self.parser._texture_block_size(info['format'], info['width'], info['height'])
            return self.parser._decode_texture_image(
                resource_data[:base_size], info['format'], info['width'], info['height']
            )
        except Exception:
            return None

    def _setup_static_mesh_preview_selector(self, selected_entry):
        if not self.static_mesh_preview_session:
            return
        entries = self.static_mesh_preview_session.get("entries", [])
        values = [str(item.get('name', 'mesh')).replace('\\', '/') for item in entries]
        self._updating_bundle_dropdown = True
        self.bundle_dropdown["values"] = values
        selected_name = str(selected_entry.get('name', 'mesh')).replace('\\', '/')
        if selected_name in values:
            self.bundle_dropdown.current(values.index(selected_name))
        elif values:
            self.bundle_dropdown.current(0)
        self.bundle_label.config(text="Mesh:")
        self.bundle_label.grid()
        self.bundle_dropdown.grid()
        self.bundle_select_frame.grid()
        self.show_editor_back_button()
        self._updating_bundle_dropdown = False

    def on_static_mesh_preview_selected(self, _event=None):
        if self._updating_bundle_dropdown or not self.static_mesh_preview_session:
            return
        selected_index = self.bundle_dropdown.current()
        entries = self.static_mesh_preview_session.get("entries", [])
        if 0 <= selected_index < len(entries):
            self.open_static_mesh_preview(entries[selected_index])

    def _texture_preview_entries(self):
        return [entry for entry in self.parsed_files if self._is_texture_preview_entry(entry)]

    def _texture_preview_display_name(self, entry):
        name = str(entry.get('name', 'texture')).replace('\\', '/')
        return name[:-9] if name.lower().endswith('.resource') else name

    def _texture_preview_temp_dir(self, entry):
        ensure_app_dirs()
        bundle_name = safe_path_name(Path(self.parser.filepath).stem if self.parser and hasattr(self.parser, 'filepath') else "bundle")
        temp_dir = get_temp_dir() / "texture_previews" / bundle_name
        temp_dir.mkdir(parents=True, exist_ok=True)
        return temp_dir

    def _ensure_texture_preview_session(self, entry):
        bundle_path = self.parser.filepath
        if (
            self.texture_preview_session
            and os.path.abspath(self.texture_preview_session.get("bundle_path", "")).lower() == os.path.abspath(bundle_path).lower()
        ):
            return self.texture_preview_session

        temp_dir = self._texture_preview_temp_dir(entry)
        shutil.rmtree(temp_dir, ignore_errors=True)
        temp_dir.mkdir(parents=True, exist_ok=True)
        entries = self._texture_preview_entries()
        self.texture_preview_session = {
            "bundle_path": bundle_path,
            "replacement_dir": str(temp_dir),
            "entries": [dict(item) for item in entries],
            "return_context": self._bundle_editor_return_context(bundle_path),
        }
        return self.texture_preview_session

    def _setup_texture_preview_selector(self, selected_entry):
        if not self.texture_preview_session:
            return
        values = [self._texture_preview_display_name(entry) for entry in self.texture_preview_session["entries"]]
        self._updating_bundle_dropdown = True
        self.bundle_dropdown["values"] = values
        selected_name = self._texture_preview_display_name(selected_entry)
        if selected_name in values:
            self.bundle_dropdown.current(values.index(selected_name))
        elif values:
            self.bundle_dropdown.current(0)
        if self.syntax_progress_active:
            self._updating_bundle_dropdown = False
            return
        self.bundle_label.grid()
        self.bundle_dropdown.grid()
        self.bundle_label.config(text="Texture:")
        self.show_editor_back_button()
        self.bundle_select_frame.grid()
        self._updating_bundle_dropdown = False

    def _texture_preview_png_path(self, session, entry):
        resource_path = Path(session["replacement_dir"]) / str(entry.get('name', '')).replace('\\', '/')
        if str(resource_path).lower().endswith('.resource'):
            return Path(str(resource_path)[:-9] + '.png')
        return Path(str(resource_path) + '.png')

    def on_texture_preview_selected(self, event):
        if self._updating_bundle_dropdown or not self.texture_preview_session:
            return
        selected_index = self.bundle_dropdown.current()
        entries = self.texture_preview_session.get("entries", [])
        if selected_index < 0 or selected_index >= len(entries):
            return
        self.open_texture_preview(entries[selected_index])

    def open_texture_preview(self, entry):
        if not self.parser or not self.parsed_files:
            return
        if not self._is_texture_preview_entry(entry):
            return

        session = self._ensure_texture_preview_session(entry)
        png_path = self._texture_preview_png_path(session, entry)
        resource_path = Path(session["replacement_dir"]) / str(entry.get('name', '')).replace('\\', '/')
        if not resource_path.exists() or not png_path.exists():
            if not self.parser.extract_file(entry, session["replacement_dir"]):
                messagebox.showerror("Texture Preview", f"Failed to extract texture:\n{entry.get('name')}")
                return

        self.texture_preview_entry = dict(entry)
        self.text_mode = None
        self.text_source_path = None
        self.bundle_entry_edit = None
        self._hide_find_bar_completely()
        self._setup_texture_preview_selector(entry)
        self.extract_btn.config(text="Replace PNG", state=tk.NORMAL)
        self.rebuild_btn.config(text="Save", state=tk.DISABLED)
        self.output_text.delete(1.0, tk.END)
        self.output_text.edit_reset()
        self.output_text.edit_modified(False)
        self._clear_editor_diff_marks()

        display_name = self._texture_preview_display_name(entry)
        self.output_text.insert(tk.END, f"Texture: {display_name}\n")
        self.output_text.insert(tk.END, f"Raw: {resource_path}\n")
        if not png_path.exists():
            self.texture_preview_image = None
            self.output_text.insert(tk.END, "\nNo PNG preview could be generated for this texture format yet.\n")
            self.output_text.insert(tk.END, "The raw .resource file is still available.\n")
            return

        self.output_text.insert(tk.END, f"PNG: {png_path}\n\n")
        if not HAS_PIL or ImageTk is None:
            self.output_text.insert(tk.END, "Pillow ImageTk is not available, so the PNG cannot be shown inline.\n")
            return
        try:
            image = Image.open(png_path).convert('RGBA')
            max_width = max(160, self.output_text.winfo_width() - 40)
            max_height = 420
            scale = min(max_width / image.width, max_height / image.height)
            if scale > 1.0:
                scale = min(scale, 4.0)
                resampling = getattr(Image, 'Resampling', Image)
                resample = getattr(resampling, 'NEAREST', Image.NEAREST)
            else:
                resampling = getattr(Image, 'Resampling', Image)
                resample = getattr(resampling, 'LANCZOS', Image.LANCZOS)
            if abs(scale - 1.0) > 0.01:
                image = image.resize((max(1, int(image.width * scale)), max(1, int(image.height * scale))), resample)
            self.texture_preview_image = ImageTk.PhotoImage(image)
            self.output_text.image_create(tk.END, image=self.texture_preview_image)
            self.output_text.insert(tk.END, "\n")
        except Exception as exc:
            self.texture_preview_image = None
            self.output_text.insert(tk.END, f"Failed to show PNG preview:\n{exc}\n")

    def replace_texture_preview_png(self):
        if not self.texture_preview_session or not self.texture_preview_entry:
            return False
        png_path = self._texture_preview_png_path(self.texture_preview_session, self.texture_preview_entry)
        selected = _dialog(
            self.root,
            filedialog.askopenfilename,
            title="Select Replacement PNG",
            initialdir=str(png_path.parent) if png_path.parent.exists() else os.path.expanduser("~"),
            filetypes=[("PNG Images", "*.png"), ("All Files", "*.*")],
        )
        if not selected:
            return False
        return self._replace_texture_preview_png_from_path(selected)

    def _replace_texture_preview_png_from_path(self, selected):
        if not self.texture_preview_session or not self.texture_preview_entry:
            return False
        if not selected or not os.path.isfile(selected) or not selected.lower().endswith('.png'):
            messagebox.showerror("Replace PNG", "Drop a valid PNG file onto the open texture preview.")
            return False
        if HAS_PIL:
            try:
                with Image.open(selected) as replacement:
                    replacement.verify()
            except Exception as exc:
                messagebox.showerror("Replace PNG", f"The dropped file is not a valid PNG:\n{exc}")
                return False
        png_path = self._texture_preview_png_path(self.texture_preview_session, self.texture_preview_entry)
        try:
            png_path.parent.mkdir(parents=True, exist_ok=True)
            if os.path.abspath(selected).lower() != os.path.abspath(png_path).lower():
                shutil.copy2(selected, png_path)
            now = datetime.now().timestamp()
            os.utime(png_path, (now, now))
        except Exception as exc:
            messagebox.showerror("Replace PNG", f"Failed to copy replacement PNG:\n{exc}")
            return False
        return self.save_texture_preview_edit()

    def save_texture_preview_edit(self):
        if not self.texture_preview_session or not self.texture_preview_entry:
            return False
        if not self.parser or not self.parsed_files:
            messagebox.showerror("Save Texture", "Original bundle is no longer loaded.")
            return False

        output_path = self.texture_preview_session["bundle_path"]
        temp_output = str(get_temp_dir() / f"{Path(output_path).name}.texture_tmp")
        replacement_dir = self.texture_preview_session["replacement_dir"]
        if self.parser.bundle_type == 'vol':
            success = self.parser.rebuild_vol(temp_output, self.parsed_files, replacement_dir)
        else:
            success = self.parser.rebuild_bdg(temp_output, self.parsed_files, replacement_dir)

        if success:
            backup = self.create_incremental_backup(output_path)
            os.replace(temp_output, output_path)
            self.parser = PipeworksParser(output_path)
            self.parsed_files = self.parser.parse()
            old_name = self.texture_preview_entry.get('name')
            updated_entry = next((entry for entry in self.parsed_files if entry.get('name') == old_name), None)
            if updated_entry:
                self.texture_preview_entry = dict(updated_entry)
                if self.texture_preview_session:
                    self.texture_preview_session["entries"] = [dict(item) for item in self._texture_preview_entries()]
            self.open_texture_preview(self.texture_preview_entry)
            messagebox.showinfo("Saved", f"Texture PNG packed into bundle:\n{output_path}\nBackup: {backup}")
            return True

        try:
            if os.path.exists(temp_output):
                os.remove(temp_output)
        except Exception:
            pass
        messagebox.showerror("Save Texture", "Failed to rebuild bundle with replacement PNG.")
        return False

    def _bundle_entry_temp_dir(self, entry):
        ensure_app_dirs()
        bundle_name = safe_path_name(Path(self.parser.filepath).stem if self.parser and hasattr(self.parser, 'filepath') else "bundle")
        temp_dir = get_temp_dir() / "bundle_entry_edits" / bundle_name
        temp_dir.mkdir(parents=True, exist_ok=True)
        return temp_dir

    def _editable_bundle_entries(self):
        return [entry for entry in self.parsed_files if self._is_editable_bundle_entry(entry)]

    def _bundle_entry_display_name(self, entry):
        return str(entry.get('name', 'entry')).replace('\\', '/')

    def _ensure_bundle_entry_session(self, entry):
        bundle_path = self.parser.filepath
        if (
            self.bundle_entry_session
            and os.path.abspath(self.bundle_entry_session.get("bundle_path", "")).lower() == os.path.abspath(bundle_path).lower()
        ):
            return self.bundle_entry_session

        temp_dir = self._bundle_entry_temp_dir(entry)
        shutil.rmtree(temp_dir, ignore_errors=True)
        temp_dir.mkdir(parents=True, exist_ok=True)
        entries = self._editable_bundle_entries()
        self.bundle_entry_session = {
            "bundle_path": bundle_path,
            "replacement_dir": str(temp_dir),
            "entries": [dict(item) for item in entries],
            "return_context": self._bundle_editor_return_context(bundle_path),
        }
        return self.bundle_entry_session

    def _entry_temp_path(self, session, entry):
        return Path(session["replacement_dir"]) / self._bundle_entry_display_name(entry)

    def _bundle_editor_return_context(self, bundle_path=None):
        match_ranges = self.output_text.tag_ranges("find_match")
        context = {
            "mode": "directory" if self.bundle_files else "file",
            "directory": self.current_bundle_dir,
            "selected_rel": self.bundle_dropdown.get() if self.bundle_files else "",
            "bundle_path": bundle_path or (self.parser.filepath if self.parser and hasattr(self.parser, "filepath") else ""),
            "zip_source": self._current_zip_source,
            "find_query": self.find_var.get(),
            "find_visible": bool(self.find_frame.winfo_ismapped()),
            "find_match": str(match_ranges[0]) if match_ranges else "",
            "insert": str(self.output_text.index(tk.INSERT)),
            "yview": self.output_text.yview()[0],
            "xview": self.output_text.xview()[0],
        }
        if self._current_zip_source:
            context["mode"] = "file" if not self.bundle_files else "directory"
        return context

    def _setup_bundle_entry_selector(self, selected_entry):
        if not self.bundle_entry_session:
            return
        values = [self._bundle_entry_display_name(entry) for entry in self.bundle_entry_session["entries"]]
        self._updating_bundle_dropdown = True
        self.bundle_dropdown["values"] = values
        selected_name = self._bundle_entry_display_name(selected_entry)
        if selected_name in values:
            self.bundle_dropdown.current(values.index(selected_name))
        elif values:
            self.bundle_dropdown.current(0)
        if self.syntax_progress_active:
            self._updating_bundle_dropdown = False
            return
        self.bundle_label.grid()
        self.bundle_dropdown.grid()
        self.bundle_label.config(text="Editable:")
        self.show_editor_back_button()
        self.bundle_select_frame.grid()
        self._updating_bundle_dropdown = False

    def on_bundle_entry_selected(self, event):
        if self._updating_bundle_dropdown or not self.bundle_entry_session:
            return
        selected_index = self.bundle_dropdown.current()
        entries = self.bundle_entry_session.get("entries", [])
        if selected_index < 0 or selected_index >= len(entries):
            return
        if not self._stage_current_bundle_editor_changes():
            if self.bundle_entry_edit:
                self._setup_bundle_entry_selector(self.bundle_entry_edit.get("entry", {}))
            return
        self.open_bundle_entry_editor(entries[selected_index])

    def _stage_current_bundle_editor_changes(self):
        """Compile the current editor into the temporary multi-file session."""
        if not self.bundle_entry_edit or not self._editor_has_unsaved_text_changes():
            return True
        if not self.write_current_editor_to_source():
            return False
        self.output_text.edit_reset()
        self.output_text.edit_modified(False)
        self._sync_editor_diff_baseline()
        return True

    def _changed_bundle_entry_names(self):
        if not self.bundle_entry_session:
            return []
        changed = []
        replacement_dir = Path(self.bundle_entry_session["replacement_dir"])
        for entry in self.bundle_entry_session.get("entries", []):
            temp_path = replacement_dir / self._bundle_entry_display_name(entry)
            if not temp_path.exists():
                continue
            try:
                original = self.parser.read_bytes(entry["offset"], entry["size"])
                edited = temp_path.read_bytes()
            except Exception:
                changed.append(self._bundle_entry_display_name(entry))
                continue
            if edited != original:
                changed.append(self._bundle_entry_display_name(entry))
        return changed

    def _prompt_save_bundle_entry_changes(self, changed_names):
        if not changed_names:
            return False, []

        dialog = tk.Toplevel(self.root)
        set_window_icon(dialog)
        dialog.title("Save Bundle Changes")
        dialog.transient(self.root)
        dialog.resizable(False, False)
        result = {"choice": None}
        variables = []

        body = ttk.Frame(dialog, padding=14)
        body.pack(fill=tk.BOTH, expand=True)
        ttk.Label(body, text="Save these edited file(s) into the bundle?").pack(
            anchor=tk.W, pady=(0, 10)
        )
        list_frame = ttk.Frame(body)
        list_frame.pack(fill=tk.BOTH, expand=True)
        for name in changed_names:
            selected = tk.BooleanVar(value=True)
            variables.append((name, selected))
            ttk.Checkbutton(list_frame, text=name, variable=selected).pack(anchor=tk.W, pady=1)

        buttons = ttk.Frame(body)
        buttons.pack(fill=tk.X, pady=(14, 0))

        def finish(choice):
            result["choice"] = choice
            dialog.destroy()

        ttk.Button(buttons, text="Yes", command=lambda: finish(True), width=10).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(buttons, text="No", command=lambda: finish(False), width=10).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(buttons, text="Cancel", command=lambda: finish(None), width=10).pack(side=tk.LEFT)
        dialog.protocol("WM_DELETE_WINDOW", lambda: finish(None))
        dialog.bind("<Escape>", lambda _event: finish(None))
        dialog.bind("<Return>", lambda _event: finish(True))
        apply_button_outline(dialog)
        dialog.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(0, x)}+{max(0, y)}")
        dialog.grab_set()
        dialog.focus_force()
        dialog.wait_window()
        selected_names = [name for name, selected in variables if selected.get()]
        return result["choice"], selected_names

    def _restore_bundle_entry_return_context(self, context):
        mode = context.get("mode") if context else ""
        if mode == "directory" and context.get("directory") and os.path.isdir(context["directory"]):
            selected_rel = context.get("selected_rel", "")
            select_file = os.path.join(context["directory"], selected_rel) if selected_rel else None
            self.load_directory(context["directory"], select_file=select_file)
            self.root.after_idle(lambda c=dict(context): self._restore_bundle_view_state(c))
            return
        zip_source = context.get("zip_source") if context else None
        if zip_source and os.path.exists(zip_source):
            self.load_bundle_file(zip_source)
            self.root.after_idle(lambda c=dict(context): self._restore_bundle_view_state(c))
            return
        bundle_path = context.get("bundle_path") if context else None
        if not bundle_path and self.parser and hasattr(self.parser, "filepath"):
            bundle_path = self.parser.filepath
        if bundle_path and os.path.exists(bundle_path):
            self.load_bundle_file(bundle_path)
            self.root.after_idle(lambda c=dict(context): self._restore_bundle_view_state(c))

    def _restore_bundle_view_state(self, context):
        query = str(context.get("find_query", ""))
        self.find_var.set(query)
        if context.get("find_visible"):
            self._position_find_bar()
        else:
            self.find_frame.place_forget()
        self.output_text.tag_remove("find_match", "1.0", tk.END)
        match = str(context.get("find_match", ""))
        if query and match:
            try:
                if self.output_text.get(match, f"{match}+{len(query)}c").lower() == query.lower():
                    self.output_text.tag_add("find_match", match, f"{match}+{len(query)}c")
            except tk.TclError:
                pass
        try:
            self.output_text.mark_set(tk.INSERT, context.get("insert", "1.0"))
            self.output_text.xview_moveto(float(context.get("xview", 0.0)))
            self.output_text.yview_moveto(float(context.get("yview", 0.0)))
        except (tk.TclError, TypeError, ValueError):
            pass

    def back_to_bundle_view(self):
        self._cancel_character_data_decode()
        self.cancel_lazy_syntax_highlight()
        # Read-only viewers such as FDF disable the shared output widget.
        # Restore it before the bundle parser redraws the main file listing.
        self.output_text.config(state=tk.NORMAL)
        if self.texture_preview_session:
            session = self.texture_preview_session
            context = dict(session.get("return_context", {})) if session else {}
            if session:
                context["bundle_path"] = session.get("bundle_path")
            self.texture_preview_session = None
            self.texture_preview_entry = None
            self.texture_preview_image = None
            self.bundle_label.config(text="Bundle:")
            self.bundle_label.grid()
            self.bundle_dropdown.grid()
            self.hide_editor_back_button()
            self.extract_btn.config(text="Extract")
            self.rebuild_btn.config(text="Rebuild")
            self._restore_bundle_entry_return_context(context)
            return

        if self.static_mesh_preview_session:
            session = self.static_mesh_preview_session
            context = dict(session.get("return_context", {})) if session else {}
            if session:
                context["bundle_path"] = session.get("bundle_path")
            if self.static_mesh_preview_viewer:
                self.static_mesh_preview_viewer.destroy()
            self.static_mesh_preview_session = None
            self.static_mesh_preview_entry = None
            self.static_mesh_preview_viewer = None
            self.bundle_label.config(text="Bundle:")
            self.bundle_label.grid()
            self.bundle_dropdown.grid()
            self.hide_editor_back_button()
            self.extract_btn.config(text="Extract", command=self.extract_files, state=tk.NORMAL)
            self.rebuild_btn.config(text="Rebuild", state=tk.NORMAL)
            if not self.rebuild_btn.winfo_manager():
                self.rebuild_btn.pack(side=tk.LEFT, padx=(0, 5), before=self.build_btn)
            self._restore_bundle_entry_return_context(context)
            return

        session = self.bundle_entry_session
        context = dict(session.get("return_context", {})) if session else {}
        if session:
            context["bundle_path"] = session.get("bundle_path")
            context.setdefault("zip_source", self._current_zip_source)
        # Back is governed by the aggregate bundle-change prompt below. Stage
        # the current editor into the session first so it appears in that one
        # list instead of showing a redundant single-file save prompt.
        if not self._stage_current_bundle_editor_changes():
            return
        changed_names = self._changed_bundle_entry_names()
        if changed_names:
            save_choice, selected_names = self._prompt_save_bundle_entry_changes(changed_names)
            if save_choice is None:
                return
            if save_choice:
                if not self.save_bundle_entry_edit(selected_names=selected_names):
                    return
        self.bundle_entry_edit = None
        self.bundle_entry_session = None
        self.bundle_label.config(text="Bundle:")
        self.bundle_label.grid()
        self.bundle_dropdown.grid()
        self.hide_editor_back_button()
        self._restore_bundle_entry_return_context(context)

    def open_bundle_entry_editor(self, entry):
        if not self.parser or not self.parsed_files:
            return
        if not self._is_editable_bundle_entry(entry):
            return

        session = self._ensure_bundle_entry_session(entry)
        if self._is_palette_entry(entry):
            self.open_palette_editor(entry, session)
            return
        if self._is_camera_path_entry(entry):
            self.open_camera_path_editor(entry, session)
            return
        if self._is_fdf_entry(entry):
            self.open_fdf_viewer(entry, session)
            return
        if self._is_character_data_entry(entry) or self._is_level_data_entry(entry):
            self.open_character_data_editor(entry, session)
            return
        if self._is_skeleton_type3_entry(entry):
            self.open_skeleton_type3_editor(entry, session)
            return
        if self._is_material_entry(entry):
            self.open_material_editor(entry, session)
            return

        temp_path = self._entry_temp_path(session, entry)
        if not temp_path.exists():
            if not self.parser.extract_file(entry, session["replacement_dir"]):
                messagebox.showerror("Open Entry", f"Failed to extract entry:\n{entry.get('name')}")
                return
            if not temp_path.exists():
                matches = list(Path(session["replacement_dir"]).rglob(Path(entry['name']).name))
                if not matches:
                    messagebox.showerror("Open Entry", f"Extracted entry was not found in temp folder:\n{entry.get('name')}")
                    return
                temp_path = matches[0]

        self.bundle_entry_edit = {
            "bundle_path": session["bundle_path"],
            "entry": dict(entry),
            "replacement_dir": session["replacement_dir"],
            "temp_path": str(temp_path),
        }
        self._setup_bundle_entry_selector(entry)

        ext = temp_path.suffix.lower()
        self.load_text_editor_file(str(temp_path), ext, from_bundle_entry=True)

    def _entry_binary_editor_paths(self, entry, session, text_suffix):
        temp_path = self._entry_temp_path(session, entry)
        if not temp_path.exists():
            if not self.parser.extract_file(entry, session["replacement_dir"]):
                raise ValueError(f"Failed to extract entry: {entry.get('name')}")
            if not temp_path.exists():
                matches = list(Path(session["replacement_dir"]).rglob(Path(entry['name']).name))
                if not matches:
                    raise ValueError(f"Extracted entry was not found: {entry.get('name')}")
                temp_path = matches[0]
        text_path = temp_path.with_name(temp_path.name + text_suffix)
        return temp_path, text_path

    def open_material_editor(self, entry, session):
        try:
            binary_path, text_path = self._entry_binary_editor_paths(entry, session, ".material.txt")
            source_blob = binary_path.read_bytes()
            endian = '>' if self.parser.is_big_endian else '<'
            rendered = MATERIAL_TEXT_TOOL.decode_material(
                source_blob,
                endian,
                self._bundle_entry_display_name(entry),
            )
            related_textures = self._related_texture_entries_for_material(entry)
            if related_textures:
                related_lines = ["", "# Related textures (click a name to preview)"]
                related_lines.extend(f"# texture: {item.get('name', '')}" for item in related_textures)
                rendered = rendered.rstrip("\n") + "\n" + "\n".join(related_lines) + "\n"
            text_path.write_text(rendered, encoding="utf-8", newline="\n")
        except Exception as exc:
            messagebox.showerror("Open Material", f"Failed to decode material:\n{exc}")
            return

        self.bundle_entry_edit = {
            "bundle_path": session["bundle_path"],
            "entry": dict(entry),
            "replacement_dir": session["replacement_dir"],
            "temp_path": str(binary_path),
            "text_path": str(text_path),
            "material_original": source_blob,
            "material_endian": endian,
            "material_tool": MATERIAL_TEXT_TOOL,
            "material_related_textures": [dict(item) for item in related_textures],
        }
        self._setup_bundle_entry_selector(entry)
        self.load_text_editor_file(str(text_path), ".material", from_bundle_entry=True)
        self.root.after_idle(self._tag_material_texture_links)

    def open_palette_editor(self, entry, session):
        try:
            binary_path, text_path = self._entry_binary_editor_paths(entry, session, ".palette.txt")
            source_blob = binary_path.read_bytes()
            rendered = PALETTE_TEXT_TOOL.decode_palette(
                source_blob,
                self._bundle_entry_display_name(entry),
            )
            text_path.write_text(rendered, encoding="utf-8", newline="\n")
        except Exception as exc:
            messagebox.showerror("Open Palette", f"Failed to decode type-13 palette:\n{exc}")
            return
        self.bundle_entry_edit = {
            "bundle_path": session["bundle_path"],
            "entry": dict(entry),
            "replacement_dir": session["replacement_dir"],
            "temp_path": str(binary_path),
            "text_path": str(text_path),
            "palette_original": source_blob,
        }
        self._setup_bundle_entry_selector(entry)
        self.load_text_editor_file(str(text_path), ".palette", from_bundle_entry=True)
        self.root.after_idle(self._tag_palette_color_swatches)

    def _tag_palette_color_swatches(self):
        if self.text_mode != "palette":
            return
        for tag in self.output_text.tag_names():
            if tag.startswith("palette_swatch_"):
                self.output_text.tag_delete(tag)
        text = self.output_text.get("1.0", tk.END)
        for index, match in enumerate(re.finditer(r"#[0-9A-Fa-f]{8}", text)):
            value = match.group(0)[1:]
            red, green, blue = (int(value[pos:pos + 2], 16) for pos in (0, 2, 4))
            foreground = "#000000" if (red * 299 + green * 587 + blue * 114) >= 145000 else "#ffffff"
            start = f"1.0+{match.start()}c"
            end = f"1.0+{match.end()}c"
            tag = f"palette_swatch_{index}"
            self.output_text.tag_add(tag, start, end)
            self.output_text.tag_configure(tag, background=f"#{value[:6]}", foreground=foreground)
            self.output_text.tag_raise(tag)

    @staticmethod
    def _asset_name_tokens(name):
        stem = Path(str(name).replace('\\', '/')).name.lower()
        stem = stem.removesuffix('.resource')
        return {
            token for token in re.split(r"[^a-z0-9]+", stem)
            if len(token) >= 3 and not token.isdigit() and token not in {"material", "texture", "map"}
        }

    def _related_texture_entries_for_material(self, material_entry):
        textures = self._texture_preview_entries()
        if not textures:
            return []
        material_tokens = self._asset_name_tokens(material_entry.get("name", ""))
        material_index = next(
            (index for index, item in enumerate(self.parsed_files) if item is material_entry or (
                item.get("file_num") == material_entry.get("file_num")
                and item.get("offset") == material_entry.get("offset")
            )),
            -1,
        )
        adjacent_texture_indices = set()
        if material_index >= 0:
            for index in range(material_index + 1, len(self.parsed_files)):
                item = self.parsed_files[index]
                if item.get("file_type") not in {9, 13}:
                    break
                if self._is_texture_preview_entry(item):
                    adjacent_texture_indices.add(index)
        scored = []
        for texture in textures:
            texture_tokens = self._asset_name_tokens(texture.get("name", ""))
            overlap = len(material_tokens & texture_tokens)
            texture_index = self.parsed_files.index(texture)
            follows_material = texture_index in adjacent_texture_indices
            score = (overlap * 20 if overlap >= 2 else 0) + (30 if follows_material else 0)
            if score:
                score -= min(abs(texture_index - material_index), 15)
                scored.append((score, texture_index, texture))
        scored.sort(key=lambda item: (-item[0], item[1]))
        return [item[2] for item in scored[:4]]

    def _related_material_entries_for_texture(self, texture_entry):
        identity = (texture_entry.get("file_num"), texture_entry.get("offset"))
        related = []
        for material in self.parsed_files:
            if not self._is_material_entry(material):
                continue
            candidates = self._related_texture_entries_for_material(material)
            if any((item.get("file_num"), item.get("offset")) == identity for item in candidates):
                related.append(material)
        return related

    def _tag_material_texture_links(self):
        if self.text_mode != "material" or not self.bundle_entry_edit:
            return
        related = self.bundle_entry_edit.get("material_related_textures", [])
        for index, entry in enumerate(related):
            name = str(entry.get("name", ""))
            start = self.output_text.search(name, "1.0", tk.END, exact=True)
            if not start:
                continue
            end = f"{start}+{len(name)}c"
            tag = f"material_texture_link_{index}"
            self.output_text.tag_add(tag, start, end)
            self.output_text.tag_configure(tag, foreground=self._bundle_entry_link_color(entry), underline=True)
            self.output_text.tag_bind(tag, "<Enter>", lambda _event: self.output_text.config(cursor="hand2"))
            self.output_text.tag_bind(tag, "<Leave>", lambda _event: self.output_text.config(cursor=""))
            self.output_text.tag_bind(tag, "<Button-1>", lambda _event, e=dict(entry): self._open_related_texture_from_material(e))
        self._raise_material_texture_links()
        self.root.after(250, self._raise_material_texture_links)
        self.root.after(1000, self._raise_material_texture_links)

    def _raise_material_texture_links(self):
        if self.text_mode != "material":
            return
        for tag in self.output_text.tag_names():
            if tag.startswith("material_texture_link_"):
                self.output_text.tag_raise(tag)

    def _open_related_texture_from_material(self, entry):
        if self._editor_has_unsaved_text_changes():
            choice = messagebox.askyesnocancel(
                "Unsaved Material",
                "Save the material changes before opening its texture?",
            )
            if choice is None:
                return
            if choice and not self.save_bundle_entry_edit():
                return
        self.open_texture_preview(entry)

    def _tag_texture_material_links(self, related):
        for index, entry in enumerate(related):
            name = str(entry.get("name", ""))
            start = self.output_text.search(name, "1.0", tk.END, exact=True)
            if not start:
                continue
            end = f"{start}+{len(name)}c"
            tag = f"texture_material_link_{index}"
            self.output_text.tag_add(tag, start, end)
            self.output_text.tag_configure(tag, foreground=self._bundle_entry_link_color(entry), underline=True)
            self.output_text.tag_bind(tag, "<Enter>", lambda _event: self.output_text.config(cursor="hand2"))
            self.output_text.tag_bind(tag, "<Leave>", lambda _event: self.output_text.config(cursor=""))
            self.output_text.tag_bind(tag, "<Button-1>", lambda _event, e=dict(entry): self.open_bundle_entry_editor(e))

    def _camera_path_endian(self, data):
        for endian in ('>', '<'):
            if len(data) < 64:
                continue
            count = struct.unpack_from(f"{endian}I", data, 0x28)[0]
            total_size = struct.unpack_from(f"{endian}I", data, 0x2C)[0]
            data_offset = struct.unpack_from(f"{endian}I", data, 0x30)[0]
            if total_size == len(data) and data_offset == 64 and count == (len(data) - 64) // 4:
                return endian
        raise ValueError("Type-21 header does not match a supported camera/path layout")

    def _camera_path_to_text(self, data, entry_name="CameraPath"):
        endian = self._camera_path_endian(data)
        endian_name = "big" if endian == '>' else "little"
        enabled = data[0x04]
        animated = data[0x08]
        near_clip = struct.unpack_from(f"{endian}f", data, 0x1C)[0]
        far_clip = struct.unpack_from(f"{endian}f", data, 0x20)[0]
        camera_parameter = struct.unpack_from(f"{endian}f", data, 0x24)[0]
        count = struct.unpack_from(f"{endian}I", data, 0x28)[0]
        track_id = struct.unpack_from(f"{endian}H", data, 0x34)[0]
        lines = [
            "# Pipeworks type-21 intro-camera field-of-view track",
            f"# Entry={entry_name}",
            f"# Endian={endian_name}",
            "# FieldOfView values are stored in radians; degree comments are provided for readability.",
            "# To extend the track, duplicate the last frame and increment its Frame index.",
            "# Frame offsets, FrameCount, TotalSize, and degree comments are regenerated when saved.",
            "",
            "camera_fov_track",
            "{",
            "    camera_settings",
            "    {",
            f"        @0x0004 u8 Enabled = {enabled};",
            f"        @0x0008 u8 Animated = {animated};",
            f"        @0x001C float NearClipDistance = {near_clip!r};",
            f"        @0x0020 float FarClipDistance = {far_clip!r};",
            f"        @0x0024 float UnknownCameraParameter = {camera_parameter!r};",
            f"        @0x0034 u16 TrackId = {track_id};",
            "",
            f"        @0x0028 u32 FrameCount = {count};  # structural",
            f"        @0x002C u32 TotalSize = {len(data)};  # structural",
            "        @0x0030 u32 FrameDataOffset = 64;  # structural",
            "",
            f"        # Unknown/reserved header bytes: {data[0:4].hex(' ')} | "
            f"{data[5:8].hex(' ')} | {data[9:0x1C].hex(' ')} | {data[0x36:0x40].hex(' ')}",
            "    }",
            "",
            "    frames",
            "    {",
        ]
        for index in range(count):
            offset = 64 + index * 4
            value = struct.unpack_from(f"{endian}f", data, offset)[0]
            degrees = math.degrees(value)
            lines.append(
                f"        @0x{offset:04X} float Frame[{index:03d}].FieldOfView = {value!r};"
                f"  # {degrees:.3f} degrees"
            )
        lines.extend(("    }", "}"))
        return "\n".join(lines) + "\n"

    def _camera_path_from_text(self, text, original_data):
        endian = self._camera_path_endian(original_data)
        output = bytearray(original_data[:64])
        row_re = re.compile(
            r"^\s*@0x([0-9A-Fa-f]+)\s+(u8|u16|u32|float)\s+[^=]+?\s*=\s*([^;#]+)",
            re.MULTILINE,
        )
        seen = set()
        for match in row_re.finditer(text):
            offset = int(match.group(1), 16)
            value_type = match.group(2)
            if offset >= 64:
                continue
            if offset in seen:
                raise ValueError(f"Duplicate camera/path offset 0x{offset:04X}")
            seen.add(offset)
            value_size = {"u8": 1, "u16": 2, "u32": 4, "float": 4}[value_type]
            if offset < 0 or offset + value_size > len(output):
                raise ValueError(f"Invalid camera/path offset 0x{offset:X}")
            if offset in {0x28, 0x2C, 0x30}:
                continue
            if offset in {0x04, 0x08}:
                expected_type = "u8"
            elif offset == 0x34:
                expected_type = "u16"
            elif offset in {0x1C, 0x20, 0x24} or offset >= 64:
                expected_type = "float"
            else:
                expected_type = "u32"
            if value_type != expected_type:
                raise ValueError(
                    f"Field at 0x{offset:04X} must remain {expected_type}, not {value_type}"
                )
            if value_type == "float":
                struct.pack_into(f"{endian}f", output, offset, float(match.group(3).strip()))
            elif value_type == "u8":
                struct.pack_into("B", output, offset, int(match.group(3).strip(), 0) & 0xFF)
            elif value_type == "u16":
                struct.pack_into(f"{endian}H", output, offset, int(match.group(3).strip(), 0) & 0xFFFF)
            else:
                struct.pack_into(f"{endian}I", output, offset, int(match.group(3).strip(), 0) & 0xFFFFFFFF)

        frame_re = re.compile(
            r"^\s*@0x[0-9A-Fa-f]+\s+float\s+Frame\[(\d+)\]\.FieldOfView\s*=\s*([^;#]+)",
            re.MULTILINE,
        )
        frames = {}
        for match in frame_re.finditer(text):
            index = int(match.group(1), 10)
            if index in frames:
                raise ValueError(f"Frame[{index:03d}] is declared more than once")
            frames[index] = float(match.group(2).strip())
        if not frames:
            raise ValueError("The camera FOV track must contain at least one frame")
        expected = list(range(max(frames) + 1))
        missing = [index for index in expected if index not in frames]
        if missing:
            preview = ", ".join(f"Frame[{index:03d}]" for index in missing[:8])
            raise ValueError(f"Camera frame indexes must be continuous; missing {preview}")
        for index in expected:
            output.extend(struct.pack(f"{endian}f", frames[index]))
        struct.pack_into(f"{endian}I", output, 0x28, len(frames))
        struct.pack_into(f"{endian}I", output, 0x2C, len(output))
        struct.pack_into(f"{endian}I", output, 0x30, 64)
        self._camera_path_endian(output)
        return bytes(output)

    def open_camera_path_editor(self, entry, session):
        try:
            temp_path, text_path = self._entry_binary_editor_paths(entry, session, ".camera_path.txt")
            data = temp_path.read_bytes()
            text_path.write_text(self._camera_path_to_text(data, entry.get("name", "CameraPath")), encoding="utf-8", newline="\n")
        except Exception as exc:
            messagebox.showerror("Camera/Path", f"Failed to decode camera/path entry:\n{exc}")
            return
        self.bundle_entry_edit = {
            "bundle_path": session["bundle_path"],
            "entry": dict(entry),
            "replacement_dir": session["replacement_dir"],
            "temp_path": str(temp_path),
            "text_path": str(text_path),
            "camera_path_original": data,
        }
        self._setup_bundle_entry_selector(entry)
        self.load_text_editor_file(str(text_path), ".camera_path", from_bundle_entry=True)

    def _read_fixed_ascii(self, data, offset, size):
        return data[offset:offset + size].split(b"\0", 1)[0].decode("latin-1", errors="replace")

    def _fdf_layout_guess(self, data, big_endian):
        del big_endian
        terminator = data.find(b"\0", 0x358)
        if terminator < 0:
            terminator = 0x358
        first_possible = (terminator + 4) & ~3
        candidates = []
        for stride in (36, 52):
            for start in range(first_possible, min(len(data), first_possible + 0x24), 4):
                remaining = len(data) - start
                if remaining <= 0 or remaining % stride:
                    continue
                count = remaining // stride
                if not (1 <= count <= 512):
                    continue
                padding_penalty = sum(byte != 0 for byte in data[terminator + 1:start])
                candidates.append((padding_penalty * 8 + start - first_possible, start, stride, count))
        return min(candidates, default=(0, len(data), 0, 0))[1:]

    def _fdf_to_text(self, data, entry_name="Font", big_endian=False):
        record_start, record_stride, record_count = self._fdf_layout_guess(data, big_endian)
        character_region = data[0x358:].split(b"\0", 1)[0]
        characters = character_region.decode("latin-1", errors="replace")
        lines = [
            "# Pipeworks FDF font viewer (read-only)",
            f"# Entry={entry_name}",
            "",
            "font",
            "{",
            f"    InternalName = {self._read_fixed_ascii(data, 0x000, 0x100)!r};",
            f"    AtlasFile = {self._read_fixed_ascii(data, 0x100, 0x100)!r};",
            f"    FontRecipe = {self._read_fixed_ascii(data, 0x200, 0x100)!r};",
            f"    Characters = {characters!r};",
            f"    GlyphRecordOffset = 0x{record_start:04X};",
            f"    GlyphRecordSize = {record_stride};",
            f"    GlyphRecordCount = {record_count};",
            "",
            "    glyph_records",
            "    {",
        ]
        # FDF glyph records use little-endian fields on both Wii and PS2.
        endian = '<'
        for index in range(record_count):
            offset = record_start + index * record_stride
            if record_stride == 36:
                u_left, u_right, v_top, v_bottom, scale, width, x_offset, height, codepoint = struct.unpack_from(
                    f"{endian}8fI", data, offset
                )
                character = chr(codepoint) if 0 <= codepoint <= 0x10FFFF else "?"
                lines.extend((
                    f"        glyph {character!r}  # U+{codepoint:04X}, record @0x{offset:04X}",
                    "        {",
                    f"            UV = ({u_left:.9g}, {v_top:.9g}) to ({u_right:.9g}, {v_bottom:.9g});",
                    f"            PixelSize = ({width:.9g}, {height:.9g});",
                    f"            Scale = {scale:.9g};",
                    f"            XOffset = {x_offset:.9g};",
                    "        }",
                ))
            else:
                words = [struct.unpack_from(f"{endian}I", data, pos)[0] for pos in range(offset, offset + record_stride, 4)]
                character = characters[index] if index < len(characters) else "?"
                word_text = ", ".join(f"0x{word:08X}" for word in words)
                lines.append(f"        [{index:03d}] {character!r} @0x{offset:04X} = {word_text};")
        lines.extend(("    }", "}"))
        return "\n".join(lines) + "\n"

    def open_fdf_viewer(self, entry, session):
        if not HAS_FDF_TEXT_TOOL:
            messagebox.showerror("FDF Font", "The editable FDF codec could not be loaded.")
            return
        try:
            temp_path, text_path = self._entry_binary_editor_paths(entry, session, ".fdf.txt")
            data = temp_path.read_bytes()
            text_path.write_text(
                FDF_TEXT_TOOL.decode_fdf(data, entry.get("name", "Font")),
                encoding="utf-8",
                newline="\n",
            )
        except Exception as exc:
            messagebox.showerror("FDF Font", f"Failed to decode FDF entry:\n{exc}")
            return
        self.bundle_entry_edit = {
            "bundle_path": session["bundle_path"],
            "entry": dict(entry),
            "replacement_dir": session["replacement_dir"],
            "temp_path": str(temp_path),
            "text_path": str(text_path),
            "fdf_original": data,
        }
        self._setup_bundle_entry_selector(entry)
        self.load_text_editor_file(str(text_path), ".fdf", from_bundle_entry=True)

    def _character_data_text_name(self, data_label=None):
        label = data_label
        if label is None and self.bundle_entry_edit:
            label = self.bundle_entry_edit.get("character_data_label")
        if self.parser and hasattr(self.parser, 'filepath'):
            if label and "leveldata" in str(label).lower():
                return f"{Path(self.parser.filepath).stem}_LevelData.txt"
            return f"{Path(self.parser.filepath).stem}_Data.txt"
        if label and "leveldata" in str(label).lower():
            return "LevelData.txt"
        return "Character_Data.txt"

    def _character_data_text_path(self, session, data_label=None):
        return Path(session["replacement_dir"]) / self._character_data_text_name(data_label)

    def _skeleton_type3_label_for_entry(self, entry):
        name = Path(str(entry.get("name", "Skeleton")).replace("\\", "/")).name
        return name or "Skeleton"

    def _skeleton_type3_text_name(self, entry):
        label = self._skeleton_type3_label_for_entry(entry)
        try:
            if int(entry.get("file_type", -1)) == 4:
                return f"{label}_Skeleton4.txt"
        except Exception:
            pass
        return f"{label}_Skeleton.txt"

    def _skeleton_type3_text_path(self, session, entry):
        return Path(session["replacement_dir"]) / self._skeleton_type3_text_name(entry)

    def _cancel_character_data_decode(self):
        self.character_data_decode_generation += 1

    def open_character_data_editor(self, entry, session):
        data_tool = self._character_data_tool_for_entry(entry)
        data_label = self._character_data_label_for_entry(entry)
        if data_tool is None:
            if data_label == "000MONSTER_DATA":
                tool_key = "monster_data"
            elif str(data_label).lower().startswith("monster_data"):
                tool_key = "cmg_data"
            else:
                tool_key = "character_data"
            details = "\n".join(TOOL_LOAD_ERRORS.get(tool_key, []))
            message = f"{data_label} decoder is missing."
            if details:
                message += f"\n\nLoad errors:\n{details}"
            else:
                message += "\n\nMake sure the PyInstaller build includes the Data Tools folder."
            messagebox.showerror(f"Open {data_label}", message)
            return

        self._cancel_character_data_decode()
        decode_generation = self.character_data_decode_generation
        text_path = self._character_data_text_path(session, data_label)
        binary_path = self._entry_temp_path(session, entry)
        bundle_path = Path(session["bundle_path"])
        replacement_dir = session["replacement_dir"]
        entry_copy = dict(entry)
        parser = self.parser
        is_level_data = self._is_level_data_entry(entry)
        self._setup_bundle_entry_selector(entry)
        self._begin_busy_progress(f"{data_label}:")
        self.extract_btn.config(state=tk.DISABLED)
        self.rebuild_btn.config(state=tk.DISABLED)

        def decode_worker():
            error = None
            try:
                text_path.parent.mkdir(parents=True, exist_ok=True)
                if is_level_data:
                    data_tool.export_txt(bundle_path, text_path, str(entry_copy.get("name", "")))
                else:
                    data_tool.export_txt(bundle_path, text_path)
                binary_path.parent.mkdir(parents=True, exist_ok=True)
                binary_path.write_bytes(parser.read_bytes(entry_copy["offset"], entry_copy["size"]))
            except Exception as exc:
                error = exc

            def finish_decode():
                if decode_generation != self.character_data_decode_generation:
                    return
                self._end_syntax_progress()
                self.extract_btn.config(state=tk.NORMAL)
                self.rebuild_btn.config(state=tk.NORMAL)
                if error is not None:
                    messagebox.showerror(f"Open {data_label}", f"Failed to decode {data_label}:\n{error}")
                    return
                self.bundle_entry_edit = {
                    "bundle_path": str(bundle_path),
                    "entry": entry_copy,
                    "replacement_dir": replacement_dir,
                    "temp_path": str(binary_path),
                    "text_path": str(text_path),
                    "character_data": True,
                    "character_data_label": data_label,
                    "character_data_tool": data_tool,
                }
                editor_ext = ".level_data" if is_level_data else ".char_data"
                self.load_text_editor_file(str(text_path), editor_ext, from_bundle_entry=True)
                self._setup_bundle_entry_selector(entry_copy)

            self.root.after(0, finish_decode)

        threading.Thread(target=decode_worker, daemon=True).start()

    def open_skeleton_type3_editor(self, entry, session):
        if not HAS_SKELETON_TYPE3_TOOL:
            messagebox.showerror("Open Skeleton", "CMP skeleton decoder is missing.")
            return

        self._cancel_character_data_decode()
        decode_generation = self.character_data_decode_generation
        skeleton_label = self._skeleton_type3_label_for_entry(entry)
        text_path = self._skeleton_type3_text_path(session, entry)
        binary_path = self._entry_temp_path(session, entry)
        bundle_path = Path(session["bundle_path"])
        replacement_dir = session["replacement_dir"]
        entry_copy = dict(entry)
        parser = self.parser
        skeleton_endian = "big" if getattr(parser, "is_big_endian", False) else "little"
        self._setup_bundle_entry_selector(entry)
        self._begin_busy_progress(f"{skeleton_label}:")
        self.extract_btn.config(state=tk.DISABLED)
        self.rebuild_btn.config(state=tk.DISABLED)

        def decode_worker():
            error = None
            try:
                text_path.parent.mkdir(parents=True, exist_ok=True)
                SKELETON_TYPE3_TOOL.export_txt(bundle_path, text_path, str(entry_copy.get("name", "")))
                binary_path.parent.mkdir(parents=True, exist_ok=True)
                binary_path.write_bytes(parser.read_bytes(entry_copy["offset"], entry_copy["size"]))
            except Exception as exc:
                error = exc

            def finish_decode():
                if decode_generation != self.character_data_decode_generation:
                    return
                self._end_syntax_progress()
                self.extract_btn.config(state=tk.NORMAL)
                self.rebuild_btn.config(state=tk.NORMAL)
                if error is not None:
                    messagebox.showerror("Open Skeleton", f"Failed to decode {skeleton_label}:\n{error}")
                    return
                self.bundle_entry_edit = {
                    "bundle_path": str(bundle_path),
                    "entry": entry_copy,
                    "replacement_dir": replacement_dir,
                    "temp_path": str(binary_path),
                    "text_path": str(text_path),
                    "skeleton_type3": True,
                    "skeleton_type3_label": skeleton_label,
                    "skeleton_type3_tool": SKELETON_TYPE3_TOOL,
                    "skeleton_endian": skeleton_endian,
                }
                self.load_text_editor_file(str(text_path), ".skeleton_type3", from_bundle_entry=True)
                self._setup_bundle_entry_selector(entry_copy)

            self.root.after(0, finish_decode)

        threading.Thread(target=decode_worker, daemon=True).start()

    def save_bundle_entry_edit(self, selected_names=None):
        if not self.bundle_entry_edit:
            return False
        if not self.parser or not self.parsed_files:
            messagebox.showerror("Save Entry", "Original bundle is no longer loaded.")
            return False

        output_path = self.bundle_entry_edit["bundle_path"]
        temp_output = str(get_temp_dir() / f"{Path(output_path).name}.rebuild_tmp")

        replacement_dir = self.bundle_entry_edit["replacement_dir"]
        excluded_files = []
        excluded_dir = None
        if selected_names is not None:
            selected = set(selected_names)
            excluded_dir = Path(tempfile.mkdtemp(prefix="gzbuildr_excluded_", dir=get_temp_dir()))
            for name in self._changed_bundle_entry_names():
                if name in selected:
                    continue
                source = Path(replacement_dir) / name
                if not source.exists():
                    continue
                held = excluded_dir / name
                held.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(source), str(held))
                excluded_files.append((held, source))
        self.parser._extra_string_values = list(getattr(self, "_pending_prx_string_values", []) or [])
        try:
            if self.parser.bundle_type == 'vol':
                success = self.parser.rebuild_vol(temp_output, self.parsed_files, replacement_dir)
            else:
                success = self.parser.rebuild_bdg(temp_output, self.parsed_files, replacement_dir)
        finally:
            for held, source in excluded_files:
                source.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(held), str(source))
            if excluded_dir is not None:
                shutil.rmtree(excluded_dir, ignore_errors=True)
        self.parser._extra_string_values = []
        self._pending_prx_string_values = []

        if success:
            backup = self.create_incremental_backup(output_path)
            os.replace(temp_output, output_path)
            zip_source = self._current_zip_source
            zip_backup = None
            final_path = output_path
            if zip_source and os.path.exists(zip_source):
                member_name = Path(output_path).name
                output_resolved = Path(output_path).resolve()
                for temp_dir in self._zip_temp_dirs:
                    try:
                        member_name = output_resolved.relative_to(Path(temp_dir).resolve()).as_posix()
                        break
                    except Exception:
                        continue
                temp_zip = str(get_temp_dir() / f"{Path(zip_source).name}.entry_save_tmp")
                zip_backup = self.create_incremental_backup(zip_source)
                replaced_member = False
                with zipfile.ZipFile(zip_source, 'r') as src_zip, zipfile.ZipFile(temp_zip, 'w', zipfile.ZIP_DEFLATED) as dst_zip:
                    for info in src_zip.infolist():
                        if info.filename.rstrip('/') == member_name.rstrip('/'):
                            dst_zip.write(output_path, info.filename)
                            replaced_member = True
                        else:
                            dst_zip.writestr(info, src_zip.read(info.filename))
                    if not replaced_member:
                        dst_zip.write(output_path, member_name)
                os.replace(temp_zip, zip_source)
                final_path = zip_source
            self.parser = PipeworksParser(output_path)
            self.parsed_files = self.parser.parse()
            backup_text = f"\nBackup: {backup}" if backup else ""
            if zip_backup:
                backup_text += f"\nZIP Backup: {zip_backup}"
            messagebox.showinfo("Saved", f"Bundle saved successfully:\n{final_path}{backup_text}")
            return True
        else:
            try:
                if os.path.exists(temp_output):
                    os.remove(temp_output)
            except Exception:
                pass
            messagebox.showerror("Save Entry", "Failed to rebuild bundle with edited entry.")
        return success

    def _read_strings_from_bdg(self, bdg_path):
        parser = PipeworksParser(str(bdg_path))
        entries = parser.parse()
        if not entries or "error" in entries[0]:
            return None, None
        return PRX_VALUE_EDITOR.read_strings(bytes(parser.file_data), parser.string_offset), entries

    def _find_prx_string_table(self, filepath):
        if not HAS_PRX_TOOLS:
            return None, None

        path = Path(filepath).resolve()
        stored_name = path.name
        if path.parent.name.isdigit():
            stored_name = f"{path.parent.name}/{path.name}"

        candidate_dirs = []
        for parent in path.parents:
            candidate_dirs.append(parent)
        if self.current_bundle_dir:
            candidate_dirs.append(Path(self.current_bundle_dir))
        candidate_dirs.append(Path.cwd())

        candidate_files = []
        seen = set()
        if self.parser and hasattr(self.parser, 'filepath') and str(self.parser.filepath).lower().endswith('.bdg'):
            candidate = Path(self.parser.filepath)
            if candidate.exists():
                seen.add(str(candidate).lower())
                candidate_files.append(candidate)
        for folder in candidate_dirs:
            for candidate in (
                folder / f"{folder.name}.bdg",
                folder / f"{folder.name}.BDG",
                Path.cwd() / f"{folder.name}.bdg",
                Path.cwd() / f"{folder.name}.BDG",
            ):
                key = str(candidate).lower()
                if key not in seen and candidate.exists():
                    seen.add(key)
                    candidate_files.append(candidate)
            try:
                for candidate in folder.glob("*.bdg"):
                    key = str(candidate).lower()
                    if key not in seen:
                        seen.add(key)
                        candidate_files.append(candidate)
                for candidate in folder.glob("*.BDG"):
                    key = str(candidate).lower()
                    if key not in seen:
                        seen.add(key)
                        candidate_files.append(candidate)
            except OSError:
                pass

        for candidate in candidate_files:
            try:
                strings, entries = self._read_strings_from_bdg(candidate)
            except Exception:
                continue
            if not strings or not entries:
                continue
            for entry in entries:
                name = str(entry.get("name", ""))
                if name.lower() == stored_name.lower() or name.lower().endswith("/" + path.name.lower()) or name.lower() == path.name.lower():
                    return strings, str(candidate)

        return None, None

    def _decode_prx_file(self, filepath):
        if not HAS_PRX_TOOLS:
            return "PRX tools are missing. Expected PRX_Tools/prx_value_editor.py.\n"

        data = Path(filepath).read_bytes()
        strings, source_bdg = self._find_prx_string_table(filepath)
        warning = ""
        if strings is None:
            strings = [f"string_{i}" for i in range(65536)]
            warning = (
                "# Warning: No matching BDG string table was found for this PRX.\n"
                "# Names and string values are shown as string_ID placeholders.\n\n"
            )

        prx_entry = {
            "name": Path(filepath).name,
            "offset": 0,
            "size": len(data),
        }
        _prx, rows, roots = PRX_VALUE_EDITOR.parse_rows(bytearray(data), prx_entry, strings)

        lines = [
            "# PRX text export",
            f"# SourcePRX={filepath}",
            f"# SourceBDG={source_bdg or ''}",
            f"# PRX={Path(filepath).name}",
            "# Edit values inside property_set blocks, then Save or Convert back to PRX.",
            "# Shared values are detached automatically when only one property is changed.",
            "",
        ]
        if warning:
            lines.insert(0, warning.rstrip())
        lines.extend(PRX_VALUE_EDITOR.prx_root_toc_lines(roots, rows))
        lines.extend(PRX_VALUE_EDITOR.prx_rows_text_lines(rows, strings))
        lines.append("")
        lines.append(f"# Total rows: {len(PRX_VALUE_EDITOR.display_rows_by_offset(rows))}")
        return "\n".join(lines) + "\n"

    def _metadata_from_editor_text(self):
        meta = {}
        for line in self._current_editor_text().splitlines():
            if not line.startswith("#"):
                continue
            body = line[1:].strip()
            if "=" in body:
                key, value = body.split("=", 1)
                meta[key.strip()] = value.strip()
        return meta

    def _get_prx_base_path_for_text(self):
        if self.text_mode == 'prx' and self.text_source_path:
            return self.text_source_path

        meta = self._metadata_from_editor_text()
        source = meta.get("SourcePRX")
        if source and os.path.isfile(source):
            return source

        selected = _dialog(
            self.root,
            filedialog.askopenfilename,
            title="Select Original PRX Base",
            initialdir=os.path.dirname(self.text_source_path) if self.text_source_path else os.path.expanduser("~"),
            filetypes=[("PRX Files", "*.prx"), ("All Files", "*.*")],
        )
        return selected or None

    def _prx_string_value_id(self, value, strings, new_strings=None):
        if value in strings:
            return strings.index(value)
        if value.startswith("string_") and value[7:].isdigit():
            return int(value[7:])
        if new_strings is None:
            return int(value, 0)
        if value not in new_strings:
            new_strings.append(value)
        return len(strings) + new_strings.index(value)

    def _parse_prx_value(self, row, value_text, strings, new_strings=None):
        value = value_text.strip()
        if row.type_id == PRX_VALUE_EDITOR.TYPE_FLOAT:
            return struct.unpack(">I", struct.pack(">f", float(value)))[0]
        if row.type_id in (PRX_VALUE_EDITOR.TYPE_INT, PRX_VALUE_EDITOR.TYPE_INT_ALT, PRX_VALUE_EDITOR.TYPE_FLOAT_ALT):
            return int(value, 0)
        if row.type_id == PRX_VALUE_EDITOR.TYPE_STRING:
            return self._prx_string_value_id(value, strings, new_strings)
        raise ValueError(f"Refusing to import non-editable PRX row type {row.type_name}")

    def _strip_prx_inline_comment(self, value_text):
        return re.split(r"\s+#", value_text, 1)[0].strip()

    def _prx_type_id_for_name(self, type_name):
        if type_name == "float":
            return PRX_VALUE_EDITOR.TYPE_FLOAT
        if type_name == "int":
            return PRX_VALUE_EDITOR.TYPE_INT_ALT
        if type_name == "string":
            return PRX_VALUE_EDITOR.TYPE_STRING
        raise ValueError(f"Unsupported PRX row type {type_name}")

    def _parse_new_prx_value(self, type_id, value_text, strings, new_strings=None):
        value = value_text.strip()
        if type_id == PRX_VALUE_EDITOR.TYPE_FLOAT:
            return struct.unpack(">I", struct.pack(">f", float(value)))[0]
        if type_id in (PRX_VALUE_EDITOR.TYPE_INT, PRX_VALUE_EDITOR.TYPE_INT_ALT, PRX_VALUE_EDITOR.TYPE_FLOAT_ALT):
            return int(value, 0)
        if type_id == PRX_VALUE_EDITOR.TYPE_STRING:
            return self._prx_string_value_id(value, strings, new_strings)
        raise ValueError(f"Unsupported PRX row type 0x{type_id:08X}")

    def _add_named_prx_rows(self, prx, rows, strings, additions):
        if not additions:
            return prx

        def table_rows_for(group):
            return [row for row in rows if row.group.lower() == group.lower()]

        def shifted(off, insert_at, delta):
            return off + delta if off >= insert_at else off

        additions_by_group = {}
        group_order = []
        for addition in additions:
            group_key = addition["group"].lower()
            if group_key not in additions_by_group:
                additions_by_group[group_key] = []
                group_order.append(group_key)
            additions_by_group[group_key].append(addition)

        for group_key in group_order:
            group_additions = additions_by_group[group_key]
            group = group_additions[0]["group"]
            group_rows = table_rows_for(group)
            if not group_rows:
                raise ValueError(f"{group} does not exist in this PRX; adding new groups is not supported")
            table_offsets = {row.table_offset for row in group_rows}
            if len(table_offsets) != 1:
                raise ValueError(f"{group} maps to multiple PRX tables; add this row with a more specific dump")
            for addition in group_additions:
                if addition["name"] not in strings:
                    raise ValueError(f"{addition['name']} is not in this bundle's string table; adding new strings is not supported")

            table_offset = next(iter(table_offsets))
            count = PRX_VALUE_EDITOR.table_count_at(prx, table_offset)
            if count is None:
                raise ValueError(f"{group} is not a writable PRX table")

            add_count = len(group_additions)
            pointer_end = table_offset + 8 + count * 4
            first_row_after_pointers = min(
                (row.row_offset for row in group_rows if row.row_offset >= pointer_end),
                default=pointer_end,
            )
            reusable_pointer_gap = max(0, first_row_after_pointers - pointer_end)
            pointer_bytes_needed = 4 * add_count

            # Most tables reserve one or more unused pointer slots before the
            # first row. Use that space and append the new row records so no
            # existing table, row, or relative reference has to move.
            if reusable_pointer_gap >= pointer_bytes_needed:
                row_insert_at = len(prx) - 4 if prx.endswith(b"\xAF\xAF\xAF\xAF") else len(prx)
                trailing_bytes = bytes(prx[row_insert_at:])
                del prx[row_insert_at:]
                new_count = count + add_count
                PRX_VALUE_EDITOR.put_u32(prx, table_offset + 4, (new_count << 16) | new_count)
                for index, addition in enumerate(group_additions):
                    new_row_off = len(prx)
                    name_id = strings.index(addition["name"])
                    pointer_offset = table_offset + 8 + (count + index) * 4
                    PRX_VALUE_EDITOR.put_u32(prx, pointer_offset, new_row_off - table_offset + 4)
                    prx.extend(b"\x00" * 12)
                    PRX_VALUE_EDITOR.put_u32(prx, new_row_off, addition["type_id"])
                    PRX_VALUE_EDITOR.put_u32(prx, new_row_off + 4, addition["value_raw"])
                    PRX_VALUE_EDITOR.put_u32(prx, new_row_off + 8, name_id)
                prx.extend(trailing_bytes)
                prx_entry = {"name": "edited.prx", "offset": 0, "size": len(prx)}
                _parsed_prx, rows, _roots = PRX_VALUE_EDITOR.parse_rows(prx, prx_entry, strings)
                continue

            reusable_pointer_bytes = min(reusable_pointer_gap, pointer_bytes_needed)
            insert_at = pointer_end + reusable_pointer_bytes
            delta = pointer_bytes_needed + (12 * add_count) - reusable_pointer_bytes

            old_prx = prx
            prx = bytearray(old_prx[:insert_at])
            prx.extend(b"\xAF" * delta)
            prx.extend(old_prx[insert_at:])

            old_rows = rows
            old_table_offsets = sorted({row.table_offset for row in old_rows})
            for old_table in old_table_offsets:
                old_count = PRX_VALUE_EDITOR.table_count_at(old_prx, old_table)
                if old_count is None:
                    continue
                new_table = shifted(old_table, insert_at, delta)
                for index in range(old_count):
                    rel = PRX_VALUE_EDITOR.signed32(PRX_VALUE_EDITOR.u32(old_prx, old_table + 8 + index * 4))
                    old_row_off = old_table + rel - 4
                    new_row_off = shifted(old_row_off, insert_at, delta)
                    PRX_VALUE_EDITOR.put_u32(prx, new_table + 8 + index * 4, new_row_off - new_table + 4)

            ref_rows = {
                row.row_offset: row.value_raw
                for row in old_rows
                if PRX_VALUE_EDITOR.is_ref_type(row.type_id)
            }
            # Root descriptors precede the first property table and are not
            # returned as normal rows. They still carry relative table
            # pointers and must move whenever an insertion shifts a table.
            first_table = min(old_table_offsets, default=len(old_prx))
            old_table_offset_set = set(old_table_offsets)
            for row_offset in range(0, max(0, first_table - 11), 4):
                if not PRX_VALUE_EDITOR.is_ref_type(PRX_VALUE_EDITOR.u32(old_prx, row_offset)):
                    continue
                value_raw = PRX_VALUE_EDITOR.u32(old_prx, row_offset + 4)
                target = row_offset + PRX_VALUE_EDITOR.signed32(value_raw)
                if target not in old_table_offset_set and target + 4 not in old_table_offset_set:
                    continue
                ref_rows[row_offset] = value_raw

            for old_row_offset, value_raw in ref_rows.items():
                old_target = old_row_offset + PRX_VALUE_EDITOR.signed32(value_raw)
                if (
                    PRX_VALUE_EDITOR.table_count_at(old_prx, old_target) is None
                    and PRX_VALUE_EDITOR.table_count_at(old_prx, old_target + 4) is not None
                ):
                    old_target += 4
                new_row_off = shifted(old_row_offset, insert_at, delta)
                new_target = shifted(old_target, insert_at, delta)
                PRX_VALUE_EDITOR.put_u32(prx, new_row_off + 4, new_target - new_row_off)

            new_table = shifted(table_offset, insert_at, delta)
            new_count = count + add_count
            PRX_VALUE_EDITOR.put_u32(prx, new_table + 4, (new_count << 16) | new_count)
            first_new_row_off = new_table + 8 + new_count * 4
            for index, addition in enumerate(group_additions):
                new_row_off = first_new_row_off + index * 12
                name_id = strings.index(addition["name"])
                PRX_VALUE_EDITOR.put_u32(prx, new_table + 8 + (count + index) * 4, new_row_off - new_table + 4)
                PRX_VALUE_EDITOR.put_u32(prx, new_row_off, addition["type_id"])
                PRX_VALUE_EDITOR.put_u32(prx, new_row_off + 4, addition["value_raw"])
                PRX_VALUE_EDITOR.put_u32(prx, new_row_off + 8, name_id)

            prx_entry = {"name": "edited.prx", "offset": 0, "size": len(prx)}
            _parsed_prx, rows, _roots = PRX_VALUE_EDITOR.parse_rows(prx, prx_entry, strings)

        return prx

    def _apply_prx_occurrence_edits(self, prx, rows, wanted_by_slot):
        """Apply logical property edits, cloning shared physical rows as needed."""
        if not wanted_by_slot:
            return prx

        rows_by_slot = {row.pointer_offset: row for row in rows}
        slots_by_row = {}
        for row in rows:
            slots_by_row.setdefault(row.row_offset, set()).add(row.pointer_offset)

        edits_by_row = {}
        for pointer_offset, new_raw in wanted_by_slot.items():
            row = rows_by_slot[pointer_offset]
            if new_raw == row.value_raw:
                continue
            edits_by_row.setdefault(row.row_offset, []).append((row, new_raw))

        for row_offset, edits in sorted(edits_by_row.items()):
            all_slots = slots_by_row.get(row_offset, set())
            edited_slots = {row.pointer_offset for row, _new_raw in edits}
            edited_values = {new_raw for _row, new_raw in edits}

            if edited_slots == all_slots and len(edited_values) == 1:
                PRX_VALUE_EDITOR.put_u32(prx, row_offset + 4, next(iter(edited_values)))
                continue

            edits_by_value = {}
            for row, new_raw in edits:
                edits_by_value.setdefault(new_raw, []).append(row)

            for new_raw, value_rows in edits_by_value.items():
                insert_at = len(prx) - 4 if prx.endswith(b"\xAF\xAF\xAF\xAF") else len(prx)
                clone = bytearray(prx[row_offset : row_offset + 12])
                PRX_VALUE_EDITOR.put_u32(clone, 4, new_raw)
                prx[insert_at:insert_at] = clone
                for row in value_rows:
                    relative = insert_at - row.table_offset + 4
                    PRX_VALUE_EDITOR.put_u32(prx, row.pointer_offset, relative)

        return prx

    def _resolve_prx_shared_line_conflicts(self, shared_conflicts):
        if not shared_conflicts:
            return {}

        window = tk.Toplevel(self.root)
        set_window_icon(window)
        window.title("Resolve Shared PRX Lines")
        window.transient(self.root)
        window.resizable(True, True)
        window.grab_set()

        result = {"value": None}
        frame = ttk.Frame(window, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            frame,
            text="Some exported lines point to the same PRX value. Choose one Change per shared value, or Ignore to keep original.",
            wraplength=760,
        ).pack(anchor=tk.W, pady=(0, 8))

        list_outer = ttk.Frame(frame)
        list_outer.pack(fill=tk.BOTH, expand=True)
        list_outer.columnconfigure(0, weight=1)
        list_outer.rowconfigure(0, weight=1)
        list_canvas = tk.Canvas(list_outer, bg=APP_BG, highlightthickness=0)
        list_scroll = ttk.Scrollbar(list_outer, orient=tk.VERTICAL, command=list_canvas.yview)
        list_canvas.configure(yscrollcommand=list_scroll.set)
        list_canvas.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        list_scroll.grid(row=0, column=1, sticky=(tk.N, tk.S))
        list_frame = ttk.Frame(list_canvas)
        list_window = list_canvas.create_window((0, 0), window=list_frame, anchor=tk.NW)
        list_frame.columnconfigure(1, weight=1)

        def configure_list_scroll(_event=None):
            list_canvas.configure(scrollregion=list_canvas.bbox("all"))
            list_canvas.itemconfigure(list_window, width=list_canvas.winfo_width())

        list_frame.bind("<Configure>", configure_list_scroll)
        list_canvas.bind("<Configure>", configure_list_scroll)

        ttk.Label(list_frame, text="Line").grid(row=0, column=0, sticky=tk.W, padx=(0, 8), pady=(0, 4))
        ttk.Label(list_frame, text="Tooltip").grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 8), pady=(0, 4))
        ttk.Label(list_frame, text="Action").grid(row=0, column=2, sticky=tk.W, pady=(0, 4))

        choices = []
        row_index = 1
        for row_off, items in sorted(shared_conflicts.items()):
            ttk.Label(
                list_frame,
                text=f"@0x{row_off:04X}",
                font=("TkDefaultFont", 8, "bold"),
            ).grid(row=row_index, column=0, columnspan=3, sticky=tk.W, pady=(8, 2))
            row_index += 1
            for item in items:
                var = tk.StringVar(value="Ignore")
                ttk.Label(list_frame, text=str(item["line"])).grid(row=row_index, column=0, sticky=tk.W, padx=(0, 8), pady=1)
                ttk.Label(list_frame, text=item["tooltip"], wraplength=620).grid(row=row_index, column=1, sticky=(tk.W, tk.E), padx=(0, 8), pady=1)
                ttk.Combobox(
                    list_frame,
                    textvariable=var,
                    values=("Ignore", "Change"),
                    state="readonly",
                    width=9,
                ).grid(row=row_index, column=2, sticky=tk.W, pady=1)
                choices.append((row_off, item, var))
                row_index += 1

        button_row = ttk.Frame(frame)
        button_row.pack(fill=tk.X, pady=(10, 0))

        def apply_choices():
            selected_by_off = {}
            for row_off, item, var in choices:
                if var.get() != "Change":
                    continue
                previous = selected_by_off.get(row_off)
                if previous is not None and previous["raw"] != item["raw"]:
                    messagebox.showerror(
                        "Resolve Shared PRX Lines",
                        f"@0x{row_off:04X} has more than one Change value selected.\nChoose one line to Change and set the others to Ignore.",
                    )
                    return
                selected_by_off[row_off] = item
            result["value"] = {row_off: item["raw"] for row_off, item in selected_by_off.items()}
            window.destroy()

        def cancel():
            result["value"] = None
            window.destroy()

        ttk.Button(button_row, text="Cancel", command=cancel, width=10).pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(button_row, text="OK", command=apply_choices, width=10).pack(side=tk.RIGHT)
        window.protocol("WM_DELETE_WINDOW", cancel)
        apply_runtime_theme(window)
        apply_button_outline(window)

        window.update_idletasks()
        width = min(860, max(620, window.winfo_width()))
        height = min(620, max(260, window.winfo_height()))
        x = self.root.winfo_rootx() + (self.root.winfo_width() - width) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - height) // 2
        window.geometry(f"{width}x{height}+{max(0, x)}+{max(0, y)}")
        window.wait_window()
        return result["value"]

    def compile_editor_text_to_prx(self, output_path, base_prx_path=None):
        if not HAS_PRX_TOOLS:
            messagebox.showerror("Missing Tool", "PRX_Tools/prx_value_editor.py is required to compile PRX files.")
            return False

        base_prx_path = base_prx_path or self._get_prx_base_path_for_text()
        if not base_prx_path:
            return False

        try:
            data = bytearray(Path(base_prx_path).read_bytes())
            strings, _source_bdg = self._find_prx_string_table(base_prx_path)
            if strings is None:
                strings = [f"string_{i}" for i in range(65536)]

            prx_entry = {
                "name": Path(base_prx_path).name,
                "offset": 0,
                "size": len(data),
            }
            prx, rows, _roots = PRX_VALUE_EDITOR.parse_rows(data, prx_entry, strings)
            rows_by_off = {row.row_offset: row for row in rows}
            rows_by_key = {}
            duplicate_keys = set()
            for row in rows:
                key = row.key.lower()
                if key in rows_by_key and rows_by_key[key].row_offset != row.row_offset:
                    duplicate_keys.add(key)
                else:
                    rows_by_key[key] = row
            wanted_by_off = {}
            wanted_detail_by_off = {}
            wanted_by_slot = {}
            additions_by_key = {}
            seen_code_keys = {}
            new_strings = [] if self.bundle_entry_edit else None
            conflicts = []
            shared_conflicts = {}
            row_re = re.compile(r"^@0x([0-9A-Fa-f]+)\s+([a-zA-Z0-9_]+)\s+(.+?)\s+=\s+(.*)$")
            code_row_re = re.compile(r"^(?:(float|int|string|ref)\s+)?([A-Za-z_][A-Za-z0-9_.# -]*?)\s*=\s*(.*)$")
            property_set_re = re.compile(r"^property_set\s+(.+?)\s*\{")
            current_property_set = None

            for line_no, line in enumerate(self._current_editor_text().splitlines(), start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#") or stripped.startswith("["):
                    continue

                set_match = property_set_re.match(stripped)
                if set_match:
                    current_property_set = set_match.group(1).strip()
                    continue
                if stripped == "}":
                    current_property_set = None
                    continue
                stripped = stripped.rstrip(";").rstrip()

                old_match = row_re.match(stripped)
                code_match = None if old_match else code_row_re.match(stripped)
                occurrence_edit = False
                if old_match:
                    row_off = int(old_match.group(1), 16)
                    type_name = old_match.group(2)
                    value_text = self._strip_prx_inline_comment(old_match.group(4))
                    row = rows_by_off.get(row_off)
                    if row is None or row.type_name != type_name:
                        continue
                elif code_match:
                    type_name = code_match.group(1)
                    key = code_match.group(2).strip()
                    if current_property_set and not key.lower().startswith(f"{current_property_set.lower()}."):
                        key = f"{current_property_set}.{key}"
                    value_text = self._strip_prx_inline_comment(code_match.group(3))
                    if type_name == "ref":
                        continue
                    lookup_key = key.lower()
                    previous_line = seen_code_keys.get(lookup_key)
                    if previous_line is not None:
                        conflicts.append(
                            f"{key} is declared more than once (lines {previous_line} and {line_no}); "
                            "edit the existing property instead of adding a duplicate line"
                        )
                        continue
                    seen_code_keys[lookup_key] = line_no
                    if lookup_key in duplicate_keys:
                        conflicts.append(f"{key} is ambiguous; use an @0x offset row for this value")
                        continue
                    row = rows_by_key.get(lookup_key)
                    if row is None:
                        if not type_name:
                            conflicts.append(f"{key} does not exist in this PRX; new rows need an explicit type")
                            continue
                        if "." not in key:
                            conflicts.append(f"{key} does not name a group and property")
                            continue
                        group, name = key.rsplit(".", 1)
                        try:
                            type_id = self._prx_type_id_for_name(type_name)
                            value_raw = self._parse_new_prx_value(type_id, value_text, strings, new_strings) & 0xFFFFFFFF
                        except Exception as exc:
                            conflicts.append(f"{key}: {exc}")
                            continue
                        addition = {
                            "group": group,
                            "name": name,
                            "type_id": type_id,
                            "value_raw": value_raw,
                        }
                        previous = additions_by_key.get(lookup_key)
                        if previous is not None and previous != addition:
                            conflicts.append(f"{key} has multiple added values")
                        else:
                            additions_by_key[lookup_key] = addition
                        continue
                    if type_name and row.type_name != type_name:
                        continue
                    occurrence_edit = True
                else:
                    continue
                if row.type_id not in PRX_VALUE_EDITOR.EDITABLE_TYPES:
                    continue

                new_raw = self._parse_prx_value(row, value_text, strings, new_strings) & 0xFFFFFFFF
                if occurrence_edit:
                    wanted_by_slot[row.pointer_offset] = new_raw
                    continue
                previous = wanted_by_off.get(row.row_offset)
                if previous is not None and previous != new_raw:
                    items = shared_conflicts.setdefault(row.row_offset, [])
                    previous_detail = wanted_detail_by_off.get(row.row_offset)
                    if previous_detail and not any(item["raw"] == previous_detail["raw"] and item["line"] == previous_detail["line"] for item in items):
                        items.append(previous_detail)
                    items.append({
                        "line": line_no,
                        "tooltip": f"{row.key} @0x{row.row_offset:04X} = {value_text}",
                        "raw": new_raw,
                    })
                    continue
                wanted_by_off[row.row_offset] = new_raw
                wanted_detail_by_off[row.row_offset] = {
                    "line": line_no,
                    "tooltip": f"{row.key} @0x{row.row_offset:04X} = {value_text}",
                    "raw": new_raw,
                }

            if conflicts:
                raise ValueError("Conflicting PRX edits found:\n" + "\n".join(conflicts))

            if shared_conflicts:
                resolved = self._resolve_prx_shared_line_conflicts(shared_conflicts)
                if resolved is None:
                    return False
                for row_off in shared_conflicts:
                    wanted_by_off.pop(row_off, None)
                for row_off, new_raw in resolved.items():
                    wanted_by_off[row_off] = new_raw

            for row_off, new_raw in sorted(wanted_by_off.items()):
                PRX_VALUE_EDITOR.put_u32(prx, row_off + 4, new_raw)

            prx = self._apply_prx_occurrence_edits(prx, rows, wanted_by_slot)
            prx = self._add_named_prx_rows(prx, rows, strings, list(additions_by_key.values()))

            Path(output_path).write_bytes(prx)
            if self.bundle_entry_edit is not None:
                self._pending_prx_string_values = list(new_strings or [])
            return True
        except Exception as exc:
            messagebox.showerror("Compile Error", f"Failed to compile PRX:\n{exc}")
            return False

    def _decode_edf_file(self, filepath):
        if not HAS_EDF_CODEC:
            return "EDF codec is missing. Expected edf_dump_codec.py.\n"
        return dump_to_editable(Path(filepath).read_bytes(), load_field_names())

    def _remove_xml_formatting_nodes(self, node):
        for child in list(node.childNodes):
            if child.nodeType == child.TEXT_NODE and not child.data.strip():
                node.removeChild(child)
                child.unlink()
            elif child.hasChildNodes():
                self._remove_xml_formatting_nodes(child)

    def _format_ifc_text(self, text):
        document = minidom.parseString(text.encode("utf-8"))
        self._remove_xml_formatting_nodes(document)
        pretty = document.toprettyxml(indent="    ", newl="\n")
        return "\n".join(line for line in pretty.splitlines() if line.strip()) + "\n"

    def _compact_ifc_text(self, text):
        document = minidom.parseString(text.encode("utf-8"))
        self._remove_xml_formatting_nodes(document)
        compact = document.toxml()
        return re.sub(r'^<\?xml version="1\.0" \?>', '<?xml version="1.0"?>', compact)

    def _finish_text_editor_load(self, loaded_text):
        self.monster_data_disassembly_generation += 1
        self.output_text.edit_reset()
        self.output_text.edit_modified(False)
        self.configure_syntax_tags()
        self.configure_editor_diff_tags()
        self.setup_root_table_folds()
        self._sync_editor_diff_baseline(loaded_text)
        self.loading_text_editor = False
        self.extract_btn.config(state=tk.NORMAL)
        self.rebuild_btn.config(state=tk.NORMAL)
        is_monster_data = bool(
            self.bundle_entry_edit
            and self.bundle_entry_edit.get("character_data_label") == "000MONSTER_DATA"
            and self.text_mode == "char_data"
        )
        if is_monster_data:
            self.monster_data_disassembly_active = False
            self.monster_data_editable_text = loaded_text.rstrip("\n") + "\n"
            self.monster_data_editable_baseline = None
            self.monster_data_disassembly_baseline = None
            self.extract_btn.config(text="Block View")
        else:
            self.monster_data_disassembly_active = False
            self.monster_data_editable_text = None
            self.monster_data_editable_baseline = None
            self.monster_data_disassembly_baseline = None
            if self.text_mode == "fdf":
                self.extract_btn.config(text="Atlas Preview")
            elif self.text_mode == "palette":
                self.extract_btn.config(text="Export TXT")
        if self.text_mode == "pvm":
            self.start_visible_syntax_highlight_only()
        else:
            self.start_lazy_syntax_highlight()

    def _insert_large_editor_text(self, loaded_text):
        """Insert a large decoded export without monopolizing Tk's event loop."""
        lines = loaded_text.splitlines(keepends=True)
        chunk_lines = 750
        next_line = 0
        load_generation = self.editor_load_generation
        self.extract_btn.config(state=tk.DISABLED)
        self.rebuild_btn.config(state=tk.DISABLED)
        self.output_text.configure(undo=False)

        def insert_next_chunk():
            nonlocal next_line
            if not self.loading_text_editor or load_generation != self.editor_load_generation:
                self.output_text.configure(undo=True)
                return
            end_line = min(len(lines), next_line + chunk_lines)
            self.output_text.insert(tk.END, "".join(lines[next_line:end_line]))
            next_line = end_line
            if next_line < len(lines):
                self.root.after(1, insert_next_chunk)
                return
            self.output_text.configure(undo=True)
            self._finish_text_editor_load(loaded_text)

        self.root.after(0, insert_next_chunk)

    def load_text_editor_file(self, filepath, ext, from_bundle_entry=False):
        """Load BSF/TXT/IFC/IFL/XFG/PRX/EDF/PVM/LOC/decoded data files into the editable status box."""
        self.cancel_lazy_syntax_highlight()
        self._hide_find_bar_completely()
        self.editor_load_generation += 1
        self.loading_text_editor = True
        if not from_bundle_entry:
            self.parser = None
            self.parsed_files = []
            self.bundle_entry_edit = None
        self.text_source_path = filepath
        self.text_mode = ext.lstrip('.')
        in_folder_dropdown = bool(
            self.current_bundle_dir
            and self.bundle_files
            and any(os.path.abspath(item).lower() == os.path.abspath(filepath).lower() for item in self.bundle_files)
        )
        if from_bundle_entry or in_folder_dropdown:
            self.bundle_select_frame.grid()
        else:
            self.bundle_select_frame.grid_remove()
        self.extract_btn.config(text="Convert")
        self.rebuild_btn.config(text="Save")

        self.output_text.config(state=tk.NORMAL)
        self.output_text.delete(1.0, tk.END)
        loaded_text = None

        if ext == '.bsf':
            if not HAS_GSTE_SCRIPT_TOOL:
                self.output_text.insert(tk.END, "GSTE script tool is missing. Cannot decompile BSF.\n")
                self.extract_btn.config(state=tk.DISABLED)
                self.rebuild_btn.config(state=tk.DISABLED)
                self.loading_text_editor = False
                return
            try:
                data = Path(filepath).read_bytes()
                tokens, _string_start, unknown = read_tokens(data)
                loaded_text = format_source(tokens)
                self.output_text.insert(tk.END, loaded_text)
                if unknown:
                    warning_text = f"\n# Warning: {len(unknown)} unknown opcode(s) were decompiled as placeholders.\n"
                    self.output_text.insert(tk.END, warning_text)
                    loaded_text += warning_text
                self.output_text.edit_reset()
                self.output_text.edit_modified(False)
            except Exception as exc:
                self.output_text.insert(tk.END, f"Failed to decompile BSF:\n{exc}\n")
                self.extract_btn.config(state=tk.DISABLED)
                self.rebuild_btn.config(state=tk.DISABLED)
                self.loading_text_editor = False
                return
            self.extract_btn.config(state=tk.NORMAL)
            self.rebuild_btn.config(state=tk.NORMAL)
        elif ext == '.prx':
            try:
                loaded_text = self._decode_prx_file(filepath)
                self.output_text.insert(tk.END, loaded_text)
                self.output_text.edit_reset()
                self.output_text.edit_modified(False)
            except Exception as exc:
                self.output_text.insert(tk.END, f"Failed to decode PRX:\n{exc}\n")
                self.extract_btn.config(state=tk.DISABLED)
                self.rebuild_btn.config(state=tk.DISABLED)
                self.loading_text_editor = False
                return
            self.extract_btn.config(state=tk.NORMAL)
            self.rebuild_btn.config(state=tk.NORMAL)
        elif ext == '.edf':
            try:
                loaded_text = self._decode_edf_file(filepath)
                self.output_text.insert(tk.END, loaded_text)
                self.output_text.edit_reset()
                self.output_text.edit_modified(False)
            except Exception as exc:
                self.output_text.insert(tk.END, f"Failed to decode EDF:\n{exc}\n")
                self.extract_btn.config(state=tk.DISABLED)
                self.rebuild_btn.config(state=tk.DISABLED)
                self.loading_text_editor = False
                return
            self.extract_btn.config(state=tk.NORMAL)
            self.rebuild_btn.config(state=tk.NORMAL)
        elif ext == '.pvm':
            if not HAS_PVM_SCRIPT_TOOL:
                self.output_text.insert(tk.END, "PVM script tool is missing. Cannot inspect PWK VM PVM.\n")
                self.extract_btn.config(state=tk.DISABLED)
                self.rebuild_btn.config(state=tk.DISABLED)
                self.loading_text_editor = False
                return
            try:
                data = Path(filepath).read_bytes()
                if not is_pwk_vm_module(data):
                    raise ValueError("This .pvm does not use the PWK Virtual machine module header.")
                parse_pvm(data)
                loaded_text = pvm_to_editable(data, Path(filepath))
                self.output_text.insert(tk.END, loaded_text)
                self.output_text.edit_reset()
                self.output_text.edit_modified(False)
            except Exception as exc:
                self.output_text.insert(tk.END, f"Failed to inspect PVM:\n{exc}\n")
                self.extract_btn.config(state=tk.DISABLED)
                self.rebuild_btn.config(state=tk.DISABLED)
                self.loading_text_editor = False
                return
            self.extract_btn.config(state=tk.NORMAL)
            self.rebuild_btn.config(state=tk.NORMAL)
        elif ext == '.loc':
            if not HAS_LOC_TEXT_TOOL:
                self.output_text.insert(tk.END, "LOC localization tool is missing. Cannot decode LOC.\n")
                self.extract_btn.config(state=tk.DISABLED)
                self.rebuild_btn.config(state=tk.DISABLED)
                self.loading_text_editor = False
                return
            try:
                loaded_text = loc_to_editable(Path(filepath).read_bytes())
                self.output_text.insert(tk.END, loaded_text)
                self.output_text.edit_reset()
                self.output_text.edit_modified(False)
            except Exception as exc:
                self.output_text.insert(tk.END, f"Failed to decode LOC:\n{exc}\n")
                self.extract_btn.config(state=tk.DISABLED)
                self.rebuild_btn.config(state=tk.DISABLED)
                self.loading_text_editor = False
                return
            self.extract_btn.config(state=tk.NORMAL)
            self.rebuild_btn.config(state=tk.NORMAL)
        elif ext in ('.char_data', '.level_data'):
            try:
                text = Path(filepath).read_text(encoding='utf-8', errors='replace')
            except Exception as exc:
                label = self.bundle_entry_edit.get("character_data_label", "Character_Data") if self.bundle_entry_edit else "Character_Data"
                self.output_text.insert(tk.END, f"Failed to open {label} text:\n{exc}\n")
                self.extract_btn.config(state=tk.DISABLED)
                self.rebuild_btn.config(state=tk.DISABLED)
                self.loading_text_editor = False
                return
            loaded_text = text
            self._insert_large_editor_text(loaded_text)
            return
        elif ext == '.skeleton_type3':
            try:
                text = Path(filepath).read_text(encoding='utf-8', errors='replace')
            except Exception as exc:
                label = self.bundle_entry_edit.get("skeleton_type3_label", "Skeleton") if self.bundle_entry_edit else "Skeleton"
                self.output_text.insert(tk.END, f"Failed to open {label} text:\n{exc}\n")
                self.extract_btn.config(state=tk.DISABLED)
                self.rebuild_btn.config(state=tk.DISABLED)
                self.loading_text_editor = False
                return
            loaded_text = text
            self.output_text.insert(tk.END, loaded_text)
            self.output_text.edit_reset()
            self.output_text.edit_modified(False)
            self.extract_btn.config(state=tk.NORMAL)
            self.rebuild_btn.config(state=tk.NORMAL)
        elif ext == '.ifc':
            try:
                text = Path(filepath).read_text(encoding='utf-8', errors='strict')
                loaded_text = self._format_ifc_text(text)
            except Exception as exc:
                self.output_text.insert(tk.END, f"Failed to format IFC markup:\n{exc}\n")
                self.extract_btn.config(state=tk.DISABLED)
                self.rebuild_btn.config(state=tk.DISABLED)
                self.loading_text_editor = False
                return
            self.output_text.insert(tk.END, loaded_text)
            self.output_text.edit_reset()
            self.output_text.edit_modified(False)
            self.extract_btn.config(state=tk.DISABLED)
            self.rebuild_btn.config(state=tk.NORMAL)
        else:
            try:
                text = Path(filepath).read_text(encoding='utf-8', errors='replace')
            except Exception as exc:
                self.output_text.insert(tk.END, f"Failed to open text file:\n{exc}\n")
                self.extract_btn.config(state=tk.DISABLED)
                self.rebuild_btn.config(state=tk.DISABLED)
                self.loading_text_editor = False
                return
            loaded_text = text
            self.output_text.insert(tk.END, loaded_text)
            self.output_text.edit_reset()
            self.output_text.edit_modified(False)
            self.extract_btn.config(state=tk.NORMAL if ext in ('.txt', '.xfg') else tk.DISABLED)
            self.rebuild_btn.config(state=tk.NORMAL)
        self._finish_text_editor_load(loaded_text)

    def _current_editor_text(self):
        if self.monster_data_disassembly_active and self.monster_data_editable_text is not None:
            return MONSTER_DATA_TOOL.apply_disassembly_edits(
                self.monster_data_editable_text,
                self.output_text.get("1.0", tk.END).rstrip("\n") + "\n",
                self.monster_data_disassembly_baseline or "",
            )
        return self.output_text.get("1.0", tk.END).rstrip("\n") + "\n"

    def _toggle_monster_data_disassembly(self):
        if not (
            self.bundle_entry_edit
            and self.bundle_entry_edit.get("character_data_label") == "000MONSTER_DATA"
            and self.text_mode == "char_data"
            and MONSTER_DATA_TOOL is not None
        ):
            return False
        if self.monster_data_disassembly_active:
            self.monster_data_disassembly_generation += 1
            try:
                displayed = MONSTER_DATA_TOOL.apply_disassembly_edits(
                    self.monster_data_editable_text or "",
                    self.output_text.get("1.0", tk.END).rstrip("\n") + "\n",
                    self.monster_data_disassembly_baseline or "",
                )
            except Exception as exc:
                messagebox.showerror("MonsterData Block View", f"Could not apply block-view edits:\n{exc}")
                return True
            self.monster_data_editable_text = displayed
            self.monster_data_disassembly_active = False
            self.output_text.config(state=tk.NORMAL)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert("1.0", displayed)
            self.extract_btn.config(text="Block View")
            self.rebuild_btn.config(state=tk.NORMAL)
            self.output_text.edit_reset()
            self.output_text.edit_modified(False)
            self._sync_editor_diff_baseline(self.monster_data_editable_baseline or displayed)
            self.monster_data_editable_baseline = None
            self.monster_data_disassembly_baseline = None
            self.setup_root_table_folds()
            self.syntax_highlighted_intervals = []
            self.start_lazy_syntax_highlight()
            return True

        editable = self.output_text.get("1.0", tk.END).rstrip("\n") + "\n"
        self.monster_data_editable_text = editable
        self.monster_data_editable_baseline = self.editor_original_text
        temp_path = self.bundle_entry_edit.get("temp_path")
        self.monster_data_disassembly_generation += 1
        generation = self.monster_data_disassembly_generation
        self.extract_btn.config(text="Loading...", state=tk.DISABLED)
        self.rebuild_btn.config(state=tk.DISABLED)
        self.output_text.config(state=tk.DISABLED)

        def worker():
            try:
                source_blob = None
                if temp_path and Path(temp_path).exists():
                    source_blob = Path(temp_path).read_bytes()
                displayed = MONSTER_DATA_TOOL.disassemble_source_view(editable, source_blob)
                error = None
            except Exception as exc:
                displayed = None
                error = exc

            def finish():
                if generation != self.monster_data_disassembly_generation:
                    return
                if error is not None:
                    self.output_text.config(state=tk.NORMAL)
                    self.extract_btn.config(text="Block View", state=tk.NORMAL)
                    self.rebuild_btn.config(state=tk.NORMAL)
                    self.monster_data_editable_baseline = None
                    messagebox.showerror("MonsterData Block View", f"Failed to build MonsterData block view:\n{error}")
                    return
                self.monster_data_disassembly_active = True
                self.monster_data_disassembly_baseline = displayed
                display_lines = displayed.splitlines(keepends=True)
                next_line = 0
                self.output_text.config(state=tk.NORMAL)
                self.output_text.delete("1.0", tk.END)

                def insert_next_chunk():
                    nonlocal next_line
                    if generation != self.monster_data_disassembly_generation:
                        return
                    end_line = min(next_line + 750, len(display_lines))
                    self.output_text.config(state=tk.NORMAL)
                    self.output_text.insert(tk.END, "".join(display_lines[next_line:end_line]))
                    next_line = end_line
                    if next_line < len(display_lines):
                        self.output_text.config(state=tk.DISABLED)
                        self.root.after_idle(insert_next_chunk)
                        return
                    self.extract_btn.config(text="Data View", state=tk.NORMAL)
                    self.rebuild_btn.config(state=tk.NORMAL)
                    self.output_text.edit_reset()
                    self.output_text.edit_modified(False)
                    self._sync_editor_diff_baseline(displayed)
                    self.setup_root_table_folds()
                    self.syntax_highlighted_intervals = []
                    self.start_lazy_syntax_highlight()

                insert_next_chunk()

            self.root.after(0, finish)

        threading.Thread(target=worker, daemon=True).start()
        return True

    def _editor_has_unsaved_text_changes(self):
        if not self.text_mode or self.loading_text_editor:
            return False
        current = self._normalize_editor_text(self._current_editor_text())
        if self.monster_data_disassembly_active and self.monster_data_editable_baseline is not None:
            baseline = self.monster_data_editable_baseline
        else:
            baseline = self.editor_original_text or ""
        return current != self._normalize_editor_text(baseline)

    def compile_editor_text_to_bsf(self, output_path):
        if not HAS_GSTE_SCRIPT_TOOL:
            messagebox.showerror("Missing Tool", "gste_script_tool_v3.py is required to compile BSF files.")
            return False
        try:
            data = compile_tokens(lex_source(self._current_editor_text()), source_name=DEFAULT_SOURCE_NAME)
            Path(output_path).write_bytes(data)
            return True
        except Exception as exc:
            messagebox.showerror("Compile Error", f"Failed to compile BSF:\n{exc}")
            return False

    def compile_editor_text_to_edf(self, output_path):
        if not HAS_EDF_CODEC:
            messagebox.showerror("Missing Tool", "edf_dump_codec.py is required to compile EDF files.")
            return False
        try:
            Path(output_path).write_bytes(editable_to_dump(self._current_editor_text()))
            return True
        except Exception as exc:
            messagebox.showerror("Compile Error", f"Failed to compile EDF:\n{exc}")
            return False

    def compile_editor_text_to_pvm(self, output_path, base_pvm_path=None):
        if not HAS_PVM_SCRIPT_TOOL:
            messagebox.showerror("Missing Tool", "pvm_script_tool.py is required to patch PVM files.")
            return False
        try:
            base_path = Path(base_pvm_path or output_path)
            original = base_path.read_bytes()
            Path(output_path).write_bytes(editable_to_pvm(self._current_editor_text(), original))
            return True
        except Exception as exc:
            messagebox.showerror("Compile Error", f"Failed to patch PVM:\n{exc}")
            return False

    def compile_editor_text_to_loc(self, output_path, base_loc_path=None):
        if not HAS_LOC_TEXT_TOOL:
            messagebox.showerror("Missing Tool", "loc_text_tool.py is required to rebuild LOC files.")
            return False
        try:
            base_path = Path(base_loc_path or output_path)
            original = base_path.read_bytes()
            Path(output_path).write_bytes(editable_to_loc(self._current_editor_text(), original))
            return True
        except Exception as exc:
            messagebox.showerror("Compile Error", f"Failed to rebuild LOC:\n{exc}")
            return False

    def compile_editor_text_to_character_data(self, output_path):
        if not self.bundle_entry_edit:
            messagebox.showerror("Save Error", "Character data must be edited from inside a loaded bundle.")
            return False

        data_tool = self.bundle_entry_edit.get("character_data_tool")
        data_label = self.bundle_entry_edit.get("character_data_label", "Character_Data")
        if data_tool is None:
            messagebox.showerror("Missing Tool", f"A decoder is required to patch {data_label}.")
            return False

        try:
            text = self._current_editor_text()
            text_path = Path(self.bundle_entry_edit.get("text_path") or self.text_source_path)
            text_path.write_text(text, encoding='utf-8', newline='\n')

            bundle_path = Path(self.bundle_entry_edit["bundle_path"])
            if self.text_mode == "level_data":
                entry_name = str(self.bundle_entry_edit.get("entry", {}).get("name", ""))
                data, _parser, _entries, strings, character_data = data_tool.parse_bundle(bundle_path, entry_name)
            else:
                data, _parser, _entries, strings, character_data = data_tool.parse_bundle(bundle_path)
            base, size = data_tool.character_data_span(character_data)
            wanted = {}
            conflicts = []
            ref_lookup = data_tool.build_ref_name_lookup_from_text(text) if hasattr(data_tool, "build_ref_name_lookup_from_text") else {}
            if hasattr(data_tool, "augment_ref_lookup_with_current_refs"):
                data_tool.augment_ref_lookup_with_current_refs(text, data, base, size, ref_lookup)
            ref_name_counts = data_tool.ref_value_name_counts_from_text(text) if hasattr(data_tool, "ref_value_name_counts_from_text") else {}

            for line in text.splitlines():
                match = data_tool.ROW_RE.match(line.strip())
                if not match:
                    continue
                rel = int(match.group(1), 16)
                kind = match.group(2)
                label = match.group(3).strip()
                value_text = match.group(4).strip()
                ascii_size = data_tool.parse_ascii_kind(kind) if hasattr(data_tool, "parse_ascii_kind") else None
                if ascii_size is None and kind not in {"string", "u32", "f32", "float", "int", "word", "ref", "bool", "u16x2", "u8x4"}:
                    continue
                edit_size = ascii_size or 4
                if rel < 0 or rel + edit_size > size or rel % 4:
                    continue
                if kind == "ref" and hasattr(data_tool, "ref_lookup_key"):
                    clean_ref_value = data_tool.strip_inline_comment(value_text).strip() if hasattr(data_tool, "strip_inline_comment") else value_text.strip()
                    try:
                        data_tool.parse_u32_value(clean_ref_value)
                    except ValueError:
                        key = data_tool.ref_lookup_key(clean_ref_value)
                        target = ref_lookup.get(key)
                        old_raw = data_tool.u32(data, base + rel) if hasattr(data_tool, "u32") else None
                        if target is None or (old_raw is not None and target != old_raw):
                            continue
                try:
                    new_bytes = data_tool.parse_new_value(kind, value_text, strings, ref_lookup)
                except TypeError:
                    new_bytes = data_tool.parse_new_value(kind, value_text, strings)
                previous = wanted.get(rel)
                if previous and previous[0] != new_bytes:
                    conflicts.append(f"@0x{rel:06X} has conflicting edits: {previous[1]} vs {value_text}")
                    continue
                wanted[rel] = (new_bytes, value_text, label, edit_size)

            if conflicts:
                raise RuntimeError("Conflicting duplicate-offset edits:\n  " + "\n  ".join(conflicts))

            for rel, (new_bytes, _value_text, _label, edit_size) in wanted.items():
                absolute = base + rel
                data[absolute:absolute + edit_size] = new_bytes

            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            Path(output_path).write_bytes(bytes(data[base:base + size]))
            return True
        except Exception as exc:
            messagebox.showerror("Compile Error", f"Failed to patch {data_label}:\n{exc}")
            return False

    def compile_editor_text_to_skeleton_type3(self, output_path):
        if not self.bundle_entry_edit:
            messagebox.showerror("Save Error", "Skeleton data must be edited from inside a loaded bundle.")
            return False

        skeleton_tool = self.bundle_entry_edit.get("skeleton_type3_tool")
        skeleton_label = self.bundle_entry_edit.get("skeleton_type3_label", "Skeleton")
        if skeleton_tool is None:
            messagebox.showerror("Missing Tool", "A decoder is required to patch CMP type-3 skeleton data.")
            return False

        try:
            text_path = Path(self.bundle_entry_edit.get("text_path") or self.text_source_path)
            text_path.write_text(self._current_editor_text(), encoding='utf-8', newline='\n')

            strings = None
            try:
                bundle_path = Path(self.bundle_entry_edit["bundle_path"])
                _data, _parser, _entries, strings, _endian = skeleton_tool.parse_bundle_any(bundle_path)
            except Exception:
                strings = None
            source_blob = Path(self.bundle_entry_edit["temp_path"]).read_bytes()
            patched_blob = skeleton_tool.apply_txt_to_skeleton_blob(
                text_path,
                source_blob,
                strings,
                self.bundle_entry_edit.get("skeleton_endian"),
            )
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            Path(output_path).write_bytes(patched_blob)
            return True
        except Exception as exc:
            messagebox.showerror("Compile Error", f"Failed to patch {skeleton_label}:\n{exc}")
            return False

    def compile_editor_text_to_material(self, output_path):
        if not self.bundle_entry_edit or not HAS_MATERIAL_TEXT_TOOL:
            messagebox.showerror("Save Error", "Material data must be edited from inside a loaded bundle.")
            return False
        try:
            original = self.bundle_entry_edit.get("material_original")
            if original is None:
                original = Path(output_path).read_bytes()
            endian = self.bundle_entry_edit.get("material_endian", '<')
            text = self._current_editor_text()
            compiled = MATERIAL_TEXT_TOOL.encode_material(text, original, endian)
            Path(output_path).write_bytes(compiled)
            text_path = Path(self.bundle_entry_edit.get("text_path") or self.text_source_path)
            text_path.write_text(text, encoding="utf-8", newline="\n")
            self.bundle_entry_edit["material_original"] = compiled
            return True
        except Exception as exc:
            messagebox.showerror("Material Save Error", f"Failed to compile material:\n{exc}")
            return False

    def compile_editor_text_to_palette(self, output_path):
        if not self.bundle_entry_edit or not HAS_PALETTE_TEXT_TOOL:
            messagebox.showerror("Save Error", "Palette data must be edited from inside a loaded bundle.")
            return False
        try:
            original = self.bundle_entry_edit.get("palette_original")
            if original is None:
                original = Path(output_path).read_bytes()
            text = self._current_editor_text()
            compiled = PALETTE_TEXT_TOOL.encode_palette(text, original)
            Path(output_path).write_bytes(compiled)
            Path(self.bundle_entry_edit.get("text_path") or self.text_source_path).write_text(
                text, encoding="utf-8", newline="\n"
            )
            self.bundle_entry_edit["palette_original"] = compiled
            return True
        except Exception as exc:
            messagebox.showerror("Palette Save Error", f"Failed to compile palette:\n{exc}")
            return False

    def compile_editor_text_to_fdf(self, output_path):
        if not self.bundle_entry_edit or not HAS_FDF_TEXT_TOOL:
            messagebox.showerror("Save Error", "FDF data must be edited from inside a loaded bundle.")
            return False
        try:
            original = self.bundle_entry_edit.get("fdf_original")
            if original is None:
                original = Path(output_path).read_bytes()
            text = self._current_editor_text()
            compiled = FDF_TEXT_TOOL.encode_fdf(text, original)
            Path(output_path).write_bytes(compiled)
            Path(self.bundle_entry_edit.get("text_path") or self.text_source_path).write_text(
                text, encoding="utf-8", newline="\n"
            )
            self.bundle_entry_edit["fdf_original"] = compiled
            return True
        except Exception as exc:
            messagebox.showerror("FDF Save Error", f"Failed to compile FDF font:\n{exc}")
            return False

    def create_incremental_backup(self, filepath):
        source = Path(filepath)
        if not source.exists():
            return None
        backup = source.with_name(f"{source.name}.bak")
        index = 1
        while backup.exists():
            backup = source.with_name(f"{source.name}.bak{index}")
            index += 1
        shutil.copy2(source, backup)
        return backup

    def backup_current_text_source(self):
        return self.create_incremental_backup(self.text_source_path)

    def write_current_editor_to_source(self):
        if not self.text_source_path or not self.text_mode:
            messagebox.showerror("Save Error", "No source file is currently open.")
            return False
        source = Path(self.text_source_path)
        if self.text_mode == 'bsf':
            return self.compile_editor_text_to_bsf(source)
        if self.text_mode in ('txt', 'xfg', 'ifl'):
            source.write_text(self._current_editor_text(), encoding='utf-8', newline='\n')
            return True
        if self.text_mode == 'ifc':
            try:
                compact = self._compact_ifc_text(self._current_editor_text())
                source.write_text(compact, encoding='utf-8', newline='\n')
                return True
            except Exception as exc:
                messagebox.showerror("IFC Save Error", f"The IFC markup is not valid:\n{exc}")
                return False
        if self.text_mode == 'edf':
            return self.compile_editor_text_to_edf(source)
        if self.text_mode == 'prx':
            return self.compile_editor_text_to_prx(source, self.text_source_path)
        if self.text_mode == 'pvm':
            return self.compile_editor_text_to_pvm(source, self.text_source_path)
        if self.text_mode == 'loc':
            return self.compile_editor_text_to_loc(source, self.text_source_path)
        if self.text_mode in {'char_data', 'level_data'}:
            if not self.bundle_entry_edit:
                messagebox.showerror("Save Error", "Data entries must be edited from inside a loaded bundle.")
                return False
            return self.compile_editor_text_to_character_data(self.bundle_entry_edit["temp_path"])
        if self.text_mode == 'skeleton_type3':
            if not self.bundle_entry_edit:
                messagebox.showerror("Save Error", "Skeleton data must be edited from inside a loaded bundle.")
                return False
            return self.compile_editor_text_to_skeleton_type3(self.bundle_entry_edit["temp_path"])
        if self.text_mode == 'material':
            if not self.bundle_entry_edit:
                messagebox.showerror("Save Error", "Material data must be edited from inside a loaded bundle.")
                return False
            return self.compile_editor_text_to_material(self.bundle_entry_edit["temp_path"])
        if self.text_mode == 'palette':
            if not self.bundle_entry_edit:
                messagebox.showerror("Save Error", "Palette data must be edited from inside a loaded bundle.")
                return False
            return self.compile_editor_text_to_palette(self.bundle_entry_edit["temp_path"])
        if self.text_mode == 'fdf':
            if not self.bundle_entry_edit:
                messagebox.showerror("Save Error", "FDF data must be edited from inside a loaded bundle.")
                return False
            return self.compile_editor_text_to_fdf(self.bundle_entry_edit["temp_path"])
        if self.text_mode == 'camera_path':
            if not self.bundle_entry_edit:
                messagebox.showerror("Save Error", "Camera/path data must be edited from inside a loaded bundle.")
                return False
            try:
                original = self.bundle_entry_edit.get("camera_path_original")
                if original is None:
                    original = Path(self.bundle_entry_edit["temp_path"]).read_bytes()
                compiled = self._camera_path_from_text(self._current_editor_text(), original)
                Path(self.bundle_entry_edit["temp_path"]).write_bytes(compiled)
                self.bundle_entry_edit["camera_path_original"] = compiled
                rendered = self._camera_path_to_text(
                    compiled,
                    self.bundle_entry_edit.get("entry", {}).get("name", "CameraPath"),
                )
                Path(self.text_source_path).write_text(rendered, encoding="utf-8", newline="\n")
                self.output_text.delete("1.0", tk.END)
                self.output_text.insert("1.0", rendered)
                return True
            except Exception as exc:
                messagebox.showerror("Camera/Path", f"Failed to compile camera/path data:\n{exc}")
                return False
        return False

    def save_text_direct(self, data_writer, label):
        if not self.text_source_path:
            messagebox.showerror("Save Error", "No source file is currently open.")
            return False
        source = Path(self.text_source_path)
        try:
            backup = self.backup_current_text_source()
            result = data_writer(source)
            if result is False:
                return False
            if self.monster_data_disassembly_active:
                merged = self._current_editor_text()
                self.monster_data_editable_text = merged
                self.monster_data_editable_baseline = merged
                self.monster_data_disassembly_baseline = self.output_text.get("1.0", tk.END).rstrip("\n") + "\n"
            self.output_text.edit_reset()
            self.output_text.edit_modified(False)
            if self.monster_data_disassembly_active:
                self._sync_editor_diff_baseline(self.monster_data_disassembly_baseline)
            else:
                self._sync_editor_diff_baseline()
            backup_msg = f"\nBackup: {backup}" if backup else ""
            if not self.bundle_entry_edit:
                messagebox.showinfo("Saved", f"{label} saved successfully:\n{source}{backup_msg}")
            return True
        except Exception as exc:
            messagebox.showerror("Save Error", f"Failed to save {label}:\n{exc}")
            return False

    def choose_txt_convert_target(self):
        choice = {"value": None}
        window = tk.Toplevel(self.root)
        set_window_icon(window)
        window.title("Convert TXT")
        window.transient(self.root)
        window.resizable(False, False)
        window.grab_set()

        frame = ttk.Frame(window, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Convert TXT to:").pack(anchor=tk.W, pady=(0, 8))

        def pick(value):
            choice["value"] = value
            window.destroy()

        row = ttk.Frame(frame)
        row.pack()
        ttk.Button(row, text="BSF", command=lambda: pick("bsf"), width=8).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(row, text="PRX", command=lambda: pick("prx"), width=8).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(row, text="EDF", command=lambda: pick("edf"), width=8).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(row, text="Cancel", command=window.destroy, width=8).pack(side=tk.LEFT)
        apply_button_outline(window)

        window.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - window.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - window.winfo_height()) // 2
        window.geometry(f"+{max(0, x)}+{max(0, y)}")
        window.wait_window()
        return choice["value"]

    def open_fdf_atlas_preview(self):
        match = re.search(r"^\s*AtlasFile\s*=\s*(['\"])(.*?)\1\s*;", self._current_editor_text(), re.MULTILINE)
        if not match:
            messagebox.showerror("FDF Atlas", "The FDF source has no valid AtlasFile value.")
            return
        atlas_name = Path(match.group(2).replace('\\', '/')).name.lower()
        atlas_stem = atlas_name.rsplit('.', 1)[0]
        candidates = []
        for entry in self._texture_preview_entries():
            display = Path(self._texture_preview_display_name(entry)).name.lower()
            display_stem = display.rsplit('.', 1)[0]
            if display_stem == atlas_stem:
                candidates.append(entry)
        if not candidates:
            messagebox.showerror("FDF Atlas", f"No type-9 texture resource matches {match.group(2)}.")
            return
        if self._editor_has_unsaved_text_changes():
            choice = messagebox.askyesnocancel("Unsaved FDF", "Save the FDF changes before opening its atlas?")
            if choice is None:
                return
            if choice and not self.save_bundle_entry_edit():
                return
        entry = candidates[0]
        sample_image = None
        try:
            session = self._ensure_texture_preview_session(entry)
            png_path = self._texture_preview_png_path(session, entry)
            resource_path = Path(session["replacement_dir"]) / str(entry.get('name', '')).replace('\\', '/')
            if not resource_path.exists() or not png_path.exists():
                self.parser.extract_file(entry, session["replacement_dir"])
            if png_path.exists() and hasattr(FDF_TEXT_TOOL, "render_sample"):
                sample_image = FDF_TEXT_TOOL.render_sample(self._current_editor_text(), png_path)
        except Exception:
            sample_image = None
        self.open_texture_preview(entry)
        if sample_image is not None and HAS_PIL and ImageTk is not None:
            self.output_text.insert(tk.END, "\nFont sample:\n")
            self.fdf_font_preview_image = ImageTk.PhotoImage(sample_image)
            self.output_text.image_create(tk.END, image=self.fdf_font_preview_image)
            self.output_text.insert(tk.END, "\n")

    def convert_text_editor_file(self):
        if self._toggle_monster_data_disassembly():
            return

        if self.text_mode == 'fdf':
            self.open_fdf_atlas_preview()
            return

        if self.text_mode == 'palette':
            output_path = _dialog(
                self.root,
                filedialog.asksaveasfilename,
                title="Export Palette TXT As",
                initialdir=os.path.dirname(self.text_source_path),
                initialfile=Path(self.text_source_path).stem + ".txt",
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            )
            if output_path:
                Path(output_path).write_text(self._current_editor_text(), encoding="utf-8", newline="\n")
                messagebox.showinfo("Exported", f"Palette TXT exported successfully:\n{output_path}")
            return

        if self.text_mode == 'bsf':
            initial = os.path.splitext(os.path.basename(self.text_source_path))[0] + ".txt"
            output_path = _dialog(
                self.root,
                filedialog.asksaveasfilename,
                title="Save Decompiled TXT As",
                initialdir=os.path.dirname(self.text_source_path),
                initialfile=initial,
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            )
            if not output_path:
                return
            Path(output_path).write_text(self._current_editor_text(), encoding='utf-8', newline='\n')
            messagebox.showinfo("Converted", f"TXT saved successfully:\n{output_path}")
            return

        if self.text_mode in ('txt', 'xfg'):
            target = self.choose_txt_convert_target()
            if not target:
                return

            ext = ".prx" if target == 'prx' else ".edf" if target == 'edf' else ".bsf"
            initial = os.path.splitext(os.path.basename(self.text_source_path))[0] + ext
            output_path = _dialog(
                self.root,
                filedialog.asksaveasfilename,
                title=f"Save Compiled {target.upper()} As",
                initialdir=os.path.dirname(self.text_source_path),
                initialfile=initial,
                defaultextension=ext,
                filetypes=[(f"{target.upper()} Files", f"*{ext}"), ("All Files", "*.*")],
            )
            if not output_path:
                return
            if target == 'prx':
                if self.compile_editor_text_to_prx(output_path):
                    messagebox.showinfo("Converted", f"PRX saved successfully:\n{output_path}")
            elif target == 'edf':
                if self.compile_editor_text_to_edf(output_path):
                    messagebox.showinfo("Converted", f"EDF saved successfully:\n{output_path}")
            elif self.compile_editor_text_to_bsf(output_path):
                messagebox.showinfo("Converted", f"BSF saved successfully:\n{output_path}")

        if self.text_mode == 'prx':
            initial = os.path.splitext(os.path.basename(self.text_source_path))[0] + ".txt"
            output_path = _dialog(
                self.root,
                filedialog.asksaveasfilename,
                title="Save Decoded PRX TXT As",
                initialdir=os.path.dirname(self.text_source_path),
                initialfile=initial,
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            )
            if output_path:
                Path(output_path).write_text(self._current_editor_text(), encoding='utf-8', newline='\n')
                messagebox.showinfo("Converted", f"PRX TXT saved successfully:\n{output_path}")

        if self.text_mode == 'edf':
            initial = os.path.splitext(os.path.basename(self.text_source_path))[0] + ".txt"
            output_path = _dialog(
                self.root,
                filedialog.asksaveasfilename,
                title="Save Decoded EDF TXT As",
                initialdir=os.path.dirname(self.text_source_path),
                initialfile=initial,
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            )
            if output_path:
                Path(output_path).write_text(self._current_editor_text(), encoding='utf-8', newline='\n')
                messagebox.showinfo("Converted", f"EDF TXT saved successfully:\n{output_path}")

        if self.text_mode == 'pvm':
            initial = os.path.splitext(os.path.basename(self.text_source_path))[0] + ".pvm.txt"
            output_path = _dialog(
                self.root,
                filedialog.asksaveasfilename,
                title="Save PVM Report As",
                initialdir=os.path.dirname(self.text_source_path),
                initialfile=initial,
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            )
            if output_path:
                Path(output_path).write_text(self._current_editor_text(), encoding='utf-8', newline='\n')
                messagebox.showinfo("Converted", f"PVM report saved successfully:\n{output_path}")

        if self.text_mode == 'loc':
            initial = os.path.splitext(os.path.basename(self.text_source_path))[0] + ".loc.txt"
            output_path = _dialog(
                self.root,
                filedialog.asksaveasfilename,
                title="Save LOC Text As",
                initialdir=os.path.dirname(self.text_source_path),
                initialfile=initial,
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            )
            if output_path:
                Path(output_path).write_text(self._current_editor_text(), encoding='utf-8', newline='\n')
                messagebox.showinfo("Converted", f"LOC text saved successfully:\n{output_path}")

        if self.text_mode in {'char_data', 'level_data'}:
            data_label = self.bundle_entry_edit.get("character_data_label", "Character_Data") if self.bundle_entry_edit else "Character_Data"
            output_path = _dialog(
                self.root,
                filedialog.asksaveasfilename,
                title=f"Export {data_label} TXT As",
                initialdir=os.path.dirname(self.text_source_path),
                initialfile=self._character_data_text_name(),
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            )
            if output_path:
                Path(output_path).write_text(self._current_editor_text(), encoding='utf-8', newline='\n')
                messagebox.showinfo("Exported", f"{data_label} TXT exported successfully:\n{output_path}")

        if self.text_mode == 'skeleton_type3':
            skeleton_label = self.bundle_entry_edit.get("skeleton_type3_label", "Skeleton") if self.bundle_entry_edit else "Skeleton"
            initial = self._skeleton_type3_text_name(self.bundle_entry_edit.get("entry", {})) if self.bundle_entry_edit else "Skeleton.txt"
            output_path = _dialog(
                self.root,
                filedialog.asksaveasfilename,
                title=f"Export {skeleton_label} TXT As",
                initialdir=os.path.dirname(self.text_source_path),
                initialfile=initial,
                defaultextension=".txt",
                filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")],
            )
            if output_path:
                Path(output_path).write_text(self._current_editor_text(), encoding='utf-8', newline='\n')
                messagebox.showinfo("Exported", f"{skeleton_label} TXT exported successfully:\n{output_path}")

    def save_text_editor_file(self):
        if self.bundle_entry_edit:
            if not self._stage_current_bundle_editor_changes():
                return
            changed_names = self._changed_bundle_entry_names()
            if not changed_names:
                return
            save_choice, selected_names = self._prompt_save_bundle_entry_changes(changed_names)
            if save_choice and self.save_bundle_entry_edit(selected_names=selected_names):
                self._sync_editor_diff_baseline()
            return

        if self.text_mode == 'bsf':
            self.save_text_direct(lambda path: self.compile_editor_text_to_bsf(path), "BSF")
            return

        if self.text_mode == 'txt':
            self.save_text_direct(lambda path: path.write_text(self._current_editor_text(), encoding='utf-8', newline='\n'), "TXT")
            return

        if self.text_mode == 'xfg':
            self.save_text_direct(lambda path: path.write_text(self._current_editor_text(), encoding='utf-8', newline='\n'), "XFG")
            return

        if self.text_mode == 'ifc':
            self.save_text_direct(lambda path: path.write_text(self._current_editor_text(), encoding='utf-8', newline='\n'), "IFC")
            return

        if self.text_mode == 'ifl':
            self.save_text_direct(lambda path: path.write_text(self._current_editor_text(), encoding='utf-8', newline='\n'), "IFL")
            return

        if self.text_mode == 'edf':
            self.save_text_direct(lambda path: self.compile_editor_text_to_edf(path), "EDF")
            return

        if self.text_mode == 'prx':
            self.save_text_direct(lambda path: self.compile_editor_text_to_prx(path, self.text_source_path), "PRX")
            return

        if self.text_mode == 'pvm':
            self.save_text_direct(lambda path: self.compile_editor_text_to_pvm(path, self.text_source_path), "PVM")
            return

        if self.text_mode == 'loc':
            self.save_text_direct(lambda path: self.compile_editor_text_to_loc(path, self.text_source_path), "LOC")
            return

        if self.text_mode in {'char_data', 'level_data'}:
            data_label = self.bundle_entry_edit.get("character_data_label", "Character_Data") if self.bundle_entry_edit else "Character_Data"
            self.save_text_direct(lambda path: self.compile_editor_text_to_character_data(path), data_label)
            return

        if self.text_mode == 'skeleton_type3':
            skeleton_label = self.bundle_entry_edit.get("skeleton_type3_label", "Skeleton") if self.bundle_entry_edit else "Skeleton"
            self.save_text_direct(lambda path: self.compile_editor_text_to_skeleton_type3(path), skeleton_label)

    def extract_files(self):
        """Open extraction window"""
        if self.texture_preview_session:
            self.replace_texture_preview_png()
            return

        if self.text_mode:
            self.convert_text_editor_file()
            return

        if not self.parsed_files or not self.parser:
            messagebox.showwarning("No Data", "Please parse a file first.")
            return

        # Create callback for window to update main output
        def output_callback(text):
            self.output_text.insert(tk.END, text)

        # Create callback to track last extraction directory
        def extract_dir_callback(dir_path):
            self.last_extract_dir = dir_path

        # Create non-modal extract window
        window = ExtractWindow(
            self.root,
            self.parsed_files,
            self.parser,
            output_callback,
            extract_dir_callback,
            remembered_file_nums=self.extract_selection_file_nums,
            selection_update_callback=self.remember_extract_selection,
        )
        self.child_windows.append(window.window)

        # Remove from list when window is closed
        def on_window_close():
            if window.window in self.child_windows:
                self.child_windows.remove(window.window)
            window.destroy()

        window.window.protocol("WM_DELETE_WINDOW", on_window_close)

    def open_build_menu(self):
        choice = {"value": None}
        window = tk.Toplevel(self.root)
        set_window_icon(window)
        window.title("Build")
        window.transient(self.root)
        window.resizable(False, False)
        window.grab_set()

        frame = ttk.Frame(window, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Build from folder:").pack(anchor=tk.W, pady=(0, 8))

        def pick(value):
            choice["value"] = value
            window.destroy()

        row = ttk.Frame(frame)
        row.pack()
        ttk.Button(row, text="VOL", command=lambda: pick("vol"), width=10).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(row, text="ISO", command=lambda: pick("iso"), width=10).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(row, text="Cancel", command=window.destroy, width=10).pack(side=tk.LEFT)
        apply_button_outline(window)

        window.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - window.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - window.winfo_height()) // 2
        window.geometry(f"+{max(0, x)}+{max(0, y)}")
        window.wait_window()

        if choice["value"] == "vol":
            self.build_vol_bundle()
        elif choice["value"] == "iso":
            self.build_iso_image()

    def _open_build_log_window(self, title):
        window = tk.Toplevel(self.root)
        window.withdraw()
        window.configure(bg=APP_BG)
        window.title(title)
        window.transient(self.root)
        window.geometry("760x420")
        set_window_icon(window)

        frame = ttk.Frame(window, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        log_container, log_text = create_dark_scrolled_text(
            frame,
            show_horizontal=True,
            wrap=tk.NONE,
            height=18,
            font=("Consolas", 10),
            undo=False,
        )
        log_container.grid(row=0, column=0, sticky=(tk.N, tk.S, tk.E, tk.W))
        log_text.configure(state=tk.DISABLED)

        button_row = ttk.Frame(frame)
        button_row.grid(row=1, column=0, sticky=tk.E, pady=(8, 0))
        ok_btn = ttk.Button(button_row, text="OK", command=window.destroy, state=tk.DISABLED, width=10)
        ok_btn.pack(side=tk.RIGHT)
        action_btn = ttk.Button(button_row, text="", state=tk.DISABLED, width=12)
        action_btn.pack(side=tk.RIGHT, padx=(0, 8))
        action_btn.pack_forget()
        progress = ttk.Progressbar(button_row, mode="indeterminate", length=180)
        progress.pack(side=tk.RIGHT, padx=(0, 8))
        apply_button_outline(window)

        def run_on_ui(callback):
            try:
                if threading.current_thread() is threading.main_thread():
                    callback()
                else:
                    self.root.after(0, callback)
            except Exception:
                pass

        def append(text):
            def do_append():
                if not window.winfo_exists():
                    return
                log_text.configure(state=tk.NORMAL)
                log_text.insert(tk.END, text)
                log_text.see(tk.END)
                log_text.configure(state=tk.DISABLED)

            run_on_ui(do_append)

        def start():
            def do_start():
                if not window.winfo_exists():
                    return
                ok_btn.config(state=tk.DISABLED)
                action_btn.config(state=tk.DISABLED)
                progress.start(12)
                set_dark_title_bar(window)

            run_on_ui(do_start)

        def finish():
            def do_finish():
                if not window.winfo_exists():
                    return
                progress.stop()
                ok_btn.config(state=tk.NORMAL)
                window.lift()
                window.focus_force()
                set_dark_title_bar(window)

            run_on_ui(do_finish)

        def set_action(text=None, command=None):
            def do_set_action():
                if not window.winfo_exists():
                    return
                if text and command:
                    action_btn.config(text=text, command=command, state=tk.NORMAL)
                    if not action_btn.winfo_ismapped():
                        action_btn.pack(side=tk.RIGHT, padx=(0, 8), before=ok_btn)
                else:
                    action_btn.config(text="", command=lambda: None, state=tk.DISABLED)
                    action_btn.pack_forget()

            run_on_ui(do_set_action)

        window.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - window.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - window.winfo_height()) // 2
        window.geometry(f"+{max(0, x)}+{max(0, y)}")
        window.deiconify()
        window.lift()
        window.after(10, lambda: set_dark_title_bar(window))
        window.after(250, lambda: set_dark_title_bar(window))
        return window, append, start, finish, set_action

    def _start_iso_build_in_log(self, source_dir, log, start_log, finish_log, set_action=None):
        if not source_dir:
            initial_input = self.last_extract_dir or self.current_bundle_dir or os.path.expanduser("~")
            source_dir = _dialog(
                self.root,
                filedialog.askdirectory,
                title="Select Folder to Pack into ISO",
                initialdir=initial_input,
            )
            if not source_dir:
                return

        base_name = os.path.basename(os.path.normpath(source_dir)) or "new_image"
        output_path = _dialog(
            self.root,
            filedialog.asksaveasfilename,
            title="Save ISO As",
            initialdir=os.path.dirname(source_dir) or self.current_bundle_dir or os.path.expanduser("~"),
            initialfile=f"{base_name}.iso",
            defaultextension=".iso",
            filetypes=[("ISO Images", "*.iso"), ("All Files", "*.*")],
            confirmoverwrite=False,
        )
        if not output_path:
            return

        if os.path.exists(output_path):
            overwrite = messagebox.askyesno(
                "Overwrite ISO?",
                f"{os.path.basename(output_path)} already exists in the output folder.\n\nOverwrite it?"
            )
            if not overwrite:
                return

        if set_action:
            set_action()
        start_log()
        log("\n=== Build ISO ===\n")
        log(f"Building ISO from folder:\n  {source_dir}\n")
        log("Data Type: MODE1/2048\n")
        log("File System: ISO9660 + UDF VRS\n")
        log(f"Output:\n  {output_path}\n\n")

        def worker():
            try:
                result = build_iso_from_directory(source_dir, output_path, log)
            except Exception as e:
                import traceback
                traceback.print_exc()

                def fail(e=e):
                    log(f"\nError creating ISO image: {e}\n")
                    finish_log()
                    messagebox.showerror("Error", f"Failed to create ISO image:\n{e}")

                self.root.after(0, fail)
                return

            def succeed(result=result):
                finish_log()
                messagebox.showinfo(
                    "Success",
                    "ISO image created successfully!\n\n"
                    f"Output: {result['path']}\n"
                    f"Data Type: {result['data_type']}\n"
                    f"File System: {result['filesystem']}\n"
                    f"Files: {result['file_count']}"
                )

            self.root.after(0, succeed)

        threading.Thread(target=worker, daemon=True).start()

    def build_vol_bundle(self):
        """Build a VOL bundle directly from a folder."""
        initial_input = self.last_extract_dir or self.current_bundle_dir or os.path.expanduser("~")
        source_dir = _dialog(
            self.root,
            filedialog.askdirectory,
            title="Select Folder to Pack into VOL",
            initialdir=initial_input,
        )
        if not source_dir:
            return

        output_dir = _dialog(
            self.root,
            filedialog.askdirectory,
            title="Select Output Folder for VOL",
            initialdir=os.path.dirname(source_dir) or self.current_bundle_dir or os.path.expanduser("~"),
        )
        if not output_dir:
            return

        base_name = os.path.basename(os.path.normpath(source_dir)) or "new_bundle"
        output_path = os.path.join(output_dir, f"{base_name}.vol")

        if os.path.exists(output_path):
            overwrite = messagebox.askyesno(
                "Overwrite VOL?",
                f"{os.path.basename(output_path)} already exists in the output folder.\n\nOverwrite it?"
            )
            if not overwrite:
                return

        _log_window, log, start_log, finish_log, set_action = self._open_build_log_window("Build VOL")
        start_log()
        log(f"Building VOL from folder:\n  {source_dir}\n")
        log(f"Output:\n  {output_path}\n\n")

        def worker():
            try:
                result = build_vol_from_directory(source_dir, output_path, log)
            except Exception as e:
                import traceback
                traceback.print_exc()

                def fail(e=e):
                    log(f"\nError creating VOL bundle: {e}\n")
                    finish_log()
                    messagebox.showerror("Error", f"Failed to create VOL bundle:\n{e}")

                self.root.after(0, fail)
                return

            def succeed(result=result):
                finish_log()
                set_action(
                    "ISO",
                    lambda: self._start_iso_build_in_log(None, log, start_log, finish_log, set_action)
                )
                messagebox.showinfo(
                    "Success",
                    "VOL bundle created successfully!\n\n"
                    f"Output: {result['path']}\n"
                    f"Files: {result['file_count']}"
                )

            self.root.after(0, succeed)

        threading.Thread(target=worker, daemon=True).start()

    def build_iso_image(self):
        """Build a MODE1/2048 ISO9660 image directly from a folder."""
        initial_input = self.last_extract_dir or self.current_bundle_dir or os.path.expanduser("~")
        source_dir = _dialog(
            self.root,
            filedialog.askdirectory,
            title="Select Folder to Pack into ISO",
            initialdir=initial_input,
        )
        if not source_dir:
            return

        base_name = os.path.basename(os.path.normpath(source_dir)) or "new_image"
        output_path = _dialog(
            self.root,
            filedialog.asksaveasfilename,
            title="Save ISO As",
            initialdir=os.path.dirname(source_dir) or self.current_bundle_dir or os.path.expanduser("~"),
            initialfile=f"{base_name}.iso",
            defaultextension=".iso",
            filetypes=[("ISO Images", "*.iso"), ("All Files", "*.*")],
            confirmoverwrite=False,
        )
        if not output_path:
            return

        if os.path.exists(output_path):
            overwrite = messagebox.askyesno(
                "Overwrite ISO?",
                f"{os.path.basename(output_path)} already exists in the output folder.\n\nOverwrite it?"
            )
            if not overwrite:
                return

        _log_window, log, start_log, finish_log, set_action = self._open_build_log_window("Build ISO")
        start_log()
        log(f"Building ISO from folder:\n  {source_dir}\n")
        log("Data Type: MODE1/2048\n")
        log("File System: ISO9660 + UDF VRS\n")
        log(f"Output:\n  {output_path}\n\n")

        def worker():
            try:
                result = build_iso_from_directory(source_dir, output_path, log)
            except Exception as e:
                import traceback
                traceback.print_exc()

                def fail(e=e):
                    log(f"\nError creating ISO image: {e}\n")
                    finish_log()
                    messagebox.showerror("Error", f"Failed to create ISO image:\n{e}")

                self.root.after(0, fail)
                return

            def succeed(result=result):
                finish_log()
                messagebox.showinfo(
                    "Success",
                    "ISO image created successfully!\n\n"
                    f"Output: {result['path']}\n"
                    f"Data Type: {result['data_type']}\n"
                    f"File System: {result['filesystem']}\n"
                    f"Files: {result['file_count']}"
                )

            self.root.after(0, succeed)

        threading.Thread(target=worker, daemon=True).start()

    def rebuild_bdg(self):
        """Open rebuild window"""
        if self.texture_preview_session:
            return

        if self.text_mode:
            self.save_text_editor_file()
            return

        if not self.parsed_files or not self.parser:
            messagebox.showwarning("No Data", "Please parse a bundle first.")
            return

        # Create callback for window to update main output
        def output_callback(text):
            self.output_text.insert(tk.END, text)

        window = RebuildWindow(self.root, self.parsed_files, self.parser, output_callback,
                               bulk_bundles=self.bundle_files if self.bundle_files else None,
                               last_extract_dir=self.last_extract_dir,
                               zip_source=self._current_zip_source)

        self.child_windows.append(window.window)

        # Remove from list when window is closed
        def on_window_close():
            if window.window in self.child_windows:
                self.child_windows.remove(window.window)
            window.destroy()

        window.window.protocol("WM_DELETE_WINDOW", on_window_close)

    def on_main_window_close(self):
        """Close all child windows when main window closes"""
        for window in self.child_windows[:]:
            try:
                window.destroy()
            except:
                pass
        # Clean up app-owned temp files so previews and rebuild scratch data do not accumulate.
        self._cleanup_zip_temps()
        clear_app_temp_contents()
        self.root.destroy()


def main():
    ensure_app_dirs()
    append_app_log("GZBuildr started")
    set_windows_app_identity()
    settings = load_app_settings()
    theme_mode = settings.get("theme_mode", "dark")
    set_theme_palette(theme_mode)

    # Use TkinterDnD.Tk if available for drag-and-drop support
    if HAS_DND:
        root = TkinterDnD.Tk()
    elif HAS_TTKBOOTSTRAP:
        root = ttkbootstrap.Window(themename=APP_THEME)
    else:
        root = tk.Tk()

    configure_app_theme(root, theme_mode)
    app = PipeworksGUI(root)
    set_window_icon(root)
    root.mainloop()


if __name__ == "__main__":
    main()
