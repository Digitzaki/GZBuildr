#!/usr/bin/env python3
from __future__ import annotations

import re
import shutil
import struct
import sys
import importlib.util
from datetime import datetime
from pathlib import Path
from tkinter import Tk, filedialog


def app_dir() -> Path:
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


TOOL_DIR = app_dir()
ROOT = TOOL_DIR.parent
BACKUP_ROOT = ROOT / "backups"
ROW_RE = re.compile(r"^@0x([0-9A-Fa-f]+)\s+([a-zA-Z0-9_]+)\s+(.+?)\s+=\s+(.*)$")


def bundled_dir() -> Path | None:
    raw = getattr(sys, "_MEIPASS", None)
    return Path(raw) if raw else None


def first_existing(paths: list[Path]) -> Path | None:
    return next((path for path in paths if path.exists()), None)


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value or (default or "")


def pick_open_file(title: str, filetypes: list[tuple[str, str]], initialdir: Path | None = None) -> Path:
    root = Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        selected = filedialog.askopenfilename(
            title=title,
            initialdir=str(initialdir or ROOT),
            filetypes=filetypes,
        )
    finally:
        root.destroy()
    if not selected:
        raise SystemExit("No file selected.")
    return Path(selected)


def pick_save_file(title: str, default_name: str, filetypes: list[tuple[str, str]]) -> Path:
    root = Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    try:
        selected = filedialog.asksaveasfilename(
            title=title,
            initialdir=str(ROOT),
            initialfile=default_name,
            defaultextension=".txt",
            filetypes=filetypes,
        )
    finally:
        root.destroy()
    if not selected:
        raise SystemExit("No output file selected.")
    return Path(selected)


def load_helpers():
    meipass = bundled_dir()
    bdg_candidates = [
        TOOL_DIR / "light_bdg.py",
        ROOT / "PRX_Tools" / "light_bdg.py",
    ]
    pve_candidates = [
        TOOL_DIR / "prx_value_editor.py",
        ROOT / "PRX_Tools" / "prx_value_editor.py",
    ]
    if meipass is not None:
        bdg_candidates[:0] = [
            meipass / "light_bdg.py",
            meipass / "PRX_Tools" / "light_bdg.py",
        ]
        pve_candidates[:0] = [
            meipass / "prx_value_editor.py",
            meipass / "PRX_Tools" / "prx_value_editor.py",
        ]

    bdg_path = first_existing(bdg_candidates)
    pve_path = first_existing(pve_candidates)
    if bdg_path is None:
        searched = "\n  ".join(str(path) for path in bdg_candidates)
        raise ModuleNotFoundError(f"Could not find light_bdg.py. Searched:\n  {searched}")
    if pve_path is None:
        searched = "\n  ".join(str(path) for path in pve_candidates)
        raise ModuleNotFoundError(f"Could not find prx_value_editor.py. Searched:\n  {searched}")

    bdg_spec = importlib.util.spec_from_file_location("light_bdg", bdg_path)
    if bdg_spec is None or bdg_spec.loader is None:
        raise ImportError(f"Could not load {bdg_path}")
    light_bdg = importlib.util.module_from_spec(bdg_spec)
    sys.modules["light_bdg"] = light_bdg
    bdg_spec.loader.exec_module(light_bdg)

    pve_spec = importlib.util.spec_from_file_location("prx_value_editor", pve_path)
    if pve_spec is None or pve_spec.loader is None:
        raise ImportError(f"Could not load {pve_path}")
    pve = importlib.util.module_from_spec(pve_spec)
    sys.modules["prx_value_editor"] = pve
    pve_spec.loader.exec_module(pve)

    return light_bdg, pve


def read_bundle(bundle_path: Path):
    light_bdg, pve = load_helpers()
    data = bytearray(bundle_path.read_bytes())
    parser = light_bdg.PipeworksParser(str(bundle_path))
    entries = parser.parse_from_data(bytes(data))
    strings = pve.read_strings(bytes(data), parser.string_offset)
    prxs = [entry for entry in entries if str(entry.get("name", "")).lower().endswith(".prx")]
    if not prxs:
        raise RuntimeError(f"No PRX files found in {bundle_path}")
    return data, parser, entries, strings, prxs, pve


def choose_bundle() -> Path:
    path = pick_open_file(
        "Select a BDG bundle containing PRX data",
        [("BDG bundles", "*.bdg *.BDG"), ("All files", "*.*")],
        ROOT / "DATA" / "files" / "Game",
    )
    if not path.exists():
        raise FileNotFoundError(path)
    print(f"Selected BDG: {path}")
    return path


def choose_prx(prxs: list[dict]) -> dict:
    print("\nPRX files:")
    for idx, entry in enumerate(prxs, start=1):
        print(f"  {idx}. {entry['name']}  size=0x{int(entry['size']):X}")
    raw = ask("PRX number or exact name", "1")
    if raw.isdigit():
        idx = int(raw)
        if not (1 <= idx <= len(prxs)):
            raise ValueError("PRX number out of range")
        return prxs[idx - 1]
    match = next((entry for entry in prxs if str(entry["name"]).lower() == raw.lower()), None)
    if match is None:
        raise ValueError(f"Unknown PRX: {raw}")
    return match


def row_value_text(row, strings: list[str]) -> str:
    value = row.value(strings)
    if isinstance(value, float):
        return repr(float(value))
    return str(value)


def export_txt() -> None:
    bundle_path = choose_bundle()
    data, _parser, _entries, strings, prxs, pve = read_bundle(bundle_path)
    prx_entry = choose_prx(prxs)
    _prx, rows, roots = pve.parse_rows(data, prx_entry, strings)

    default_out = f"{Path(str(prx_entry['name'])).stem}_values.txt"
    out_path = pick_save_file(
        "Save PRX text dump",
        default_out,
        [("Text files", "*.txt"), ("All files", "*.*")],
    )

    lines: list[str] = [
        "# PRX text export",
        f"# SourceBDG={bundle_path}",
        f"# PRX={prx_entry['name']}",
        f"# PRXOffset=0x{int(prx_entry['offset']):X}",
        f"# PRXSize=0x{int(prx_entry['size']):X}",
        "# Edit values after '=' on @ rows, then run import mode.",
        "# Ref rows are listed for context and are not imported.",
        "",
    ]
    lines.extend(pve.prx_root_toc_lines(roots, rows))
    lines.extend(pve.prx_rows_text_lines(rows, strings))
    lines.append("")
    lines.append(f"# Total rows: {len(pve.display_rows_by_offset(rows))}")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"\nWrote {out_path}")


def metadata_from_txt(txt_path: Path) -> dict[str, str]:
    meta: dict[str, str] = {}
    for line in txt_path.read_text(encoding="utf-8").splitlines():
        if not line.startswith("#"):
            continue
        body = line[1:].strip()
        if "=" in body:
            key, value = body.split("=", 1)
            meta[key.strip()] = value.strip()
    return meta


def parse_import_value(row, value: str, strings: list[str], pve) -> int:
    value = value.strip()
    if row.type_id == pve.TYPE_FLOAT:
        return struct.unpack(">I", struct.pack(">f", float(value)))[0]
    if row.type_id in (pve.TYPE_INT, pve.TYPE_INT_ALT, pve.TYPE_FLOAT_ALT):
        return int(value, 0)
    if row.type_id == pve.TYPE_STRING:
        if value in strings:
            return strings.index(value)
        return int(value, 0)
    raise ValueError(f"Refusing to import non-editable row type {row.type_name}")


def import_txt() -> None:
    txt_path = pick_open_file(
        "Select edited PRX txt file",
        [("Text files", "*.txt"), ("All files", "*.*")],
        ROOT,
    )
    if not txt_path.exists():
        raise FileNotFoundError(txt_path)
    print(f"Selected txt: {txt_path}")

    meta = metadata_from_txt(txt_path)
    bundle_meta = meta.get("SourceBDG")
    bundle_path = Path(bundle_meta) if bundle_meta else Path()
    if not bundle_meta or not bundle_path.exists():
        print("Source BDG from the txt was missing or not found. Pick the BDG to update.")
        bundle_path = pick_open_file(
            "Select BDG bundle to update",
            [("BDG bundles", "*.bdg *.BDG"), ("All files", "*.*")],
            ROOT / "DATA" / "files" / "Game",
        )
    print(f"Target BDG: {bundle_path}")

    data, _parser, _entries, strings, prxs, pve = read_bundle(bundle_path)
    prx_name = meta.get("PRX")
    if prx_name:
        prx_entry = next((entry for entry in prxs if entry["name"] == prx_name), None)
        if prx_entry is None:
            raise RuntimeError(f"{prx_name} not found in {bundle_path}")
    else:
        prx_entry = choose_prx(prxs)

    prx, rows, _roots = pve.parse_rows(data, prx_entry, strings)
    rows_by_off: dict[int, object] = {}
    aliases_by_off: dict[int, list[str]] = {}
    for row in rows:
        rows_by_off.setdefault(row.row_offset, row)
        aliases_by_off.setdefault(row.row_offset, []).append(row.key)

    wanted_by_off: dict[int, tuple[object, int, str, str]] = {}
    conflicts: list[str] = []

    for line in txt_path.read_text(encoding="utf-8").splitlines():
        match = ROW_RE.match(line.strip())
        if not match:
            continue
        row_off = int(match.group(1), 16)
        type_name = match.group(2)
        value_text = match.group(4).strip()
        row = rows_by_off.get(row_off)
        if row is None or row.type_name != type_name:
            continue
        if row.type_id not in pve.EDITABLE_TYPES:
            continue
        old = row.value(strings)
        new_raw = parse_import_value(row, value_text, strings, pve)
        new_raw &= 0xFFFFFFFF
        if new_raw == row.value_raw:
            continue

        previous = wanted_by_off.get(row.row_offset)
        if previous is not None and previous[1] != new_raw:
            aliases = ", ".join(sorted(set(aliases_by_off.get(row.row_offset, []))))
            conflicts.append(
                f"@0x{row.row_offset:04X} has multiple edited values "
                f"({previous[3]} vs {value_text}). Aliases: {aliases}"
            )
            continue
        wanted_by_off[row.row_offset] = (row, new_raw, str(old), value_text)

    if conflicts:
        joined = "\n  ".join(conflicts)
        raise RuntimeError(f"Conflicting duplicate-offset edits found:\n  {joined}")

    changes: list[tuple[str, object, str]] = []
    for row_off, (row, new_raw, old, value_text) in sorted(wanted_by_off.items()):
        pve.put_u32(prx, row.row_offset + 4, new_raw)
        changes.append((row.key, old, value_text))

    if not changes:
        print("No changed editable values found.")
        return

    backup_dir = BACKUP_ROOT / f"prx_txt_import_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    backup_dir.mkdir(parents=True, exist_ok=True)
    backup = backup_dir / bundle_path.name
    shutil.copy2(bundle_path, backup)

    start = int(prx_entry["offset"])
    size = int(prx_entry["size"])
    if len(prx) != size:
        raise RuntimeError("Refusing to write a changed-size PRX")
    data[start : start + size] = prx
    bundle_path.write_bytes(data)

    print(f"\nApplied {len(changes)} changed values.")
    for key, old, new in changes[:40]:
        print(f"  {key}: {old} -> {new}")
    if len(changes) > 40:
        print(f"  ... {len(changes) - 40} more")
    print(f"Backup: {backup}")


def main() -> int:
    print("PRX TXT Tool")
    print("1. Export PRX to txt")
    print("2. Import txt back into PRX")
    choice = ask("Choose mode", "1")
    if choice == "1":
        export_txt()
    elif choice == "2":
        import_txt()
    else:
        raise ValueError("Choose 1 or 2")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
