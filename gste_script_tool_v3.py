#!/usr/bin/env python3
"""
Godzilla STE Script Tool - Python v3

- BSF -> TXT decompile for PPTokenStream 1.03
- TXT -> BSF compile from readable script text
- Exact rebuild still works when # raw_hex_begin is present and --exact is used

Notes:
This implements the observed STE token-stream format:
  header: b"Compiled PPTokenStream version 1.03.\x1a\x00\x00\x00"
  u32 total_size
  u32 zero
  u32 source_name_string_offset
  token stream begins at 0x34
  string/symbol refs are absolute file offsets
  0x26 = string literal ref, 0x27 = float32, 0x28 = symbol ref
  0xFE xx / 0xFF xx = compiler/source metadata markers, not emitted as source text
  0xFD = end of token stream
"""
from __future__ import annotations

import argparse
import re
import struct
from pathlib import Path

HEADER = b"Compiled PPTokenStream version 1.03.\x1a\x00\x00\x00"
CODE_START = 52
DEFAULT_SOURCE_NAME = "game.scr"

OP = {
    0x00: "==", 0x01: "!=", 0x02: "*", 0x03: "+", 0x04: "-", 0x05: "/", 0x06: "%",
    0x07: "&", 0x08: "~", 0x09: "|", 0x0A: "^", 0x0B: "&&", 0x0C: "||", 0x0D: "!",
    0x0E: "<<", 0x0F: ">>", 0x10: "<", 0x11: ">", 0x12: ">=", 0x13: "<=", 0x14: "=",
    0x15: "(", 0x16: ")", 0x17: "{", 0x18: "}", 0x19: "[", 0x1A: "]", 0x1B: ",",
    0x1C: ";", 0x1D: ".", 0x1E: "::", 0x1F: "++", 0x20: "--",
    0x21: "++", 0x22: "++", 0x23: "do", 0x24: "switch", 0x25: "case",
    0x2C: "for", 0x2D: "if", 0x2E: "else", 0x2F: "return", 0x30: "break", 0x31: "enum",
    0x32: "continue", 0x33: "struct", 0x34: "class",
}
REV_OP = {v: k for k, v in OP.items()}
# prefer normal prefix/postfix encodings for ++/--
REV_OP["++"] = 0x1F
REV_OP["--"] = 0x20
KEYWORD_OPS = {"do", "switch", "case", "for", "if", "else", "return", "break", "enum", "continue", "struct", "class"}
BINARY_OPS = {"==", "!=", "*", "+", "-", "/", "%", "&", "|", "^", "&&", "||", "<<", ">>", "<", ">", ">=", "<=", "="}
PREFIX_OPS = {"!", "~"}
POSTFIX_OPS = {"++", "--"}

MULTI_OPS = sorted([op for op in REV_OP if len(op) > 1 and not op.isalpha()], key=len, reverse=True)
SINGLE_OPS = set("(){}[],;.+-*/%&~|^!<>=")


def c_string(data: bytes, off: int) -> str:
    end = data.find(b"\x00", off)
    if end < 0:
        end = len(data)
    return data[off:end].decode("latin-1", errors="replace")


def is_string_ptr(data: bytes, off: int) -> bool:
    if not (0 <= off < len(data)):
        return False
    end = data.find(b"\x00", off)
    if end < 0 or end == off:
        return False
    s = data[off:end]
    return all((32 <= x <= 126) or x in (9, 10, 13) for x in s)


def find_string_table_start(data: bytes) -> int:
    ptrs = []
    for i in range(CODE_START, len(data) - 4):
        if data[i] in (0x26, 0x28):
            val = struct.unpack_from("<I", data, i + 1)[0]
            if val > CODE_START and is_string_ptr(data, val):
                ptrs.append(val)
    return min(ptrs) if ptrs else len(data)


def read_tokens(data: bytes):
    if not data.startswith(HEADER):
        raise ValueError("Not a PPTokenStream 1.03 BSF, or header is different.")
    string_start = find_string_table_start(data)
    i = CODE_START
    tokens = []
    unknown = []
    while i < string_start:
        off = i
        op = data[i]
        i += 1
        if op == 0x28:
            ptr = struct.unpack_from("<I", data, i)[0]; i += 4
            tokens.append(("sym", c_string(data, ptr), off))
        elif op == 0x26:
            ptr = struct.unpack_from("<I", data, i)[0]; i += 4
            tokens.append(("str", c_string(data, ptr), off))
        elif op == 0x27:
            val = struct.unpack_from("<f", data, i)[0]; i += 4
            tokens.append(("num", val, off))
        elif op in (0xFE, 0xFF):
            # The old STE tool drops this marker and the following metadata byte.
            # If we treat the metadata byte as an opcode, decompiled source gets
            # bogus +/*/!= tokens around declarations and array accesses.
            if i < string_start:
                i += 1
        elif op == 0xFD:
            tokens.append(("end", "", off))
            break
        else:
            text = OP.get(op)
            if text is None:
                text = f"[Unimplemented: 0x{op:02X}]"
                unknown.append((off, op))
            tokens.append(("op", text, off))
    return tokens, string_start, unknown


def quote_string(s: str) -> str:
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def format_number(x: float) -> str:
    if abs(x) < 0.0000005:
        x = 0.0
    return f"{x:.6f}"


def token_text(tok) -> str:
    kind, val, _ = tok
    if kind == "sym": return val
    if kind == "str": return quote_string(val)
    if kind == "num": return format_number(val)
    return val


def append_token(line: str, tok: str) -> str:
    if not line: return tok
    if tok in {"(", "["}: return line + tok
    if tok in {")", "]"}: return line.rstrip() + tok
    if tok == ".": return line.rstrip() + "."
    if tok == "::": return line.rstrip() + "::"
    if tok == ",": return line.rstrip() + ", "
    if tok in BINARY_OPS: return line.rstrip() + f" {tok} "
    if tok in PREFIX_OPS: return line + tok
    if tok in POSTFIX_OPS: return line.rstrip() + tok
    if line.endswith((".", "::", "(", "[")): return line + tok
    return line.rstrip() + " " + tok


def format_source(tokens) -> str:
    lines=[]; indent=0; line=""
    def emit(text=""):
        if text.strip(): lines.append("\t"*indent + text.rstrip())
    for tok in tokens:
        if tok[0] == "end": break
        text=token_text(tok)
        if text == "{":
            if line.strip():
                emit(line.rstrip()+" "); lines[-1]+="{" 
            else: emit("{")
            line=""; indent+=1; continue
        if text == "}":
            if line.strip(): emit(line); line=""
            indent=max(0,indent-1); emit("}"); continue
        if text == ";": emit(line.rstrip()+";"); line=""; continue
        if text == "else":
            if line.strip(): emit(line); line=""
            line="else"; continue
        if text in {"if","for","return"} and line.strip() and text != "return":
            emit(line); line=""
        line=append_token(line,text)
    if line.strip(): emit(line)
    out=[]; i=0
    while i<len(lines):
        if i+1<len(lines) and lines[i].lstrip()=="}" and lines[i+1].lstrip().startswith("else"):
            pref=lines[i][:len(lines[i])-len(lines[i].lstrip())]
            out.append(pref+"} "+lines[i+1].lstrip()); i+=2
        else:
            out.append(lines[i]); i+=1
    return "\n".join(out)+"\n"


def decompile_bsf(path: Path, out: Path|None=None, include_raw=False) -> Path:
    data=path.read_bytes(); tokens,string_start,unknown=read_tokens(data)
    src=format_source(tokens)
    out=out or path.with_suffix('.txt')
    lines=[]
    lines.append(src.rstrip('\n'))
    if include_raw:
        lines += ["", "# raw_hex_begin"]
        hx=data.hex(' ')
        for n in range(0,len(hx),240): lines.append('# '+hx[n:n+240])
        lines.append('# raw_hex_end')
    out.write_text("\n".join(lines)+"\n",encoding='utf-8',newline='\n')
    if unknown:
        print(f"Warning: {len(unknown)} unknown opcodes")
    return out


def strip_tool_comments(text: str) -> str:
    lines=[]; in_raw=False
    for ln in text.splitlines():
        if ln.strip()=="# raw_hex_begin": in_raw=True; continue
        if ln.strip()=="# raw_hex_end": in_raw=False; continue
        if in_raw: continue
        if ln.lstrip().startswith('#'): continue
        lines.append(ln)
    return "\n".join(lines)


def lex_source(text: str):
    text = strip_tool_comments(text)
    out=[]; i=0; n=len(text)
    while i<n:
        c=text[i]
        if c.isspace(): i+=1; continue
        # C++ comments
        if text.startswith('//', i):
            j=text.find('\n', i); i=n if j<0 else j+1; continue
        if text.startswith('/*', i):
            j=text.find('*/', i+2); i=n if j<0 else j+2; continue
        if c=='"':
            i+=1; s=[]
            while i<n:
                ch=text[i]; i+=1
                if ch=='\\' and i<n:
                    esc=text[i]; i+=1
                    maps={'n':'\n','r':'\r','t':'\t','\\':'\\','"':'"','0':'\0'}
                    s.append(maps.get(esc, esc))
                elif ch=='"': break
                else: s.append(ch)
            out.append(('str',''.join(s))); continue
        # number: only positive here; unary minus is an op in original output
        if c.isdigit() or (c=='.' and i+1<n and text[i+1].isdigit()):
            m=re.match(r'(?:\d+\.\d*|\d*\.\d+|\d+)(?:[eE][+-]?\d+)?', text[i:])
            if m:
                out.append(('num', float(m.group(0)))); i+=len(m.group(0)); continue
        if c.isalpha() or c=='_':
            m=re.match(r'[A-Za-z_][A-Za-z0-9_?]*', text[i:])
            val=m.group(0); i+=len(val)
            if val in KEYWORD_OPS: out.append(('op', val))
            else: out.append(('sym', val))
            continue
        matched=False
        for op in MULTI_OPS:
            if text.startswith(op, i):
                out.append(('op', op)); i+=len(op); matched=True; break
        if matched: continue
        if c in SINGLE_OPS:
            out.append(('op', c)); i+=1; continue
        raise SyntaxError(f"Unexpected character at {i}: {c!r}")
    return out


def compile_tokens(lexed, source_name=DEFAULT_SOURCE_NAME) -> bytes:
    # Build code with placeholders while collecting strings in first-reference order.
    strings=[]; index={}
    placeholders=[]
    code=bytearray()
    def need_string(s):
        if s not in index:
            index[s]=len(strings); strings.append(s)
        return index[s]
    for ti, (kind,val) in enumerate(lexed):
        if kind=='sym':
            idx=need_string(val); code.append(0x28); placeholders.append((len(code), idx)); code += b'\0\0\0\0'
        elif kind=='str':
            idx=need_string(val); code.append(0x26); placeholders.append((len(code), idx)); code += b'\0\0\0\0'
        elif kind=='num':
            code.append(0x27); code += struct.pack('<f', float(val))
        elif kind=='op':
            if val not in REV_OP: raise ValueError(f'No opcode for operator/keyword {val!r}')
            opcode = REV_OP[val]
            if val in ('++', '--'):
                # PPTokenStream has separate prefix/postfix encodings.
                # Shipped scripts use 0x22 for postfix ++.
                prev_kind = lexed[ti-1][0] if ti > 0 else None
                next_val = lexed[ti+1][1] if ti + 1 < len(lexed) else None
                if prev_kind in ('sym', 'num', 'str') or next_val in (')', ']', ';', ','):
                    opcode = 0x22 if val == '++' else 0x20
                else:
                    opcode = 0x1F if val == '++' else 0x20
            code.append(opcode)
        else: raise ValueError(kind)
    code.append(0xFD)
    # source filename is usually unreferenced but header points at it.
    if source_name not in index:
        source_idx=len(strings); strings.append(source_name)
    else:
        source_idx=index[source_name]
    string_start=CODE_START+len(code)
    offsets=[]; pos=string_start
    table=bytearray()
    for s in strings:
        offsets.append(pos)
        raw=s.encode('latin-1', errors='replace')+b'\0'
        table += raw; pos += len(raw)
    # original files have three trailing zero bytes after game.scr\0
    table += b'\0\0'
    for at,idx in placeholders:
        struct.pack_into('<I', code, at, offsets[idx])
    total=CODE_START+len(code)+len(table)
    source_ptr=offsets[source_idx]
    return HEADER + struct.pack('<III', total, 0, source_ptr) + bytes(code) + bytes(table)


def compile_txt(path: Path, out: Path|None=None, source_name=DEFAULT_SOURCE_NAME) -> Path:
    text=path.read_text(encoding='utf-8',errors='replace')
    lexed=lex_source(text)
    data=compile_tokens(lexed, source_name=source_name)
    out=out or path.with_suffix('.bsf')
    out.write_bytes(data)
    return out


def rebuild_exact_from_txt(path: Path, out: Path|None=None) -> Path:
    text=path.read_text(encoding='utf-8',errors='replace')
    lines=text.splitlines(); a=lines.index('# raw_hex_begin')+1; b=lines.index('# raw_hex_end')
    hx=''.join(ln[1:].strip().replace(' ','') for ln in lines[a:b] if ln.startswith('#'))
    data=bytes.fromhex(hx); out=out or path.with_suffix('.bsf'); out.write_bytes(data); return out


def choose_default() -> Path:
    for name in ('game.bsf','game.txt'):
        p=Path.cwd()/name
        if p.exists(): return p
    for pat in ('*.bsf','*.txt'):
        xs=sorted(Path.cwd().glob(pat))
        if xs: return xs[0]
    raise FileNotFoundError('No input given and no game.bsf/game.txt found.')


def main(argv=None):
    ap=argparse.ArgumentParser(description='Godzilla STE PPTokenStream 1.03 BSF TXT tool')
    ap.add_argument('input', nargs='?')
    ap.add_argument('-o','--output')
    ap.add_argument('--raw', action='store_true', help='include raw hex block when decompiling')
    ap.add_argument('--exact', action='store_true', help='for TXT input, rebuild from raw_hex block instead of compiling source')
    ap.add_argument('--source-name', default=DEFAULT_SOURCE_NAME)
    args=ap.parse_args(argv)
    inp=Path(args.input) if args.input else choose_default(); out=Path(args.output) if args.output else None
    if inp.suffix.lower()=='.bsf':
        made=decompile_bsf(inp,out,include_raw=args.raw); print(f'Wrote TXT: {made}')
    elif inp.suffix.lower()=='.txt':
        if args.exact:
            made=rebuild_exact_from_txt(inp,out); print(f'Rebuilt exact BSF: {made}')
        else:
            made=compile_txt(inp,out,source_name=args.source_name); print(f'Compiled BSF: {made}')
    else: raise ValueError('Input must be .bsf or .txt')

if __name__=='__main__': main()
