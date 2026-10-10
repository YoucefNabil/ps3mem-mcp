"""ps3mem: headless MCP server for reading/writing PS3 guest memory inside a running RPCS3.

Addresses are PS3 addresses (e.g. 0x33743dc4); values are big-endian like the console.
Anything >= 4 GiB is treated as a raw host address. Output is kept short on purpose.
Top Spin 4 helpers (ts4_*) sit on top of the generic tools.
"""
import ctypes, ctypes.wintypes as wt, json, os, re, struct, subprocess, difflib
from mcp.server.fastmcp import FastMCP

BASE = 0x300000000          # RPCS3 maps PS3 virtual memory here; _detect_base() reads the real one from the log
PS3_END = 0x100000000
HERE = os.path.dirname(os.path.abspath(__file__))

k32 = ctypes.WinDLL('kernel32', use_last_error=True)


class MBI(ctypes.Structure):
    _fields_ = [('BaseAddress', ctypes.c_void_p), ('AllocationBase', ctypes.c_void_p),
                ('AllocationProtect', wt.DWORD), ('PartitionId', wt.WORD),
                ('RegionSize', ctypes.c_size_t), ('State', wt.DWORD),
                ('Protect', wt.DWORD), ('Type', wt.DWORD)]


k32.OpenProcess.restype = wt.HANDLE
k32.VirtualQueryEx.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
k32.ReadProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_size_t)]
k32.WriteProcessMemory.argtypes = [wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                                   ctypes.POINTER(ctypes.c_size_t)]
k32.GetExitCodeProcess.argtypes = [wt.HANDLE, ctypes.POINTER(wt.DWORD)]

_proc = {'h': None, 'pid': None, 'name': 'rpcs3.exe'}


def _find_pid(name):
    out = subprocess.check_output(['tasklist', '/FI', f'IMAGENAME eq {name}', '/FO', 'CSV', '/NH'],
                                  text=True, errors='ignore')
    for line in out.splitlines():
        parts = [p.strip('"') for p in line.split('","')]
        if parts and parts[0].lower() == name.lower():
            return int(parts[1])
    return None


def _alive():
    if not _proc['h']:
        return False
    code = wt.DWORD()
    return bool(k32.GetExitCodeProcess(_proc['h'], ctypes.byref(code))) and code.value == 259


def H():
    if not _alive():
        pid = _find_pid(_proc['name'])
        if not pid:
            raise RuntimeError(f"{_proc['name']} is not running")
        h = k32.OpenProcess(0x1F0FFF, False, pid)
        if not h:
            raise RuntimeError(f'OpenProcess failed (error {ctypes.get_last_error()}); run as admin?')
        _proc.update(h=h, pid=pid)
        _ts4.clear()
        _detect_base()
    return _proc['h']


def _detect_base():
    """RPCS3 picks the guest memory base at startup (0x300000000, 0x500000000, ...); it logs it near the top."""
    global BASE
    try:
        with _open_shared(os.path.join(_rpcs3_dir(), 'log', 'RPCS3.log')) as fh:
            m = re.search(rb'vm::g_base_addr = ([0-9a-fA-F]+)', fh.read(0x100000))
        if m:
            BASE = int(m.group(1), 16)
    except OSError:
        pass


def host(a):
    a = int(a, 0) if isinstance(a, str) else int(a)
    return a + BASE if a < PS3_END else a


def guest(h):
    return h - BASE if BASE <= h < BASE + PS3_END else h


def rd(a, n):
    buf = ctypes.create_string_buffer(n)
    got = ctypes.c_size_t()
    if not k32.ReadProcessMemory(H(), ctypes.c_void_p(host(a)), buf, n, ctypes.byref(got)) or got.value != n:
        raise RuntimeError(f'cannot read {n} bytes at {guest(host(a)):#x}')
    return buf.raw


def wr(a, data):
    got = ctypes.c_size_t()
    if not k32.WriteProcessMemory(H(), ctypes.c_void_p(host(a)), data, len(data), ctypes.byref(got)):
        raise RuntimeError(f'cannot write at {guest(host(a)):#x}')


def regions(lo, hi):
    addr, m = lo, MBI()
    while addr < hi and k32.VirtualQueryEx(H(), ctypes.c_void_p(addr), ctypes.byref(m), ctypes.sizeof(m)):
        base = m.BaseAddress or 0
        if m.State == 0x1000 and m.Protect and not (m.Protect & 0x101):
            s, e = max(base, lo), min(base + m.RegionSize, hi)
            if e > s:
                yield s, e - s
        addr = base + m.RegionSize


TYPES = {'u8': 'B', 's8': 'b', 'u16': 'H', 's16': 'h', 'u32': 'I', 's32': 'i',
         'u64': 'Q', 's64': 'q', 'f32': 'f', 'f64': 'd'}


def _fmt(t):
    if t not in TYPES:
        raise ValueError(f'type must be one of {", ".join(TYPES)}, bytes, str')
    return '>' + TYPES[t]


def _show(v, t):
    if t.startswith('f'):
        return f'{v:g}'
    if t.startswith('u') and int(v) > 9:
        return f'{v} ({v:#x})'
    return str(v)


def _pack(value, t):
    if isinstance(value, str):
        value = float(value) if t.startswith('f') else int(value, 0)
    return struct.pack(_fmt(t), value)


def _pattern(pattern):
    """'30 2D ?? 2A' -> regex bytes"""
    out = b''
    for tok in pattern.replace(',', ' ').split():
        out += b'.' if tok in ('?', '??') else re.escape(bytes([int(tok, 16)]))
    return re.compile(out, re.S)


mcp = FastMCP('ps3mem', instructions=(
    'Read/write PS3 guest memory in a running RPCS3 (big-endian; addresses are PS3 addresses, '
    'host = RPCS3 base (0x300000000 or 0x500000000, read from RPCS3.log) + addr). Prefer these tools over ad-hoc ReadProcessMemory scripts. '
    'ts4_* tools understand the Top Spin 4 player roster.'))


@mcp.tool()
def attach(process: str = 'rpcs3.exe') -> str:
    """Attach (or re-attach) to the emulator process. Other tools attach automatically."""
    _proc.update(name=process, h=None)
    H()
    return f"attached to {process} pid {_proc['pid']}"


@mcp.tool()
def read(addr: str, type: str = 'u32', count: int = 1, stride: int = 0) -> str:
    """Read `count` values of `type` (u8/s8/u16/s16/u32/s32/u64/s64/f32/f64, big-endian) from PS3 `addr`,
    or type 'str' (C string, count = max length) / 'bytes' (hex, count = length).
    `stride` spaces the values (default = type size), e.g. one field across table rows."""
    a = host(addr)
    if type == 'str':
        return repr(rd(a, count if count > 1 else 64).split(b'\0')[0].decode('latin-1'))
    if type == 'bytes':
        return rd(a, count).hex(' ')
    f = _fmt(type)
    size = struct.calcsize(f)
    stride = stride or size
    if stride == size:
        raw = rd(a, size * count)
        vals = [struct.unpack_from(f, raw, i * size)[0] for i in range(count)]
    else:
        vals = [struct.unpack(f, rd(a + i * stride, size))[0] for i in range(count)]
    if count == 1:
        return _show(vals[0], type)
    return '\n'.join(f'{guest(a + i * stride):#x}: {_show(v, type)}' for i, v in enumerate(vals))


@mcp.tool()
def hexdump(addr: str, size: int = 0x100, words: bool = True) -> str:
    """Hex dump (max 0x1000 bytes). words=True groups big-endian u32s and shows printable ASCII."""
    size = min(size, 0x1000)
    a = host(addr)
    raw = rd(a, size)
    lines = []
    for o in range(0, size, 16):
        chunk = raw[o:o + 16]
        if words:
            hx = ' '.join(chunk[i:i + 4].hex() for i in range(0, len(chunk), 4))
        else:
            hx = chunk.hex(' ')
        asc = ''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)
        lines.append(f'{guest(a + o):08x}  {hx:<35}  {asc}')
    return '\n'.join(lines)


@mcp.tool()
def write(addr: str, value: str, type: str = 'u32', count: int = 1, stride: int = 0) -> str:
    """Write `value` as `type` at PS3 `addr` (repeated `count` times, every `stride` bytes).
    type 'bytes' takes hex ('00 00 00 63'), 'str' writes a NUL-terminated string. Returns old -> new."""
    a = host(addr)
    if type == 'bytes':
        data = bytes.fromhex(value.replace(' ', ''))
    elif type == 'str':
        data = value.encode('latin-1') + b'\0'
    else:
        data = _pack(value, type)
    stride = stride or len(data)
    old = rd(a, len(data))
    for i in range(count):
        wr(a + i * stride, data)
    return f'{guest(a):#x}: {old.hex()} -> {data.hex()}' + (f' (x{count}, stride {stride:#x})' if count > 1 else '')


@mcp.tool()
def struct_read(addr: str, fields: str) -> str:
    """Read named fields relative to `addr`. fields: 'serve:u32@0x48, name:str@0x24, hash:u32@0xB4'."""
    a = host(addr)
    out = []
    for spec in fields.split(','):
        name, rest = spec.strip().split(':')
        t, off = rest.split('@')
        out.append(f'{name}={read(str(guest(a + int(off, 0))), t.strip())}')
    return ', '.join(out)


_scan = {'addrs': [], 'type': None, 'vals': {}}


def _search(rx, lo, hi, align, limit):
    hits = []
    lo, hi = int(str(lo), 0), int(str(hi), 0) or PS3_END
    lo = lo + BASE if lo < PS3_END else lo
    hi = hi + BASE if hi <= PS3_END else hi          # end is exclusive, so PS3_END itself is a PS3 address
    for base, size in regions(lo, hi):
        for off in range(0, size, 0x1000000):
            n = min(0x1000000 + 64, size - off)
            try:
                buf = rd(base + off, n)
            except RuntimeError:
                continue
            for m in rx.finditer(buf):
                if m.start() >= 0x1000000:
                    break
                a = base + off + m.start()
                if align <= 1 or a % align == 0:
                    hits.append(a)
                    if len(hits) >= limit:
                        return hits
    return hits


_NP = {'u8': '>u1', 's8': '>i1', 'u16': '>u2', 's16': '>i2', 'u32': '>u4', 's32': '>i4',
       'u64': '>u8', 's64': '>i8', 'f32': '>f4', 'f64': '>f8'}


def _num(x, t):
    return float(x) if t.startswith('f') else int(x, 0)


def _range_scan(value, t, start, end, limit, show):
    import numpy as np
    lo, hi = (_num(x.strip(), t) for x in value.split('..', 1))
    dt = np.dtype(_NP[t])
    size = dt.itemsize
    a0, a1 = int(str(start), 0), int(str(end), 0) or PS3_END
    a0 = a0 + BASE if a0 < PS3_END else a0
    a1 = a1 + BASE if a1 <= PS3_END else a1
    hits, vals = [], {}
    for base, rsize in regions(a0, a1):
        for off in range(0, rsize, 0x1000000):
            n = min(0x1000000, rsize - off)
            a = base + off
            skip = (-a) % size
            try:
                buf = rd(a, n)
            except RuntimeError:
                continue
            arr = np.frombuffer(buf, dt, (n - skip) // size, skip)
            with np.errstate(invalid='ignore'):
                idx = np.nonzero((arr >= lo) & (arr <= hi))[0]
            for i in idx[:limit - len(hits)]:
                h = a + skip + int(i) * size
                hits.append(h)
                vals[h] = arr[i].item()
            if len(hits) >= limit:
                break
        if len(hits) >= limit:
            break
    _scan.update(addrs=hits, type=t, vals=vals)
    head = ', '.join(f'{guest(x):#x}={_show(vals[x], t)}' for x in hits[:show])
    more = ' (limit reached)' if len(hits) >= limit else ''
    return f'{len(hits)} hits{more}: {head}' + (' ...' if len(hits) > show else '')


@mcp.tool()
def scan(value: str = '', type: str = 'u32', pattern: str = '', start: str = '0', end: str = '0',
         align: int = 0, max_results: int = 200000, show: int = 20) -> str:
    """New scan over PS3 RAM (start..end, default all). Either `value` of `type` (exact match,
    aligned to the type size unless align given; type 'str' searches text), a range 'lo..hi' (inclusive,
    e.g. value='0.033..0.034' type='f32' for a 1/30 s delta time), or `pattern` hex with ?? wildcards.
    Results are kept for scan_next. Shows the first `show` addresses."""
    if '..' in value and not pattern and type in TYPES:
        return _range_scan(value, type, start, end, max_results, show)
    if pattern:
        rx, t = _pattern(pattern), None
    elif type == 'str':
        rx, t = re.compile(re.escape(value.encode('latin-1'))), None
        align = align or 1
    else:
        rx, t = re.compile(re.escape(_pack(value, type)), re.S), type
        align = align or struct.calcsize(_fmt(type))
    end = end if int(end, 0) else str(PS3_END)
    hits = _search(rx, start, end, align or 1, max_results)
    vals = {}
    if t:
        vals = dict.fromkeys(hits, struct.unpack(_fmt(t), _pack(value, t))[0])
    elif len(hits) <= 50000:
        for x in hits:
            try:
                vals[x] = struct.unpack('>I', rd(x, 4))[0]
            except RuntimeError:
                pass
    _scan.update(addrs=hits, type=t or 'u32', vals=vals)
    head = ', '.join(f'{guest(x):#x}' for x in hits[:show])
    more = ' (limit reached)' if len(hits) >= max_results else ''
    return f'{len(hits)} hits{more}: {head}' + (' ...' if len(hits) > show else '')


@mcp.tool()
def scan_next(condition: str, type: str = '', show: int = 20) -> str:
    """Filter the last scan's results. condition: '=N', '!=N', '>N', '<N', 'lo..hi', 'changed', 'unchanged',
    'increased', 'decreased' (the last four compare against the values at the previous scan step)."""
    t = type or _scan['type'] or 'u32'
    f = _fmt(t)
    size = struct.calcsize(f)
    prev = _scan['vals']
    cur = {}
    for a in _scan['addrs']:
        try:
            cur[a] = struct.unpack(f, rd(a, size))[0]
        except RuntimeError:
            pass
    c = condition.strip()
    m = re.match(r'(!=|>=|<=|=|>|<)\s*(.+)', c)
    if '..' in c:
        lo, hi = (_num(x.strip(), t) for x in c.split('..', 1))
        test = lambda v, p: lo <= v <= hi
    elif m:
        op, n = m.group(1), m.group(2)
        n = float(n) if t.startswith('f') else int(n, 0)
        test = {'=': lambda v, p: v == n, '!=': lambda v, p: v != n, '>': lambda v, p: v > n,
                '<': lambda v, p: v < n, '>=': lambda v, p: v >= n, '<=': lambda v, p: v <= n}[op]
    else:
        test = {'changed': lambda v, p: p is not None and v != p, 'unchanged': lambda v, p: v == p,
                'increased': lambda v, p: p is not None and v > p,
                'decreased': lambda v, p: p is not None and v < p}[c]
    keep = [a for a, v in cur.items() if test(v, prev.get(a))]
    _scan.update(addrs=keep, type=t, vals={a: cur[a] for a in keep})
    head = ', '.join(f'{guest(a):#x}={_show(cur[a], t)}' for a in keep[:show])
    return f'{len(keep)} left: {head}' + (' ...' if len(keep) > show else '')


_snaps = {}


@mcp.tool()
def snapshot(label: str, addr: str, size: int) -> str:
    """Remember `size` bytes at `addr` under `label`, to compare later with diff()."""
    _snaps[label] = (host(addr), rd(host(addr), size))
    return f'snapshot {label}: {size:#x} bytes at {guest(host(addr)):#x}'


@mcp.tool()
def diff(label: str, max_lines: int = 60) -> str:
    """Show which big-endian u32 words changed since snapshot(label). Updates the snapshot."""
    a, old = _snaps[label]
    new = rd(a, len(old))
    out = []
    for o in range(0, len(old) - 3, 4):
        if old[o:o + 4] != new[o:o + 4]:
            ov, nv = struct.unpack_from('>I', old, o)[0], struct.unpack_from('>I', new, o)[0]
            out.append(f'+{o:#x} ({guest(a + o):#x}): {ov:#x} -> {nv:#x}  ({ov} -> {nv})')
    _snaps[label] = (a, new)
    extra = f'\n... {len(out) - max_lines} more' if len(out) > max_lines else ''
    return ('\n'.join(out[:max_lines]) + extra) if out else 'no change'


@mcp.tool()
def watch(addr: str, type: str = 'u32', seconds: float = 2.0, interval_ms: int = 20) -> str:
    """Sample one value for `seconds` (every `interval_ms`) and summarise how it moves:
    distinct values, changes per second, and the per-second rate for counters (e.g. frames per second)."""
    import time
    a = host(addr)
    f = _fmt(type)
    size = struct.calcsize(f)
    seconds = min(max(seconds, 0.1), 30.0)
    samples = []
    t0 = time.perf_counter()
    while (now := time.perf_counter() - t0) < seconds:
        samples.append((now, struct.unpack(f, rd(a, size))[0]))
        time.sleep(max(interval_ms, 1) / 1000)
    vals = [v for _, v in samples]
    changes = sum(1 for x, y in zip(vals, vals[1:]) if x != y)
    span = samples[-1][0] - samples[0][0] or 1e-9
    distinct = list(dict.fromkeys(vals))
    out = [f'{guest(a):#x} {type}: {len(samples)} samples over {span:.2f}s, {changes} changes '
           f'({changes / span:.1f}/s), min {_show(min(vals), type)}, max {_show(max(vals), type)}']
    if len(distinct) <= 8:
        out.append('values: ' + ', '.join(_show(v, type) for v in distinct))
    else:
        out.append(f'{len(distinct)} distinct values, first: ' + ', '.join(_show(v, type) for v in distinct[:5]))
    if changes and all(y >= x for x, y in zip(vals, vals[1:])):
        out.append(f'counter: +{(vals[-1] - vals[0]) / span:.2f} per second')
    return '\n'.join(out)


# ---------------------------------------------------------------- RPCS3 game info and patches
k32.QueryFullProcessImageNameW.argtypes = [wt.HANDLE, wt.DWORD, wt.LPWSTR, ctypes.POINTER(wt.DWORD)]


def _rpcs3_dir():
    buf = ctypes.create_unicode_buffer(1024)
    n = wt.DWORD(1024)
    if not k32.QueryFullProcessImageNameW(H(), 0, buf, ctypes.byref(n)):
        raise RuntimeError('cannot get the emulator path')
    return os.path.dirname(buf.value)


k32.CreateFileW.argtypes = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD, wt.HANDLE]
k32.CreateFileW.restype = wt.HANDLE


def _open_shared(path):
    """open() for reading a file RPCS3 holds open (it requires FILE_SHARE_DELETE, which Python's open lacks)."""
    import msvcrt
    h = k32.CreateFileW(path, 0x80000000, 7, None, 3, 0x80, None)     # GENERIC_READ, share all, OPEN_EXISTING
    if h in (None, wt.HANDLE(-1).value):
        raise OSError(f'cannot open {path} (error {ctypes.get_last_error()})')
    return os.fdopen(msvcrt.open_osfhandle(h, os.O_RDONLY | os.O_BINARY), 'rb')


def _game():
    """Info about the last game booted, from the end of RPCS3.log."""
    d = _rpcs3_dir()
    path = os.path.join(d, 'log', 'RPCS3.log')
    if not os.path.exists(path):
        path = os.path.join(d, 'RPCS3.log')
    with _open_shared(path) as fh:                       # read from the end: the log can be hundreds of MB
        size = fh.seek(0, 2)
        chunk, data, i = 0x400000, b'', -1
        while i < 0 and len(data) < size:
            n = min(chunk, size - len(data))
            fh.seek(size - len(data) - n)
            data = fh.read(n) + data
            i = data.rfind(b'SYS: Title: ')
            chunk *= 2
        if i < 0:
            raise RuntimeError('no game boot found in RPCS3.log')
        j = data.find(b'PPU executable hash: ', i)
        tail = data[i:(j + 200 if j >= 0 else i + 0x40000)].decode('utf-8', 'replace')
    g = {'dir': d, 'log': path}
    for key, rx in (('title', r'SYS: Title: (.*)'), ('serial', r'SYS: Serial: (\S+)'),
                    ('version', r'APP_VER=(\S+)'), ('config', r'Applying custom config: (.*)'),
                    ('decoder', r'PPU Decoder: (.*)'), ('hash', r'PPU executable hash: (PPU-[0-9a-f]+)')):
        m = re.search(rx, tail)
        if m:
            g[key] = m.group(1).strip()
    g['applied'] = re.findall(r"Applied patch \(hash='[^']*', description='([^']*)'", tail)
    return g


@mcp.tool()
def rpcs3_game() -> str:
    """Last booted game from RPCS3.log: title, serial, app version, PPU executable hash (the patch.yml key),
    PPU decoder, custom config and the patches that were applied at boot."""
    g = _game()
    out = [f"{g.get('title')} [{g.get('serial')}] v{g.get('version')}  {g.get('hash', 'hash not logged yet')}",
           f"PPU decoder: {g.get('decoder')} (with the LLVM recompiler, code edits in RAM are ignored; use patches)",
           f"RPCS3: {g['dir']}"]
    if g.get('config'):
        out.append(f"custom config: {g['config']}")
    out.append('applied patches: ' + ('; '.join(g['applied']) or 'none'))
    return '\n'.join(out)


_ycache = {}


def _unique_anchors(text):
    """patch.yml redefines some anchors (yaml-cpp allows it, PyYAML does not): rename each redefinition
    and point later aliases at the newest one, which is what yaml-cpp does."""
    rx = re.compile(r'(?<=[\s\[,:-])([&*])([A-Za-z0-9_.\-]+)')
    seen = {}
    for m in rx.finditer(text):
        if m.group(1) == '&':
            seen[m.group(2)] = seen.get(m.group(2), 0) + 1
    if all(n == 1 for n in seen.values()):
        return text
    cur = {}

    def sub(m):
        kind, name = m.groups()
        if seen.get(name, 0) < 2:
            return m.group(0)
        if kind == '&':
            cur[name] = cur.get(name, 0) + 1
        return f'{kind}{name}__{cur.get(name, 1)}'
    return rx.sub(sub, text)


def _yload(path):
    import yaml
    try:
        mt = os.path.getmtime(path)
    except OSError:
        return {}
    if _ycache.get(path, (None,))[0] != mt:
        with open(path, encoding='utf-8') as fh:
            text = _unique_anchors(fh.read())
        # BaseLoader keeps every scalar as text, so versions like 01.00 stay '01.00'
        _ycache[path] = (mt, yaml.load(text, Loader=getattr(yaml, 'CBaseLoader', yaml.BaseLoader)) or {})
    return _ycache[path][1]


def _patch_paths(d):
    cfg = os.path.join(d, 'config', 'patch_config.yml')
    if not os.path.exists(cfg) and os.path.exists(os.path.join(d, 'patch_config.yml')):
        cfg = os.path.join(d, 'patch_config.yml')
    return os.path.join(d, 'patches', 'patch.yml'), os.path.join(d, 'patches', 'imported_patch.yml'), cfg


def _enabled(cfg, h, name):
    try:
        for games in cfg[h][name].values():
            for vers in games.values():
                for v in vers.values():
                    if isinstance(v, dict) and str(v.get('Enabled')).lower() == 'true':
                        return True
    except (KeyError, AttributeError, TypeError):
        pass
    return False


@mcp.tool()
def rpcs3_patches(serial: str = '', filter: str = '', details: str = '') -> str:
    """List RPCS3 patches (official patch.yml + imported_patch.yml) for a game serial (default: last booted game).
    `filter` narrows by patch name (e.g. 'fps', '60'). `details` = exact patch name to show its notes and code.
    '*' marks enabled patches; '<- current' marks the hash of the executable that was last booted."""
    g = {}
    try:
        g = _game()
    except Exception:
        pass
    serial = serial or g.get('serial', '')
    d = g.get('dir') or _rpcs3_dir()
    main, imported, cfgp = _patch_paths(d)
    cfg = _yload(cfgp)
    out = []
    for path in (main, imported):
        for h, patches in (_yload(path) or {}).items():
            if not str(h).startswith(('PPU-', 'SPU-')) or not isinstance(patches, dict):
                continue
            for name, p in patches.items():
                if not isinstance(p, dict):
                    continue
                games = p.get('Games') or {}
                if serial and not any(isinstance(sv, dict) and serial in sv for sv in games.values()):
                    continue
                if filter and filter.lower() not in str(name).lower():
                    continue
                if details and details.lower() != str(name).lower():
                    continue
                if details:
                    code = p.get('Patch') or []
                    out.append(f"{name} [{h}] ({os.path.basename(path)}), enabled={_enabled(cfg, h, name)}\n"
                               f"Author: {p.get('Author')}  Version: {p.get('Patch Version')}\n"
                               f"Notes: {p.get('Notes', '')}\n{len(code)} lines:\n"
                               + '\n'.join(str(c) for c in code[:60]))
                else:
                    out.append(f"{'*' if _enabled(cfg, h, name) else ' '} {name}  [{h[:16]}...]"
                               f"{' <- current' if h == g.get('hash') else ''} ({os.path.basename(path)})")
    if out:
        return '\n'.join(out[:80])
    return f'no patches for {serial or "any game"}' + (f' matching {filter or details!r}' if filter or details else '')


def _backup(path):
    import shutil, time
    if os.path.exists(path):
        bk = f"{path}.bak_{time.strftime('%Y%m%d_%H%M%S')}"
        n = 1
        while os.path.exists(bk):                      # never overwrite an earlier backup from the same second
            n += 1
            bk = f"{path}.bak_{time.strftime('%Y%m%d_%H%M%S')}_{n}"
        shutil.copy2(path, bk)
        return bk
    return None


def _scalar(x):
    x = str(x)
    if not x or x != x.strip() or ': ' in x or ' #' in x or x.endswith(':') or x[0] in '[]{}&*!|>\'"%@`,?:-#':
        return json.dumps(x)
    return x


def _emit(node, ind=0):
    """Minimal YAML writer for patch_config.yml (nested maps of text, lists of text), like RPCS3 writes it."""
    out = []
    for k, v in node.items():
        pad = ' ' * ind
        if isinstance(v, dict):
            out.append(f'{pad}{_scalar(k)}:' + ('' if v else ' {}'))
            if v:
                out.append(_emit(v, ind + 2).rstrip('\n'))
        elif isinstance(v, list):
            out.append(f'{pad}{_scalar(k)}: [' + ', '.join(_scalar(i) for i in v) + ']')
        else:
            out.append(f'{pad}{_scalar(k)}: {_scalar(v)}')
    return '\n'.join(out) + '\n'


def _set_enabled(cfgp, h, name, title, serial, version, on):
    cfg = _yload(cfgp) or {}
    node = cfg.setdefault(h, {}).setdefault(name, {}).setdefault(title, {}).setdefault(serial, {})
    node.setdefault(version, {})['Enabled'] = 'true' if on else 'false'
    bk = _backup(cfgp)
    with open(cfgp, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(_emit(cfg))
    _ycache.pop(cfgp, None)
    return bk


def _patch_line(line):
    line = line.strip()
    if not line:
        return None
    if line.startswith('#') or line.startswith('- ['):
        return '      ' + line
    code, _, comment = line.partition('#')
    toks = [t for t in re.split(r'[\s,\[\]]+', code) if t]
    if len(toks) != 3:
        raise ValueError(f'patch line needs "type address value": {line!r}')
    return f'      - [ {toks[0]}, {toks[1]}, {toks[2]} ]' + (f' # {comment.strip()}' if comment.strip() else '')


@mcp.tool()
def rpcs3_patch_write(name: str, lines: str, notes: str = '', enable: bool = True,
                      author: str = 'Claude', patch_version: str = '1.0') -> str:
    """Add or replace a patch for the last booted game in patches/imported_patch.yml and (by default) enable it
    in patch_config.yml. `lines`: one per line, 'be32 0x003f8a08 0x806300CC # comment' or '- [ be32, ..., ... ]'
    (RPCS3 types: be16/be32/be64/bef32/bef64/byte/utf8...). Backs up both files first. Applies on next game boot."""
    import yaml
    g = _game()
    for k in ('hash', 'title', 'serial', 'version'):
        if not g.get(k):
            raise RuntimeError(f'could not read the game {k} from RPCS3.log; boot the game once first')
    h, title, serial, ver = g['hash'], g['title'], g['serial'], g['version']
    body = [x for x in (_patch_line(l) for l in lines.splitlines()) if x]
    n_code = sum(1 for x in body if x.lstrip().startswith('- ['))
    if not n_code:
        raise ValueError('no patch lines given')
    q = json.dumps
    block = [f'  {q(name)}:', '    Games:', f'      {q(title)}:', f'        {serial}: [ {ver} ]',
             f'    Author: {q(author)}', f'    Notes: {q(notes)}', f'    Patch Version: {patch_version}',
             '    Patch:'] + body
    _, imported, cfgp = _patch_paths(g['dir'])
    text = open(imported, encoding='utf-8').read() if os.path.exists(imported) else 'Version: 1.2\n'
    L = text.splitlines()
    top = next((i for i, l in enumerate(L) if l.rstrip() == f'{h}:'), None)
    if top is None:
        while L and not L[-1].strip():
            L.pop()
        L += ['', f'{h}:'] + block
        action = 'added'
    else:
        end = next((i for i in range(top + 1, len(L))
                    if L[i] and not L[i][0].isspace() and not L[i].startswith('#')), len(L))
        names = {f'  {q(name)}:', f'  {name}:', f"  '{name}':"}
        start = next((i for i in range(top + 1, end) if L[i].rstrip() in names), None)
        if start is not None:
            stop = next((i for i in range(start + 1, end) if re.match(r'  \S', L[i])), end)
            while stop > start + 1 and not L[stop - 1].strip():
                stop -= 1
            L[start:stop] = block
            action = 'replaced'
        else:
            ins = end
            while ins > top + 1 and not L[ins - 1].strip():
                ins -= 1
            L[ins:ins] = [''] + block
            action = 'added'
    new = '\n'.join(L) + '\n'
    got = ((yaml.safe_load(new) or {}).get(h) or {}).get(name) or {}
    if len(got.get('Patch') or []) != n_code:
        raise RuntimeError('generated YAML did not parse back correctly; nothing was written')
    bk = _backup(imported)
    with open(imported, 'w', encoding='utf-8', newline='\n') as fh:
        fh.write(new)
    _ycache.pop(imported, None)
    msg = f'{action} "{name}" under {h} in {imported} ({n_code} lines)' + (f', backup {bk}' if bk else '')
    if enable:
        cbk = _set_enabled(cfgp, h, name, title, serial, ver, True)
        msg += f'\nenabled in {cfgp}' + (f' (backup {cbk})' if cbk else '')
    return msg + '\nReboot the game to apply. Close the RPCS3 patch manager first, or it may overwrite patch_config.yml.'


@mcp.tool()
def rpcs3_patch_enable(name: str, enabled: bool = True, hash: str = '') -> str:
    """Enable or disable a patch (exact name) for the last booted game in patch_config.yml. Backs up first."""
    g = _game()
    h = hash or g.get('hash')
    main, imported, cfgp = _patch_paths(g['dir'])
    for path in (imported, main):
        p = ((_yload(path) or {}).get(h) or {}).get(name)
        if not isinstance(p, dict):
            continue
        for title, sv in (p.get('Games') or {}).items():
            vers = (sv or {}).get(g.get('serial'))
            if vers is None:
                continue
            for ver in (vers if isinstance(vers, list) and vers else [g.get('version')]):
                bk = _set_enabled(cfgp, h, name, title, g['serial'], str(ver), enabled)
            return f'"{name}" {"enabled" if enabled else "disabled"} (backup {bk}). Reboot the game to apply.'
    return f'no patch named {name!r} for {g.get("serial")} under {h}'


# ---------------------------------------------------------------- Top Spin 4 roster
STRIDE = 0x104
STATS = ['serve', 'return', 'reflex', 'forehand', 'backhand', 'volley', 'power', 'speed', 'stamina', 'mental']
FIELDS = {s: 0x48 + 4 * i for i, s in enumerate(STATS)}
FIELDS.update(level=0x70, skill1=0x74, skill2=0x78, skill3=0x7C, skill4=0x80, style=0x84)
SKILLS = ('skill1', 'skill2', 'skill3', 'skill4')   # in-game order; skill4 is not shown in game
CREATED = 0x302D482A
_ts4 = {}


def _abilities():
    if 'ab' not in _ts4:
        try:
            db = json.load(open(os.path.join(HERE, 'data', 'ts4_abilities.json'), encoding='utf-8'))
        except OSError:
            db = {}
        _ts4['ab'] = {int(h, 16): n for h, n in db.items()}
    return _ts4['ab']


def _rowname(r):
    try:
        off = struct.unpack('>i', rd(r + 0xB0, 4))[0]
        if off <= 0 or off >= 0x400000:
            return None
        s = rd(r + 0xB0 + off, 40).split(b'\0')[0]
    except RuntimeError:
        return None
    return s.decode() if re.fullmatch(rb'[A-Za-z0-9]{2,32}', s) else None


def _roster():
    fed = _ts4.get('federer')
    if fed and _rowname(fed) == 'Federer':
        return _ts4['rows']
    hits = _search(re.compile(re.escape(bytes.fromhex('7330E4A4'))), '0', str(PS3_END), 4, 64)
    fed = min((h - 0xB4 for h in hits if _rowname(h - 0xB4) == 'Federer'), default=None)
    if fed is None:
        raise RuntimeError('Top Spin 4 roster not found (game not booted to menus?)')
    r = fed
    while _rowname(r - STRIDE):
        r -= STRIDE
    rows = {}
    while (n := _rowname(r)):
        rows[n] = r
        r += STRIDE
    _ts4.update(federer=fed, rows=rows)
    return rows


def _row(name):
    rows = _roster()
    if name in rows:
        return name, rows[name]
    low = {k.lower(): k for k in rows}
    if name.lower() in low:
        k = low[name.lower()]
        return k, rows[k]
    m = difflib.get_close_matches(name, rows, 1, 0.6)
    if not m:
        raise ValueError(f'no roster row like {name!r}')
    return m[0], rows[m[0]]


def _ability(v):
    if v == 0:
        return '-'
    return _abilities().get(v, f'{v:08x}')


@mcp.tool()
def ts4_roster(filter: str = '') -> str:
    """List Top Spin 4 roster rows (name @ PS3 address). `filter` = substring; empty = summary only."""
    rows = _roster()
    first = min(rows.values())
    if not filter:
        return (f'{len(rows)} rows from {guest(first):#x}, stride {STRIDE:#x}. Career slots P1CreatedPlayer01-04, '
                f'match copies PlayerCreated1-4, pros from Federer ({guest(_ts4["federer"]):#x}).')
    hit = [f'{n} @ {guest(r):#x}' for n, r in rows.items() if filter.lower() in n.lower()]
    return '\n'.join(hit[:80]) or 'no match'


@mcp.tool()
def ts4_player(name: str) -> str:
    """Show one Top Spin 4 player: 10 attributes, level, 4 skills (in-game order, skill4 hidden), style."""
    n, r = _row(name)
    raw = rd(r + 0x48, 0x40)
    v = struct.unpack('>16I', raw)
    st = ' '.join(f'{s[:3]}={v[i]}' for i, s in enumerate(STATS))
    sk = ' | '.join(_ability(v[11 + i]) for i in range(4))
    tag = ' (created)' if v[15] == CREATED else ''
    return f'{n} @ {guest(r):#x}{tag}\n{st} level={v[10]}\nskills: {sk}'


@mcp.tool()
def ts4_set(name: str, field: str, value: str) -> str:
    """Set a Top Spin 4 player field. field: serve..mental, 'all' (10 attributes), level, skill1..skill4.
    For skills, value may be an ability name (fuzzy), a hex hash, or 0 to clear."""
    n, r = _row(name)
    f = field.lower()
    if f in SKILLS:
        try:
            val = int(value, 16) if re.fullmatch(r'(0x)?[0-9a-fA-F]{8}', value) else int(value, 0)
        except ValueError:
            ab = _abilities()
            names = {nm.lower(): h for h, nm in ab.items()}
            m = difflib.get_close_matches(value.lower(), names, 1, 0.4)
            if not m:
                raise ValueError(f'unknown ability {value!r}')
            val = names[m[0]]
        wr(r + FIELDS[f], struct.pack('>I', val))
        return f'{n}.{f} = {_ability(val)}'
    val = int(value, 0)
    targets = STATS if f == 'all' else [f]
    for t in targets:
        if t not in FIELDS:
            raise ValueError(f'unknown field {field!r}')
        wr(r + FIELDS[t], struct.pack('>I', val))
    return f'{n}.{f} = {val}'


@mcp.tool()
def ts4_abilities(filter: str = '') -> str:
    """Search the 261-entry ability DB by name. Returns 'hash name'."""
    out = [f'{h:08x} {nm}' for h, nm in sorted(_abilities().items(), key=lambda x: x[1])
           if filter.lower() in nm.lower()]
    return '\n'.join(out[:60]) or 'no match'


if __name__ == '__main__':
    mcp.run()
