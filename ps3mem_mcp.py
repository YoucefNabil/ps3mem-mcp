"""ps3mem: headless MCP server for reading/writing PS3 guest memory inside a running RPCS3.

Addresses are PS3 addresses (e.g. 0x33743dc4); values are big-endian like the console.
Anything >= 4 GiB is treated as a raw host address. Output is kept short on purpose.
Top Spin 4 helpers (ts4_*) sit on top of the generic tools.
"""
import ctypes, ctypes.wintypes as wt, json, os, re, struct, subprocess, difflib
from mcp.server.fastmcp import FastMCP

BASE = 0x300000000          # RPCS3 maps PS3 virtual memory here
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
    return _proc['h']


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
    'host = 0x300000000 + addr). Prefer these tools over ad-hoc ReadProcessMemory scripts. '
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


@mcp.tool()
def scan(value: str = '', type: str = 'u32', pattern: str = '', start: str = '0', end: str = '0',
         align: int = 0, max_results: int = 200000, show: int = 20) -> str:
    """New scan over PS3 RAM (start..end, default all). Either `value` of `type` (exact match,
    aligned to the type size unless align given; type 'str' searches text), or `pattern` hex with ?? wildcards.
    Results are kept for scan_next. Shows the first `show` addresses."""
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
    """Filter the last scan's results. condition: '=N', '!=N', '>N', '<N', 'changed', 'unchanged',
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
    if m:
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
