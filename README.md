# ps3mem-mcp

A headless [MCP](https://modelcontextprotocol.io) server for reading and writing PS3 guest memory inside a running
[RPCS3](https://rpcs3.net). It attaches to `rpcs3.exe` on its own, without Cheat Engine or a debugger window, so an
AI assistant such as Claude Code can inspect and patch a game's RAM with short tool calls.

- Addresses are **PS3 addresses** (e.g. `0x33743dc4`). RPCS3 maps guest memory at host `0x300000000`, and the server
  adds that for you. Anything at 4 GiB or above is treated as a raw host address.
- Values are **big-endian**, like on the console.
- Output is deliberately compact, to keep assistant context small.

Windows only (it uses `ReadProcessMemory` / `WriteProcessMemory` through ctypes).

## Tools

| Tool | What it does |
|---|---|
| `attach(process="rpcs3.exe")` | (Re)attach. Other tools attach automatically and re-attach if the emulator restarts. |
| `read(addr, type="u32", count=1, stride=0)` | Read `u8/s8/u16/s16/u32/s32/u64/s64/f32/f64`, `str` or `bytes`. `stride` reads one field across table rows. |
| `write(addr, value, type="u32", count=1, stride=0)` | Write a value (or hex `bytes` / `str`). Returns old -> new. |
| `hexdump(addr, size=0x100, words=True)` | Hex + ASCII dump, grouped as big-endian words. |
| `struct_read(addr, fields)` | Named fields, e.g. `"serve:u32@0x48, racket:str@0x4"`. |
| `scan(value, type)` / `scan(pattern="30 2D ?? 2A")` | Cheat Engine-style first scan over PS3 RAM (value, text or wildcard pattern). |
| `scan_next(condition)` | Filter the last scan: `=N`, `!=N`, `>N`, `<N`, `changed`, `unchanged`, `increased`, `decreased`. |
| `snapshot(label, addr, size)` / `diff(label)` | Show which words of a memory block changed between two moments. |

### Top Spin 4 (BLES00668) helpers

| Tool | What it does |
|---|---|
| `ts4_roster(filter="")` | Finds the 731-row player roster (via Federer's name hash) and lists rows by name. |
| `ts4_player(name)` | 10 attributes, level and the 4 skills (in in-game order, skill 4 is hidden in game) by name. |
| `ts4_set(name, field, value)` | Set `serve`..`mental`, `all`, `level` or `skill1`..`skill4`. Skill values may be names (fuzzy), hex hashes or 0. |
| `ts4_abilities(filter="")` | Search the 261-entry ability list (`data/ts4_abilities.json`). |

Roster layout: 0x104-byte rows; row+0x48 holds Serve, Return, Reflex, Forehand, Backhand, Volley, Power, Speed,
Stamina and Mental (u32 each), +0x70 level, +0x74..+0x80 skills, +0x84 play style (created players `302D482A`),
+0xB0 self-relative offset to the internal name, +0xB4 CRC32 of that name.

## Install

Requires Python 3.10+.

```
pip install "mcp>=1.2"
```

Register it with Claude Code for every folder (user scope):

```
claude mcp add ps3mem -s user -- python C:/path/to/ps3mem-mcp/ps3mem_mcp.py
```

Or add it to any MCP client as a stdio server running `python ps3mem_mcp.py`.

Writing another process's memory may need the client to run with the same privileges as RPCS3 (or as admin).

## Adding another game

Generic tools work for any RPCS3 game. For game-specific helpers, follow the `ts4_*` section: find a stable anchor
with `scan`, decode a structure with `struct_read`, then wrap it in a `@mcp.tool()` with compact output.
