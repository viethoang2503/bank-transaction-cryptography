# Architecture: TBA Bank Demo

Tài liệu đi kèm spec `docs/superpowers/specs/2026-11-06-tba-midterm-design.md`. Các sơ đồ viết bằng Mermaid, có thể xuất ra SVG/PDF để đưa vào report (Hình F1-F3).

## 1. Thành phần và phụ thuộc (Hình F1)

```mermaid
flowchart LR
  subgraph PC["Máy tính nạn nhân (không tin cậy)"]
    BR["Trình duyệt<br/>trang ngân hàng"]
    MITM["attacker/mitb_addon.py<br/>(mitmproxy, giả lập MitB)"]
  end
  subgraph PHONE["Điện thoại (tin cậy)"]
    APP["authenticator/<br/>HTML + ES modules<br/>Web Crypto + IndexedDB"]
  end
  subgraph SRV["Bank server (FastAPI, HTTPS :8443)"]
    WEB["server/app.py<br/>routes + templates"]
    VER["server/verify.py"]
    TRF["server/transfers.py"]
    AUTH["server/auth.py"]
    DB[("SQLite")]
  end
  CORE["tba_core/<br/>encoding, totp, hmac_otp,<br/>signature, challenge"]
  EVAL["evaluation/<br/>harness, VirtualPhone,<br/>scenarios, bench"]
  VEC["shared/vectors.json"]

  BR -- HTTPS --> MITM -- HTTPS --> WEB
  APP -- "HTTPS (kênh riêng)" --> WEB
  BR -. "QR trên màn hình" .-> APP
  WEB --> VER & TRF & AUTH --> DB
  VER & TRF --> CORE
  EVAL --> CORE
  EVAL -- "TestClient" --> WEB
  VEC -. "kiểm tra" .-> CORE
  VEC -. "kiểm tra" .-> APP
```

Quy tắc phụ thuộc:
- `tba_core` không phụ thuộc vào bất kỳ thành phần nào khác (chỉ dùng stdlib và `cryptography`).
- `server` dùng `tba_core`; không import `evaluation`.
- `evaluation` dùng `tba_core` và `server` (qua `create_app` và `server.testing`).
- `authenticator` chỉ giao tiếp với server qua HTTP; tính đúng đắn được ràng buộc với Python qua `shared/vectors.json`.
- `attacker/mitb_addon.py` chỉ dùng stdlib (+ `segno` nếu bật giả QR), vì chạy trong môi trường riêng của `mitmproxy`.

## 2. Triển khai khi demo

```mermaid
flowchart TB
  subgraph LAN["Mạng LAN / Wi-Fi"]
    LAP["Laptop chạy server<br/>uvicorn server.main:app :8443<br/>cert từ mkcert"]
    VPC["Laptop nạn nhân<br/>trình duyệt → proxy 127.0.0.1:8080<br/>mitmdump -s attacker/mitb_addon.py"]
    PH["Điện thoại<br/>https://&lt;host&gt;:8443/app/<br/>tin cậy root CA của mkcert"]
  end
  VPC -- "HTTPS qua mitmproxy" --> LAP
  PH -- "HTTPS trực tiếp" --> LAP
```

Server và máy nạn nhân có thể là cùng một laptop. Phương án dự phòng: `cloudflared tunnel --url https://localhost:8443 --no-tls-verify` cho ra một URL có chứng chỉ hợp lệ.

## 3. Đăng ký thiết bị (Hình F2)

```mermaid
sequenceDiagram
  participant U as Người dùng
  participant B as Trình duyệt
  participant S as Server
  participant P as Authenticator
  U->>B: Đăng nhập, mở /enroll
  B->>S: GET /enroll
  Note over S: Đã có thiết bị → 409, không phát token (không cho thay thiết bị chỉ bằng session)
  S->>S: token = random, hạn 300 s, dùng 1 lần
  S-->>B: QR "tbaenroll1:" + token
  U->>P: Quét QR
  P->>P: generateKey(ECDSA P-256, non-extractable)
  P->>S: POST /api/device/enroll {token, public_key}
  S->>S: Đánh dấu token đã dùng, sinh K_totp, K_hmac, lưu thiết bị
  S-->>P: {device_id, k_totp, k_hmac, mode} (khóa HMAC ở dạng rõ, qua HTTPS)
  P->>P: importKey(HMAC, non-extractable), lưu vào IndexedDB
```

Lưu ý khi viết Chương 4 và 5: chỉ khóa riêng ECDSA là không bao giờ rời điện thoại (sinh tại chỗ, `extractable = false`). `k_totp` và `k_hmac` là bí mật dùng chung: server sinh, gửi dạng rõ trong JSON và lưu dạng rõ trong bảng `devices`. "Non-extractable" chỉ đúng với bản sao trên điện thoại *sau khi* `importKey`. Đây cũng là lý do S10 phá được `baseline` và `hmac`. Server hiện sinh và gửi cả hai khóa này ở mọi chế độ, kể cả `sig`/`sig_blind`.

## 4. Xác nhận giao dịch, 4 chế độ (Hình F3)

```mermaid
sequenceDiagram
  participant U as Người dùng
  participant B as Trình duyệt
  participant S as Server
  participant P as Authenticator
  U->>B: to, amount
  B->>S: POST /transfer
  S->>S: tx = new_tx(...), lưu canonical(tx), state = pending
  S-->>B: 303 → /transfer/{tx_id}
  B->>S: GET /transfer/{tx_id}
  alt baseline
    S-->>B: Trang xác nhận, không có QR
    P->>U: Hiển thị TOTP (đổi mỗi 30 s)
    U->>B: Nhập TOTP
    B->>S: POST /transfer/{tx_id}/otp
  else hmac
    S-->>B: Trang xác nhận + QR "tba1:" + b64url(canonical)
    U->>P: Quét QR
    P->>U: Hiển thị amount, to, to_name
    U->>P: Approve
    P->>U: OTP = DT(HMAC(K_hmac, tag ‖ canonical))
    U->>B: Nhập OTP
    B->>S: POST /transfer/{tx_id}/otp
  else sig / sig_blind
    S-->>B: Trang xác nhận + QR, trình duyệt polling /status
    U->>P: Quét QR
    P->>U: sig: hiển thị chi tiết / sig_blind: chỉ có nút Approve
    U->>P: Approve
    P->>S: POST /api/device/confirm {device_id, tx_id, signature}
  end
  S->>S: verify trên canonical lưu trong DB, cập nhật nguyên tử
  S-->>B: Kết quả
```

### 4b. Luồng `sig` khi bị MitB tấn công (hình cho Chương 6)

Người dùng muốn chuyển cho Bob. MitB đổi `to` thành tài khoản Mallory và sửa trang để vẫn hiện Bob. Ba nhánh tương ứng S2a (`sig`), S2a (`sig_blind`) và S4.

```mermaid
sequenceDiagram
  participant U as Người dùng
  participant M as MitB (trong trình duyệt)
  participant S as Server
  participant P as Authenticator
  U->>M: to = Bob, amount = 1.000.000
  M->>S: POST /transfer (to = Mallory)
  S->>S: tx = new_tx(to = Mallory), lưu canonical, state = pending
  S-->>M: Trang xác nhận + QR(canonical với to = Mallory)
  M-->>U: Trang hiển thị "Bob" (đã bị sửa)
  alt sig, QR thật (S2a)
    U->>P: Quét QR
    P->>U: Hiển thị to = Mallory, to_name = LE VAN M
    U->>P: Thấy không khớp ý định, Reject
    Note over S: Không có chữ ký, giao dịch hết hạn → blocked
  else sig_blind, QR thật (S2a)
    U->>P: Quét QR
    P->>U: Chỉ có nút Approve, không hiện chi tiết
    U->>P: Approve
    P->>S: POST /api/device/confirm {sig trên tx to = Mallory}
    S->>S: Chữ ký hợp lệ trên canonical trong DB
    Note over S: Thực hiện chuyển cho Mallory → succeeded
  else sig, MitB giả QR với to = Bob (S4)
    M-->>U: QR giả chứa tx' (to = Bob, cùng tx_id)
    U->>P: Quét QR giả
    P->>U: Hiển thị to = Bob (khớp ý định)
    U->>P: Approve
    P->>S: POST /api/device/confirm {sig trên tx'}
    S->>S: Verify trên canonical trong DB (to = Mallory) → sai
    Note over S: attempts += 1, không chuyển tiền → blocked
  end
```

Ý chính cho Chương 6: S4 bị chặn nhờ *gắn mật mã* (server chỉ tin bản canonical của mình, G1). S2a chỉ bị chặn khi điện thoại *hiển thị* giao dịch và người dùng đọc nó (G7). `sig_blind` có đủ phần mật mã nhưng vẫn thua S2a.

## 5. Vòng đời giao dịch

```mermaid
stateDiagram-v2
  [*] --> pending: POST /transfer
  pending --> executed: mã/chữ ký đúng và đủ số dư
  pending --> failed: sai lần thứ 3, hoặc không đủ số dư lúc thực hiện
  pending --> expired: now > exp (kiểm khi xác nhận hoặc khi polling)
  executed --> [*]
  failed --> [*]
  expired --> [*]
```

Mọi chuyển trạng thái đều nằm trong một `BEGIN IMMEDIATE`. Vì vậy hai yêu cầu đồng thời không thể cùng thấy `pending` (S8).

## 6. Mô hình dữ liệu

```mermaid
erDiagram
  users ||--o{ sessions : has
  users ||--o{ enroll_tokens : has
  users ||--o| devices : has
  users ||--o{ transactions : creates
  users {
    int id PK
    text username UK
    blob pw_salt
    blob pw_hash
    text account UK
    text display_name
    int balance
  }
  sessions {
    text token PK
    int user_id FK
    int exp
  }
  enroll_tokens {
    text token PK
    int user_id FK
    int exp
    int used
  }
  devices {
    text id PK
    int user_id FK "UNIQUE"
    blob public_key "65 byte"
    blob k_totp "20 byte"
    blob k_hmac "32 byte"
    int last_totp_step
    int created_at
  }
  transactions {
    text tx_id PK
    int user_id FK
    text mode
    blob canonical
    text state
    int attempts
    int created_at
    blob evidence
  }
  audit_log {
    int id PK
    int ts
    int user_id
    text tx_id
    text event
    text detail
  }
```

## 7. Cấu trúc thư mục

```
.
├── pyproject.toml, Makefile, README.md
├── tba_core/        b64.py encoding.py totp.py hmac_otp.py signature.py challenge.py
├── server/          config.py db.py auth.py transfers.py verify.py app.py main.py testing.py templates/
├── authenticator/   index.html app.css package.json js/{b64,canonical,otp,sig,store,app}.js vendor/jsQR.js tests/
├── attacker/        mitb_addon.py
├── evaluation/      harness.py virtual_phone.py mitb.py user_model.py flows.py scenarios.py expected.py
│                    goals.py latex.py run_scenarios.py bruteforce.py bench.py sizes.py
├── scripts/         gen_vectors.py dev_cert.sh
├── shared/          vectors.json
├── proverif/        (tùy chọn) tba_sig.pv tba_sig_blind.pv
├── tests/           core/ server/ evaluation/
├── results/         (sinh ra bởi make eval)
├── report/          main.tex members.tex chapters/ refs.bib
└── docs/            architecture.md superpowers/{specs,plans}/
```
