# Design: Transaction-Bound Authentication for Online Banking

**Môn:** Introduction to Cryptography (USTH), midterm project
**Tên đề (ghi đúng nguyên văn trên bìa):** *Transaction-Bound Authentication for Online Banking: Implementation and Security Evaluation*
**Nhóm:** 7 thành viên, 10 ngày (ngày 1 = 07/11/2026, hạn nộp = 16/11/2026)
**Yêu cầu của giảng viên:** nộp report dạng PDF; trang bìa có tên đề, danh sách thành viên và mã sinh viên (kiểm tra kỹ danh sách); leader là người nộp.

Kiến trúc chi tiết và sơ đồ: xem `docs/architecture.md`.
Kế hoạch cài đặt: xem `docs/superpowers/plans/`.

---

## 1. Mục tiêu và câu hỏi nghiên cứu

Xây một hệ thống ngân hàng demo có 4 chế độ xác thực giao dịch, rồi đánh giá bằng thực nghiệm xem chế độ nào chặn được những tấn công nào.

- **RQ1:** Gắn mật mã vào giao dịch có chặn được MitB và phishing thời gian thực tốt hơn OTP thông thường không?
- **RQ2:** Gắn đối xứng (HMAC) và bất đối xứng (chữ ký) khác nhau thế nào về bảo mật và chi phí?
- **RQ3:** Màn hình tin cậy (WYSIWYS) đóng vai trò gì? Thí nghiệm ký mù (`sig_blind`) trả lời câu hỏi này.

## 2. Các quyết định đã chốt

| Chủ đề | Quyết định |
|---|---|
| Ngôn ngữ | Python ≥ 3.11 (server, lõi mật mã, đánh giá); JavaScript thuần (authenticator trên điện thoại) |
| Authenticator | Web app chạy trên điện thoại thật qua HTTPS, phục vụ tại `/app/` của cùng server |
| Lõi kiểm thử | Thư viện `tba_core` dùng chung + "điện thoại ảo" (`VirtualPhone`) để test và benchmark tự động |
| Các chế độ | `baseline` (TOTP, không gắn giao dịch), `hmac` (OTP gắn giao dịch, kiểu OCRA), `sig` (ECDSA P-256), `sig_blind` (như `sig` nhưng điện thoại không hiển thị chi tiết) |
| WebAuthn/SPC | Không cài đặt; chỉ bàn trong Discussion |
| Encoding giao dịch | JSON chuẩn hóa (khóa sắp xếp, không khoảng trắng, chỉ ASCII, số nguyên) |
| MitB | Addon `mitmproxy` cho demo thật; lớp `Mitb` giả lập trong test tự động |
| OTP | `hmac`: 8 chữ số; `baseline`: 6 chữ số; tối đa 3 lần thử mỗi giao dịch (áp dụng cho mọi chế độ) |
| Tên người nhận | In hoa, không dấu, do server tra cứu |
| Đăng ký thiết bị | Giả định môi trường sạch (trust-on-first-use) |
| Usability | Chỉ 7 thành viên làm người thử, ghi rõ mẫu nhỏ |
| ProVerif | Tùy chọn, chỉ làm nếu dư thời gian |
| Ngôn ngữ report và giao diện | Tiếng Anh (để ảnh chụp màn hình khớp với report) |
| Report | LaTeX trên Overleaf, khoảng 19 trang nội dung chính + phụ lục |

## 3. Các thành phần

1. **`tba_core/`**: lõi mật mã Python thuần, không I/O.
   - `b64.py`: base64url không padding, giải mã chặt.
   - `encoding.py`: kiểm tra schema, `canonical_bytes`, `parse_canonical`, `tagged_message`, mã hóa/giải mã QR.
   - `totp.py`: HOTP/TOTP theo RFC 4226/6238.
   - `hmac_otp.py`: OTP gắn giao dịch.
   - `signature.py`: ECDSA P-256 (chữ ký raw `r‖s` 64 byte), thêm Ed25519 để benchmark.
   - `challenge.py`: sinh nonce và giao dịch mới.
2. **`server/`**: FastAPI + SQLite + Jinja2. Đăng nhập, đăng ký thiết bị, tạo giao dịch, xác minh, ghi sổ, audit log.
3. **`authenticator/`**: web app tĩnh (HTML + ES modules) cho điện thoại. Dùng Web Crypto, lưu khóa trong IndexedDB, quét QR bằng jsQR. Khóa ký ECDSA sinh trên điện thoại với `extractable = false` nên khóa riêng không rời điện thoại qua API. `k_totp` và `k_hmac` do server sinh, gửi dạng rõ lúc đăng ký và lưu dạng rõ trong DB; điện thoại chỉ import chúng ở dạng non-extractable.
4. **`attacker/`**: addon `mitmproxy` mô phỏng MitB.
5. **`evaluation/`**: harness, điện thoại ảo, mô hình người dùng, kịch bản tấn công S1-S13, brute-force, benchmark, sinh bảng LaTeX.
6. **`shared/vectors.json`**: test vector dùng chung cho Python và JS.
7. **`report/`**: khung LaTeX.

## 4. Giao thức

### 4.1. Giao dịch

```json
{"amount":1000000,"currency":"VND","exp":1800000120,"from":"0011223344",
 "nonce":"AAECAwQFBgcICQoLDA0ODw","to":"0123456789","to_name":"TRAN THI B",
 "tx_id":"3f2b8c1e-5a4d-4e7f-9b6a-1c2d3e4f5a6b","v":1}
```

Ràng buộc của từng trường (Python và JS phải kiểm tra giống hệt nhau):

| Trường | Ràng buộc |
|---|---|
| `v` | số nguyên, bằng 1 |
| `tx_id` | UUID chữ thường `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}` |
| `from`, `to` | `[0-9]{6,20}` |
| `to_name` | `[A-Z0-9 ]{1,64}` |
| `amount` | số nguyên (không phải bool), 1 ≤ amount ≤ 2⁵³−1 |
| `currency` | `[A-Z]{3}` |
| `nonce` | 16 byte ngẫu nhiên, base64url không padding, đúng 22 ký tự `[A-Za-z0-9_-]` |
| `exp` | số nguyên, 1 ≤ exp ≤ 2⁵³−1; bằng thời điểm tạo + 120 giây |

Thừa hay thiếu trường đều bị từ chối.

**Canonical:** `json.dumps(tx, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")`.
**Parse chặt:** từ chối khóa trùng, số thực, NaN/Infinity, byte không phải ASCII, và mọi chuỗi mà khi canonical hóa lại không ra đúng chuỗi byte ban đầu.
**QR giao dịch:** `"tba1:" + base64url(canonical)`. **QR đăng ký:** `"tbaenroll1:" + token`.
**Nguyên tắc:** server luôn xác minh trên bản canonical lưu trong DB của chính nó, không bao giờ dùng giao dịch do client gửi lên.

### 4.2. Mật mã của từng chế độ

| Chế độ | Điện thoại tính | Server kiểm tra |
|---|---|---|
| `baseline` | `HOTP(K_totp, ⌊t/30⌋)`, HMAC-SHA1, 6 chữ số | Cửa sổ ±1 bước; từ chối bước thời gian ≤ `last_totp_step` |
| `hmac` | `DT(HMAC-SHA256(K_hmac, "TBA-HMAC-v1" ‖ 0x00 ‖ canonical(tx)))`, 8 chữ số | `hmac.compare_digest` |
| `sig` | `ECDSA-P256-SHA256(sk, "TBA-SIG-v1" ‖ 0x00 ‖ canonical(tx))`, raw 64 byte | Chuyển sang DER rồi verify bằng public key |
| `sig_blind` | Giống `sig` | Giống `sig` |

`DT` là dynamic truncation của RFC 4226. Mỗi thiết bị có K_totp (20 byte) và K_hmac (32 byte) riêng.

### 4.3. Đăng ký thiết bị

1. Trình duyệt mở `/enroll`, server tạo token (ngẫu nhiên, dùng một lần, hạn 300 giây) và hiển thị QR.
2. Điện thoại sinh cặp khóa P-256 non-extractable, gửi `POST /api/device/enroll {token, public_key}`.
3. Server trả `{device_id, k_totp, k_hmac, mode}`. Mỗi người dùng chỉ có một thiết bị. Khi đã có thiết bị, server **từ chối đăng ký lại**: `GET /enroll` trả 409 và không phát token, `enroll_device` từ chối cả token đã phát trước đó. Lý do: nếu chỉ cần session là thay được thiết bị thì kẻ A1 (MitB) hoặc kẻ có mật khẩu tự đăng ký khóa của mình rồi duyệt mọi giao dịch, ở mọi chế độ. Trong demo, muốn đăng ký lại thì xóa DB bằng `make reset MODE=<mode>`; hệ thống thật cần quy trình ngoài băng (ghi vào Limitations).

### 4.4. API

| Phía | Endpoint | Request | Response |
|---|---|---|---|
| Trình duyệt | `GET/POST /login` | form `username`, `password` | 303 → `/transfer`, cookie `session` (HttpOnly, Secure, SameSite=Lax); 401 nếu sai |
| Trình duyệt | `POST /logout` | | 303 → `/login` |
| Trình duyệt | `GET /enroll` | | HTML có `<div id="qr" data-payload="tbaenroll1:...">`; 409 và không có QR nếu người dùng đã có thiết bị |
| Trình duyệt | `GET /transfer` | | Form chuyển tiền |
| Trình duyệt | `POST /transfer` | form `to`, `amount` | 303 → `/transfer/{tx_id}`; 400 kèm thông báo lỗi |
| Trình duyệt | `GET /transfer/{tx_id}` | | Trang xác nhận; chế độ khác `baseline` có `<div id="qr" data-payload="tba1:...">` |
| Trình duyệt | `POST /transfer/{tx_id}/otp` | form `otp` (khoảng trắng bị bỏ qua) | 200 + trang kết quả nếu đã thực hiện; 400 + trang xác nhận kèm số lượt còn lại nếu mã sai mà giao dịch còn `pending`; 400 + trang kết quả nếu `failed`/`expired`; 404 ở chế độ `sig`/`sig_blind` |
| Trình duyệt | `GET /transfer/{tx_id}/status` | | `{"state": "pending"\|"executed"\|"failed"\|"expired"}` |
| Trình duyệt | `GET /transfer/{tx_id}/result` | | Trang kết quả |
| Trình duyệt | `GET /api/lookup?account=` | cần session | `{"account", "name"}` hoặc 404 |
| Điện thoại | `GET /api/config` | | `{"mode", "otp_digits": 8, "totp_digits": 6}` |
| Điện thoại | `POST /api/device/enroll` | `{"token", "public_key"}` (base64url, điểm không nén 65 byte) | `{"device_id","k_totp","k_hmac","mode"}`; 400 `invalid_public_key`; 403 `invalid_token` (token sai, hết hạn, đã dùng, hoặc người dùng đã có thiết bị) |
| Điện thoại | `POST /api/device/confirm` | `{"device_id","tx_id","signature"}` (base64url, 64 byte) | `{"result": "ok"\|"rejected"}`; 422 nếu thiếu trường; **không bao giờ trả 5xx** |

### 4.5. Thứ tự kiểm tra phía server (trong một `BEGIN IMMEDIATE`)

1. `tx_id` tồn tại và thuộc về đúng người dùng.
2. Trạng thái là `pending`.
3. Chưa quá `exp` (nếu quá thì chuyển sang `expired`).
4. Dựng lại `tx` từ bản canonical trong DB.
5. Xác minh OTP hoặc chữ ký. Nếu sai: `attempts += 1`; khi `attempts ≥ 3` thì chuyển sang `failed`. Bằng chứng sai loại so với chế độ (OTP ở chế độ chữ ký, chữ ký ở chế độ OTP) bị từ chối trước bước 1 và không tính vào `attempts`.
6. Nếu đúng: trừ tiền người gửi (với điều kiện `balance ≥ amount`), cộng tiền người nhận, chuyển sang `executed`, lưu bằng chứng (`evidence`) là OTP hoặc chữ ký.
7. Ghi audit log. Client chỉ nhận thông báo chung, lý do cụ thể nằm trong audit log.

### 4.6. Dữ liệu demo

| Username | Password | Tài khoản | Tên | Số dư |
|---|---|---|---|---|
| alice | alice-pass | 0011223344 | NGUYEN VAN A | 100.000.000 |
| bob | bob-pass | 0123456789 | TRAN THI B | 5.000.000 |
| mallory (kẻ tấn công) | mallory-pass | 0999888777 | LE VAN M | 0 |

Mật khẩu băm bằng scrypt (n=2¹⁴, r=8, p=1). K_totp và K_hmac lưu plaintext trong DB, có chủ ý để làm kịch bản S10; report ghi rõ hệ thống thật cần HSM.

## 5. Threat model

**Giả định tin cậy:** TLS an toàn; server trung thực nhưng DB có thể bị lộ (chỉ đọc); điện thoại được tin cậy; lúc đăng ký thiết bị môi trường sạch.

| Mã | Kẻ tấn công | Phạm vi | Kịch bản |
|---|---|---|---|
| A1 | MitB: đọc và sửa mọi thứ trong trình duyệt | Trong | S2a, S2b, S3, S4 |
| A2 | Phishing proxy: chuyển tiếp mã theo thời gian thực | Trong | S2a, S2b, S3, S4 (xem ghi chú) |
| A3 | Replay mã/chữ ký cũ | Trong | S6, S7, S8 |
| A4 | Đoán mã online | Trong | S9 |
| A5 | Có bản sao DB server | Trong | S10 |
| A6 | Mã độc trên điện thoại, hoặc máy tính và điện thoại cùng bị nhiễm | Ngoài (Discussion) | |
| A7 | Social engineering | Ngoài (Discussion) | |

**Ghi chú về A2.** Không có kịch bản riêng cho phishing proxy, vì trong mô hình này nó làm được đúng những việc lớp `Mitb` làm: đứng giữa người dùng và ngân hàng, sửa request chuyển tiền và sửa trang (kể cả QR) trả về cho người dùng. Khác biệt duy nhất là cách kẻ tấn công vào được vị trí đó (trang giả thay vì mã độc), và điều này không ảnh hưởng tới kết quả. Vì vậy mọi khẳng định về phishing thời gian thực trong report (RQ1) phải dẫn S2a/S2b/S3/S4 và nêu rõ lập luận tương đương này; không được viết như thể đã có thí nghiệm phishing riêng.

**Ghi chú về A6.** Giả định "điện thoại tin cậy và tách biệt với máy tính" là giả định mạnh, và tài liệu đã cho thấy nó dễ mất: nhiễm chéo máy tính và điện thoại (Dmitrienko và cộng sự, FC 2014), đồng bộ giữa các nền tảng xóa khoảng cách giữa hai thiết bị (Konoth và cộng sự, FC 2016), ngân hàng và ứng dụng xác thực chạy trên cùng một điện thoại (Haupert và Müller, 2018). Chương 8 phải dẫn các bài này khi nêu A6 là ngoài phạm vi.

| Mã | Mục tiêu | Kịch bản dùng để kiểm |
|---|---|---|
| G1 | Toàn vẹn ủy quyền: server chỉ thực hiện T nếu thiết bị đã tạo mã cho đúng T | S4, S5 |
| G2 | Tính tươi | S6, S7 |
| G3 | Dùng một lần | S8 |
| G4 | Chống đoán, **trong phạm vi một giao dịch** (không có giới hạn theo người dùng, xem Limitations) | S9 |
| G5 | Chịu được lộ DB (lộ dữ liệu khóa trong bảng `devices`, thiết bị đã đăng ký giữ nguyên) | S10 |
| G6 | Bằng chứng kiểm chứng được bởi bên thứ ba (điều kiện cần, chưa đủ, của chống chối bỏ) | S11 |
| G7 | WYSIWYS: người dùng đã thấy đúng T (với người dùng lý tưởng, xem mục 6) | S2a, S3 |

**Phạm vi của G5 (S10).** S10 chỉ xét *lộ dữ liệu khóa trong DB* (đọc được bảng `devices`) khi thiết bị đăng ký vẫn giữ nguyên: ở `sig`/`sig_blind`, DB chỉ chứa *public key* nên không giả mạo được chữ ký. Một mối đe dọa *khác* là kẻ chiếm được session hợp lệ rồi đăng ký lại thiết bị bằng khóa của mình — mối này được chặn riêng ở tầng đăng ký, không thuộc G5: `server/auth.py` từ chối (`enroll_rejected`, "device already enrolled") và `GET /enroll` trả 409 khi user đã có thiết bị, nên một session đơn thuần không thể thay khóa (xem mục Enrolment, A1).

**Giới hạn của G6 (bắt buộc ghi vào Chương 6 và Limitations).** S11 chỉ cho thấy bằng chứng lưu trong DB kiểm được bằng public key mà không cần khóa bí mật nào của ngân hàng. Nó chưa phải chống chối bỏ, vì hai lý do: (1) authenticator là web app do chính server ngân hàng phục vụ, nên ngân hàng có thể gửi JavaScript khác để dùng khóa ký cho giao dịch bất kỳ (khóa non-extractable chỉ chống *xuất* khóa, không chống *dùng* khóa); (2) public key chỉ nằm trong bảng `devices` của ngân hàng, không có bên độc lập nào chứng thực nó thuộc về người dùng, nên ngân hàng có thể thay khóa. Report dùng cụm *verifiable evidence*, không dùng *non-repudiation* cho kết quả của S11; ở `sig_blind` còn thêm chú thích dấu \* như dưới bảng kịch bản.

## 6. Kế hoạch đánh giá

**Mô hình người dùng:** `attentive_user` đồng ý khi điện thoại không hiển thị gì (ký mù), hoặc khi `to` và `amount` hiển thị khớp với ý định. `careless_user` luôn đồng ý. Ở chế độ `baseline`, điện thoại không hiển thị giao dịch còn trình duyệt bị MitB làm giả, nên người dùng luôn nhập mã.

**Giới hạn của mô hình người dùng (bắt buộc ghi vào Chương 6 và Limitations).** `attentive_user` là người dùng lý tưởng: luôn đọc và luôn phát hiện sai lệch. Người thật nằm giữa hai mô hình. Nghiên cứu của AlZomai và cộng sự (AISC 2008) trên ngân hàng mô phỏng báo cáo rằng một phần đáng kể tấn công vẫn qua được bước kiểm tra của người dùng, nhất là khi chỉ một chữ số tài khoản bị đổi; Haupert và Gabert (ESORICS 2019) khảo sát 100 khách hàng thật cũng với câu hỏi này. Hệ quả:
- Ô `blocked` của S2a và S3, và dấu ✓ của G7, là **cận trên**: chúng nói cơ chế *cho phép* người dùng phát hiện, không nói người dùng *sẽ* phát hiện. S2b là cận dưới.
- Kịch bản S2a đổi cả tài khoản nhận (khác nhiều chữ số), là trường hợp dễ phát hiện nhất.
- Buổi usability P4 đã bị lược bỏ; kể cả khi còn, nó không có lần thử nào bị tấn công nên không đo được tỷ lệ phát hiện. Report không được suy ra tỷ lệ phát hiện từ thử nghiệm của nhóm.
- Số liệu cụ thể của hai nghiên cứu trên phải lấy từ bài gốc trước khi trích (bản review ngày 11/11 mới chỉ có số từ thông cáo báo chí: 21% tấn công lộ liễu và 61% tấn công kín thành công).

**Kết quả mong đợi** (`blocked`/`ok`/`yes` = tốt; `succeeded`/`no` = xấu; `n/a` = không áp dụng):

| Mã | Kịch bản | baseline | hmac | sig | sig_blind |
|---|---|---|---|---|---|
| S1 | Giao dịch bình thường | ok | ok | ok | ok |
| S2a | MitB đổi tài khoản nhận, người dùng cẩn thận | succeeded | blocked | blocked | succeeded |
| S2b | MitB đổi tài khoản nhận, người dùng cẩu thả | succeeded | succeeded | succeeded | succeeded |
| S3 | MitB đổi số tiền thành 9.000.000 | succeeded | blocked | blocked | succeeded |
| S4 | MitB làm giả QR chứa giao dịch gốc | succeeded | blocked | blocked | blocked |
| S5 | Sửa từng trường (to, to_name, amount, currency, from, nonce, exp, tx_id) sau khi đã có mã | succeeded | blocked | blocked | blocked |
| S6 | Replay mã cho giao dịch cũ và cho giao dịch mới giống hệt | blocked | blocked | blocked | blocked |
| S7 | Xác nhận sau khi hết hạn (+121 giây) | blocked | blocked | blocked | blocked |
| S8 | Gửi cùng một mã hợp lệ 50 lần đồng thời | blocked | blocked | blocked | blocked |
| S9 | 3 lần đoán sai, sau đó gửi mã đúng | blocked | blocked | blocked | blocked |
| S10 | Lộ DB, giả mạo giao dịch tới mallory | succeeded | succeeded | blocked | blocked |
| S11 | Bên thứ ba kiểm chứng được bằng chứng | no | no | yes | yes* |
| S12 | 14 payload QR không chuẩn | n/a | blocked | blocked | blocked |
| S13 | Chữ ký dị dạng (server không được trả 5xx) | n/a | n/a | blocked | blocked |

\* Với `sig_blind`, chữ ký chỉ chứng minh thiết bị đã ký, không chứng minh người dùng đã nhìn thấy giao dịch. Report phải ghi chú điểm này. `evaluation/latex.py` tự gắn dấu \* vào ô `sig_blind` của S11 và G6, kèm chú thích dưới bảng.

Trong bảng trên, S11 trả lời câu hỏi "bên thứ ba có kiểm được bằng chứng không"; xem giới hạn của G6 ở mục 5.

Thay đổi so với bản thảo trong chat: S6 ở `baseline` là `blocked` (vì baseline được cài đúng RFC, có chặn dùng lại bước thời gian); thêm S2b; G1 dùng S4/S5, còn G7 dùng S2a/S3, để tách bạch vai trò của *gắn mật mã* và *hiển thị*.

Phạm vi kiểm thử: phần lớn kịch bản chạy end-to-end qua `TestClient` của server, nhưng **S5, S12 và S13 là kiểm offline** thực thi trực tiếp trên lõi `tba_core`/harness (sửa từng trường rồi kiểm lại mã, 14 payload QR dị dạng, chữ ký r‖s dị dạng) chứ không đi qua HTTP; chúng kiểm bất biến của hàm mã hóa/verify, không phải hành vi tầng web.

**Thí nghiệm brute-force (S9):** mô phỏng 100.000 giao dịch với OTP 3 và 4 chữ số, mỗi giao dịch đoán 3 lần; so sánh với lý thuyết `3/10^d` (hmac) và `1 − C(10^d−3,3)/C(10^d,3)` (baseline, cửa sổ 3 mã); ngoại suy lý thuyết cho d = 6 và 8. Mọi con số là **xác suất trên mỗi giao dịch**.

**Giới hạn của G4 (bắt buộc ghi vào Chương 6 và mục Limitations ở Chương 8):** giới hạn 3 lần thử tính theo từng giao dịch (`server/verify.py`, `settings.max_attempts`), không có bộ đếm theo người dùng hay thiết bị, và `create_transfer` không giới hạn số giao dịch đang chờ. Kẻ A4 (có mật khẩu, không có điện thoại) có thể tạo k giao dịch, mỗi giao dịch đoán 3 lần, nên xác suất thành công cộng dồn xấp xỉ k·p:
- `baseline` (6 chữ số, cửa sổ 3 mã): p ≈ 9,0·10⁻⁶ mỗi giao dịch; khoảng 7,7·10⁴ giao dịch cho 50%.
- `hmac` (8 chữ số): p = 3·10⁻⁸ mỗi giao dịch; khoảng 2,3·10⁷ giao dịch cho 50%.
- `sig`/`sig_blind`: phải giả mạo chữ ký ECDSA, không đoán được.

Đây là **mô hình lý tưởng**: các con số cộng dồn k·p chỉ là cận trên giải tích, giả định cửa sổ mã giữ nguyên trong suốt chiến dịch đoán. Riêng với `baseline`, mã TOTP đổi mỗi 30 giây, nên không được diễn giải hàng chục nghìn giao dịch trong *một* cửa sổ TOTP là năng lực thực tế đã được đo; nếu đoán không lặp trong một cửa sổ cố định thì mốc 50% theo mô hình không-lặp (`1 − C(10⁶−3,3k)/C(10⁶,3k)`) rơi vào khoảng 6,9·10⁴ giao dịch, hơi thấp hơn xấp xỉ có-lặp 7,7·10⁴ ở trên. Con số thực nghiệm đo được trong `results/bruteforce.csv` chỉ là **xác suất trên mỗi giao dịch**, không phải tỷ lệ cộng dồn.

Vì vậy dấu ✓ của G4 trong bảng mục tiêu chỉ có nghĩa là "cơ chế khóa theo giao dịch hoạt động". Cách khắc phục (ngoài phạm vi): bộ đếm sai theo người dùng hoặc thiết bị và giới hạn tốc độ tạo giao dịch. Cách này có đánh đổi: kẻ có mật khẩu có thể cố tình đoán sai để khóa tài khoản nạn nhân (DoS).

**Hiệu năng:**
- P1: median và p95 (10.000 lần) cho canonical, TOTP, HMAC-OTP, ECDSA ký/verify, Ed25519 ký/verify, kèm thông tin máy.
- P2: thời gian ký trên điện thoại (200 lần, `performance.now()`).
- P3: kích thước dữ liệu và phiên bản QR.
- P4 (thời gian hoàn thành giao dịch, 6 người): ĐÃ LƯỢC BỎ khỏi phạm vi bài.

**Đầu ra:** `make eval` ghi vào `results/`: `scenarios.csv`, `scenarios.tex`, `goals.tex`, `bench.csv`, `bench.pdf`, `bench_env.json`, `sizes.csv`, `bruteforce.csv`, `bruteforce.pdf`.

**Tùy chọn:** mô hình ProVerif cho `sig` (tính chất phải đúng) và `sig_blind` (tính chất phải sai).

## 7. Report

| Chương | Trang | Người viết | Hình/bảng bắt buộc |
|---|---|---|---|
| Trang bìa | 1 | TV1 | Bảng thành viên: họ tên, mã SV, vai trò |
| Abstract | 0,3 | TV1 | |
| 1 Introduction | 1,5 | TV1 | RQ1-RQ3, contributions |
| 2 Background & Related Work | 3 | TV6 + TV2 | T1 so sánh các giải pháp hiện có |
| 3 Threat Model & Goals | 2 | TV6 | T2 kẻ tấn công, T3 mục tiêu |
| 4 System Design | 3 | TV2 + TV3 | F1 kiến trúc, F2 đăng ký, F3 xác nhận khi bị MitB, T4 mật mã |
| 5 Implementation | 2 | TV3 + TV4 | F7 ảnh giao diện, đoạn code trích |
| 6 Security Evaluation | 4 | TV5 + TV6 | F4 cặp ảnh MitB, T5 kịch bản, F5 brute-force, T6 ma trận mục tiêu |
| 7 Performance & Usability | 1,5 | TV2 + TV4 + TV6 | F6, T7, T8 |
| 8 Discussion & Limitations | 1,5 | TV1 + TV5 | |
| 9 Conclusion | 0,5 | TV1 | |
| References | 1 | Tất cả | IEEE, mỗi tài liệu đã kiểm tra bản gốc; danh sách bắt buộc ở master plan Task R1 Step 4 |
| Phụ lục A-E | | Tất cả | Repo, API, vectors, kết quả đầy đủ, bảng đóng góp |

**Quy ước:** thuật ngữ thống nhất (*transaction binding*, *authenticator*, *challenge*, *blind-signing mode*, *verifiable evidence*); mọi số liệu lấy từ `results/`; mọi khẳng định về tấn công dẫn mã kịch bản; không chép nguyên văn từ nguồn.

**Định vị so với tài liệu đã có (Ch.1 và Ch.2):** gắn mã xác thực vào giao dịch không phải ý tưởng mới. Nó đã được đề xuất và triển khai từ lâu (Hiltgen và cộng sự 2006; ZTIC 2008; chipTAN, photoTAN; chế độ chữ ký của OCRA, RFC 6287 mục 7.3; "dynamic linking" ở Điều 5 Quy định (EU) 2018/389; W3C Secure Payment Confirmation). Đóng góp của report là *cài đặt và so sánh có kiểm soát* bốn chế độ trên cùng một hệ thống, cùng thí nghiệm `sig_blind` tách vai trò của hiển thị khỏi vai trò của mật mã. Không viết rằng nhóm đề xuất cơ chế mới. Chế độ `hmac` là "kiểu OCRA", không phải OCRA đúng chuẩn (không có OCRASuite, không theo định dạng DataInput); RFC 4226, 6238 và 6287 đều là Informational.

## 8. Rủi ro

| Rủi ro | Phương án dự phòng |
|---|---|
| Web Crypto không chạy trên điện thoại | Cài root CA của mkcert lên điện thoại → tunnel `cloudflared` → laptop thứ hai (ghi vào Limitations) |
| Tích hợp bị trễ | Phần đánh giá chạy trên `VirtualPhone`, không phụ thuộc điện thoại thật |
| Trích dẫn quy định Việt Nam đã hết hiệu lực | Kiểm tra hiệu lực của Quyết định 2345/QĐ-NHNN trước khi trích (xem master plan Task R1 Step 4) |
| Python và JS lệch nhau | `shared/vectors.json` được kiểm ở cả hai phía |
| `mitmproxy` xung đột thư viện | Cài riêng bằng `pipx`; addon chỉ dùng stdlib (+ `segno` nếu giả QR) |

## 9. Ngoài phạm vi

Push notification, app native, WebAuthn, HSM, nhiều thiết bị trên một người dùng, chống CSRF ngoài SameSite=Lax, chống DoS (kẻ biết `tx_id` có thể làm hết lượt thử; ghi vào Limitations).
