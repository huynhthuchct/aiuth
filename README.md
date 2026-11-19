# aiuth

Quản lý nhiều tài khoản cho `~/.codex/auth.json` của Codex CLI. Không phụ thuộc thư viện, cần Node >= 18.

```bash
npm i -g aiuth
# hoặc chạy thẳng: npx aiuth list
```

## Lệnh

| Lệnh | Tác dụng |
|---|---|
| `aiuth add [tên]` | Thêm tài khoản mới bằng `codex login --device-auth`, **không logout** tài khoản cũ |
| `aiuth save [tên]` | Lưu auth hiện tại thành tài khoản (mặc định tên = email) |
| `aiuth list [--usage]` | Liệt kê tài khoản, `*` = đang dùng |
| `aiuth current` | Tài khoản đang dùng |
| `aiuth usage [tên]` | Thống kê limit từng tài khoản: % đã dùng, thời gian reset, credits (`--json`) |
| `aiuth use <số\|tên>` | Chuyển tài khoản (tự giữ auth hiện tại trước khi ghi đè) |
| `aiuth send <tên>` | Chờ 1 máy trong LAN nhận trực tiếp, in lệnh `receive` kèm mã 8 ký tự |
| `aiuth receive <ip:port> <mã>` | Nhận tài khoản từ máy đang `send` (`--name`, `--use`) |
| `aiuth remove <tên>` | Xoá tài khoản đã lưu và backup của nó |
| `aiuth sync setup` | Tự cài Cloudflare: đăng nhập, tạo D1, tạo bảng, deploy Worker và lưu mã thiết lập |
| `aiuth sync setup <URL>` | Chỉ lưu địa chỉ Worker đã có, không deploy |
| `aiuth sync [--url URL]` | Kéo Worker → merge với local → ghi bản gộp lên Worker và local |
| `aiuth sync change-password` | Đổi mật khẩu bằng mật khẩu cũ, giữ dữ liệu Worker |
| `aiuth sync reset-password` | Quên mật khẩu: dùng mã thiết lập, thay bản Worker bằng dữ liệu local |

## Đồng bộ qua Cloudflare Worker

```bash
aiuth sync setup
aiuth sync
```

`aiuth sync setup` chạy đủ 6 bước: kiểm tra Node.js/npx, đăng nhập Cloudflare (mở trình duyệt nếu cần), tìm hoặc tạo D1 `aiuth-sync`, tạo bảng, deploy Worker và lưu mã thiết lập cùng URL. Cần Node >= 22.12.0 để cài Cloudflare; chức năng CLI khác vẫn cần Node >= 18. Chạy được trên Windows, macOS và Linux, không cần shell script.

File Worker và mã thiết lập nằm trong `$CODEX_HOME/aiuth-worker/` (mặc định `~/.codex/aiuth-worker/`); mã được lưu ở `setup-info.txt` với quyền 0600. Chạy lại setup để cập nhật: database và dữ liệu giữ nguyên, mã hiện có được dùng lại. Bản source cũ có `sync-worker/setup-info.txt` sẽ được đọc để giữ mã cũ nếu trùng URL.

Mỗi lần `sync`, nhập mật khẩu đồng bộ (tối thiểu 8 ký tự). Lần đầu trên Worker trống cần thêm mã thiết lập `SETUP_CODE` trong file thông tin; các máy sau dùng cùng địa chỉ và mật khẩu. Có thể đặt `AIUTH_SYNC_URL`, `AIUTH_SYNC_PASSWORD`, `AIUTH_SYNC_SETUP_CODE` cho chạy không tương tác. Không truyền mật khẩu bằng tham số dòng lệnh.

- Kéo và giải mã dữ liệu Worker trước, rồi gộp theo danh tính tài khoản. **Local được ưu tiên** khi trùng tài khoản; auth live được ưu tiên nếu là cùng tài khoản local.
- Trùng tên nhưng khác tài khoản: bản remote nhận hậu tố `-remote-...`, giữ cả hai. Tài khoản chỉ có trên Worker được thêm vào local.
- Ghi bản gộp lên Worker bằng kiểm tra revision; nếu máy khác vừa ghi, kéo lại và gộp lại, tối đa 4 lượt.
- Không xoá tài khoản local, không chuyển tài khoản đang dùng, không ghi đè `auth.json` live hoặc backup cũ. Tài khoản nhập về có backup riêng.
- Xoá một tài khoản ở local sẽ **không** xoá nó trên Worker; lần sync tiếp theo sẽ kéo lại. Đây là lệnh gộp, không đồng bộ thao tác xoá.
- Worker chỉ giữ ciphertext AES-256-GCM; mật khẩu và khoá giải mã không gửi lên Worker. File `~/.codex/aiuth-sync.json` chỉ chứa địa chỉ máy chủ. Giới hạn bản rõ là 500 KB.
- Đừng chia sẻ mật khẩu hoặc mã thiết lập. Quên mật khẩu không giải mã lại được bản cũ; reset chỉ tải lại dữ liệu còn ở local.

### Đổi hoặc quên mật khẩu đồng bộ

```bash
aiuth sync change-password
aiuth sync reset-password
# alias cho lệnh quên mật khẩu:
aiuth sync forgot-password
```

`change-password` hỏi mật khẩu hiện tại và mật khẩu mới hai lần. Lệnh chỉ bọc lại khoá dữ liệu, giữ nguyên bản dữ liệu đã mã hoá trên Worker và thu hồi các phiên đồng bộ cũ. Các máy khác cần cập nhật aiuth và nhập mật khẩu mới.

`reset-password` hỏi mật khẩu mới, yêu cầu gõ `RESET` và mã thiết lập trong `~/.codex/aiuth-worker/setup-info.txt` (hoặc file cũ `sync-worker/setup-info.txt`). Bản Worker cũ bị thay bằng tài khoản local (ưu tiên auth live nếu có). Mục chỉ có trên Worker sẽ mất; `auth.json` đang dùng, danh sách tài khoản và backup local được giữ nguyên. Lệnh kiểm tra toàn bộ local trước, rồi thay mật khẩu và bản Worker trong cùng một transaction.

Đây là mật khẩu đồng bộ của aiuth, không đổi mật khẩu tài khoản OpenAI. Cả hai lệnh hỗ trợ `--url URL`.

Chạy không tương tác: đặt `AIUTH_SYNC_NEW_PASSWORD`; khi đổi mật khẩu đặt thêm `AIUTH_SYNC_PASSWORD` (mật khẩu cũ). Khi reset đặt `AIUTH_SYNC_SETUP_CODE` và truyền `--confirm-reset` để xác nhận việc thay bản Worker. Không đưa mật khẩu vào tham số dòng lệnh. Các lệnh không lưu mật khẩu vào file cấu hình.

Source và hướng dẫn triển khai Worker: [sync-worker/README.md](sync-worker/README.md). Chạy trực tiếp bản source bằng `node aiuth.mjs sync` nếu chưa cài lại bản CLI mới.

## Chuyển sang máy khác

```bash
# máy A
aiuth send <tên>                      # in: aiuth receive 192.168.1.5:7421 K7P4-QX9M
# máy B (cùng mạng / Tailscale / VPN)
aiuth receive 192.168.1.5:7421 K7P4-QX9M --use
```

`send` chỉ phục vụ đúng 1 lần, tự đóng sau 5 phút hoặc sau 3 lần sai mã. Dữ liệu mã hoá bằng mã đó, mã không đi qua mạng. Hai máy cần kết nối được với nhau (cùng LAN, hoặc qua Tailscale/VPN).

## Chuyển qua hộp thư (khác mạng)

```bash
aiuth mail setup                 # một lần: email + mật khẩu ứng dụng (app password), lưu ở ~/.codex/aiuth-mail.json (0600)
# máy A
aiuth send <tên> --mail          # in: aiuth receive --mail K7P4-QX9M-LB2S
# máy B (đã chạy mail setup cùng hộp thư)
aiuth receive --mail K7P4-QX9M-LB2S --use
```

Dữ liệu mã hoá bằng mã 12 ký tự trước khi gửi; mã không nằm trong thư. Thư nhận xong bị xoá khỏi INBOX, thư quá 24 giờ bị từ chối. Bản trong thư mục Đã gửi/Thùng rác của nhà cung cấp mail có thể còn (vẫn là dữ liệu đã mã hoá). Có thể đặt thay file bằng biến môi trường `AIUTH_MAIL_USER`, `AIUTH_MAIL_PASS`, `AIUTH_SMTP`, `AIUTH_IMAP` (host:port, TLS ngầm định: 465/993).

## Lưu trữ

```
~/.codex/auth.json                     file live Codex đọc
~/.codex/accounts/<tên>/auth.json      bản mới nhất của tài khoản
~/.codex/accounts/<tên>/backups/*.json tối đa 20 bản
~/.codex/accounts/.unsaved/*.json      auth bị ghi đè mà chưa thuộc tài khoản nào
```

Đổi thư mục bằng biến môi trường `CODEX_HOME`. File được ghi với quyền `0600`.

## Lưu ý bảo mật

Các file trong `accounts/` chứa token đăng nhập dạng rõ (giống `auth.json`). Không commit, không chia sẻ.
