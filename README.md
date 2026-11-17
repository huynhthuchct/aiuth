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
