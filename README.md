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
| `aiuth list` | Liệt kê tài khoản, `*` = đang dùng |
| `aiuth current` | Tài khoản đang dùng |
| `aiuth use <tên>` | Chuyển tài khoản (tự giữ auth hiện tại trước khi ghi đè) |
| `aiuth backup [tên]` | Backup có dấu thời gian |
| `aiuth backups <tên>` | Liệt kê backup |
| `aiuth restore <tên> [id\|latest]` | Khôi phục từ backup |
| `aiuth export <tên> [id]` | In 1 chuỗi `aiuth1:e:…` (mã hoá bằng passphrase) để dán sang máy khác |
| `aiuth import [chuỗi]` | Nhập chuỗi từ `export` (`--name`, `--use`) |
| `aiuth send <tên> [id]` | Chờ 1 máy trong LAN nhận trực tiếp, in lệnh `receive` kèm mã 8 ký tự |
| `aiuth receive <ip:port> <mã>` | Nhận tài khoản từ máy đang `send` (`--name`, `--use`) |
| `aiuth remove <tên>` | Xoá tài khoản đã lưu và backup của nó |

## Chuyển sang máy khác

```bash
# máy A
aiuth send <tên>                      # in: aiuth receive 192.168.1.5:7421 K7P4-QX9M
# máy B (cùng mạng / Tailscale / VPN)
aiuth receive 192.168.1.5:7421 K7P4-QX9M --use
```

`send` chỉ phục vụ đúng 1 lần, tự đóng sau 5 phút hoặc sau 3 lần sai mã. Dữ liệu mã hoá bằng mã đó, mã không đi qua mạng. Khác mạng thì dùng `export` / `import`.

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
