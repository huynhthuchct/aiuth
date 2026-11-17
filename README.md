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
| `aiuth remove <tên>` | Xoá tài khoản đã lưu và backup của nó |

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
