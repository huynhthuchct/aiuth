# Worker riêng cho aiuth

Worker này chỉ phục vụ đồng bộ tài khoản Codex của `aiuth`, tách biệt với Worker Authenticator và FB Account Switcher. Không lưu token Codex dạng rõ.

## Triển khai

Cách tự động (Windows / macOS / Linux, Node >= 22.12.0):

```sh
aiuth sync setup
```

Lệnh tự chạy các bước Cloudflare bên dưới. Nếu chưa đăng nhập, trình duyệt sẽ mở để bạn bấm Allow. File triển khai và mã thiết lập được giữ trong `$CODEX_HOME/aiuth-worker/` (mặc định `~/.codex/aiuth-worker/`), không ghi vào thư mục cài npm. Setup có thể chạy lại để cập nhật mà giữ database, dữ liệu và mã thiết lập cũ. Để chỉ lưu Worker sẵn có, dùng `aiuth sync setup <URL>`.

Cách thủ công:

Trong thư mục này, cần Node.js LTS và tài khoản Cloudflare:

```sh
npx --yes wrangler@4 login
npx --yes wrangler@4 d1 create aiuth-sync
```

Điền database ID được trả về vào `wrangler.toml`, binding giữ tên `DB`. Nếu database đã tồn tại, dùng ID cũ.

```sh
npx --yes wrangler@4 d1 execute aiuth-sync --remote --file=schema.sql --yes
npx --yes wrangler@4 deploy
npx --yes wrangler@4 secret put SETUP_CODE
```

Lệnh cuối hỏi một mã thiết lập do bạn chọn (nên dùng chuỗi ngẫu nhiên dài). Ghi lại địa chỉ `workers.dev` và mã vào nơi an toàn; không commit mã vào git. Bản cài đặt trên máy hiện tại lưu chúng trong `setup-info.txt` (đã bỏ qua trong git).

Chạy `aiuth sync setup <địa-chỉ>` rồi `aiuth sync`. Tự chọn mật khẩu đồng bộ khi đăng ký lần đầu, các máy khác dùng cùng mật khẩu. Mật khẩu khác với mã thiết lập.

Khi cập nhật, chạy lại `d1 execute aiuth-sync --remote --file=schema.sql --yes` trước `deploy` để thêm bảng mới. `schema.sql` chỉ dùng `CREATE TABLE IF NOT EXISTS`, giữ dữ liệu hiện có. Không xoá database.

Worker hỗ trợ `aiuth sync change-password` (giữ ciphertext và thay lớp bọc khoá) và `aiuth sync reset-password` (xác thực bằng SETUP_CODE, thay bản đồng bộ bằng local). Giữ kín mã thiết lập vì ai có mã có thể đặt lại tài khoản đồng bộ. Không có giới hạn khoá 15 phút.

## Kiểm thử

Từ thư mục gốc: `npm test`. Kiểm thử dùng database SQLite trong RAM, thư mục local tạm và token giả; không truy cập dữ liệu Codex thật.
