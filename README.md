# 🛡️ Hệ thống Giám sát Hạn SSL & Tên miền (Sysadmin Dashboard)

Hệ thống tự động kiểm tra **hạn chứng chỉ SSL/TLS** và **hạn đăng ký tên miền (WHOIS / RDAP)**, hiển thị giao diện quản trị trực quan trên **GitHub Pages (`https://duongnvd.github.io/ssl-monitor/`)** và gửi cảnh báo gia hạn qua **Mail Server Công ty (Groupware SMTP)** hoặc **Gmail SMTP**.

---

## ✨ Tính năng chính dành cho Sysadmin

1. **Giao diện Web trực quan trên GitHub Pages (`index.html`)**:
   - Thống kê tổng quan: Tổng số tên miền, An toàn (`> 30 ngày`), Sắp hết hạn (`≤ 30 ngày`), Khẩn cấp / Lỗi (`≤ 7 ngày`).
   - Thêm / Sửa / Xóa tên miền, hoặc **Nhập hàng loạt (Bulk Import)** trực tiếp ngay trên giao diện Web.
   - Tra cứu nhanh IP (qua Cloudflare DoH) và hạn tên miền (qua RDAP) ngay tức thì trên trình duyệt khi vừa thêm.
   - Hỗ trợ kiểm tra SSL trên cổng tùy chỉnh (`443`, `8443`, `465`, `587`, `993`...) và hỗ trợ nhập ngày hết hạn Domain thủ công (cho các tên miền nội bộ hoặc bị ẩn WHOIS).
   - Xem chi tiết chứng chỉ X.509 (Subject, Issuer CA, Serial, Giao thức TLS, Cipher, SANs, độ trễ) và thông tin nhà đăng ký tên miền (Registrar, Nameservers).
   - Xuất báo cáo ra file Excel **CSV**.

2. **Tự động quét ngầm bằng GitHub Actions (`.github/workflows/monitor.yml`)**:
   - Tự động chạy định kỳ mỗi ngày lúc **07:30 sáng (giờ Việt Nam)**.
   - Tự động chạy ngay lập tức mỗi khi bạn Thêm / Sửa / Xóa tên miền trên Web UI.
   - Có nút **"🔄 Quét ngay"** và **"✉️ Gửi Email Test"** trực tiếp từ giao diện Web.

3. **Cảnh báo Email qua Groupware Mail Server của công ty (`scripts/monitor.py`)**:
   - Tương thích hoàn toàn với các hệ thống Mail Groupware doanh nghiệp (Zimbra, Exchange, Synology MailPlus, Postfix/Dovecot, MDaemon, Kerio...) cũng như Gmail / Office 365.
   - Hỗ trợ cổng `587` (STARTTLS), `465` (SSL/TLS), `25` (Plain/Internal Relay), và tùy chọn bỏ qua kiểm tra chứng chỉ tự ký (`SMTP_SKIP_TLS_VERIFY=true`) cho mail server nội bộ.

---

## 🚀 Hướng dẫn Triển khai lên `https://duongnvd.github.io/ssl-monitor/`

### Bước 1: Tạo Repository và đẩy code lên GitHub
Tạo một repository mới tên là **`ssl-monitor`** trên tài khoản GitHub **`duongnvd`** (để ở chế độ Public nếu dùng GitHub Pages miễn phí), sau đó chạy lệnh trong thư mục dự án:

```powershell
cd C:\Users\DUONGNVD\.gemini\antigravity\scratch\ssl-monitor
git init
git branch -M main
git add .
git commit -m "feat: khởi tạo hệ thống giám sát SSL và Domain"
git remote add origin https://github.com/duongnvd/ssl-monitor.git
git push -u origin main
```

### Bước 2: Bật GitHub Pages
1. Vào repo `https://github.com/duongnvd/ssl-monitor` → chọn tab **Settings** → menu bên trái chọn **Pages**.
2. Tại mục **Build and deployment** → **Source**: chọn **Deploy from a branch**.
3. Chọn branch **`main`** và thư mục **`/ (root)`** → bấm **Save**.
4. Sau khoảng 1 phút, giao diện của bạn sẽ hoạt động tại:
   👉 **`https://duongnvd.github.io/ssl-monitor/`**

### Bước 3: Cấu hình Email Groupware Công ty (GitHub Secrets)
Vào repo `https://github.com/duongnvd/ssl-monitor` → **Settings** → **Secrets and variables** → **Actions** → bấm **New repository secret** và thêm các biến sau:

| Tên Secret | Giá trị cho Mail Server Công ty (Groupware) | Mô tả |
| :--- | :--- | :--- |
| `SMTP_HOST` | `mail.tencongty.com` | Địa chỉ SMTP của Mail Server công ty (hoặc `smtp.gmail.com`) |
| `SMTP_PORT` | `587` (hoặc `465`, `25`) | Cổng SMTP (`587` cho STARTTLS, `465` cho SSL, `25` cho Relay) |
| `SMTP_USER` | `alert@tencongty.com` | Tài khoản đăng nhập Mail Groupware |
| `SMTP_PASS` | `MatKhauCuaBan` | Mật khẩu tài khoản Mail (hoặc App Password nếu dùng Gmail) |
| `SMTP_FROM` | `SSL Monitor <alert@tencongty.com>` | Tên và địa chỉ người gửi hiển thị trong thư |
| `SMTP_TO` | `duongnvd@tencongty.com, it@tencongty.com` | Danh sách email nhận cảnh báo (cách nhau dấu phẩy) |
| `SMTP_SECURITY` | `auto` | Để `auto` (mặc định), hoặc ép kiểu `starttls` / `ssl` / `none` |
| `SMTP_SKIP_TLS_VERIFY` | `true` hoặc `false` | Đặt `true` nếu Mail Server công ty dùng chứng chỉ SSL tự ký |

### Bước 4: Gắn GitHub Token trên giao diện Web để Thêm / Xóa Domain
1. Tạo một Personal Access Token tại: [GitHub Personal Access Tokens](https://github.com/settings/tokens/new?scopes=repo,workflow&description=SSL-Domain-Monitor) (chọn quyền **`repo`** và **`workflow`**).
2. Mở trang **`https://duongnvd.github.io/ssl-monitor/`**, bấm nút **⚙️ Cấu hình & Email** ở góc trên bên phải.
3. Dán Token vào ô **GitHub Personal Access Token** → bấm **💾 Lưu Cấu hình** (Token chỉ lưu trong `localStorage` trên trình duyệt của riêng bạn).
4. Bấm thử **✉️ Gửi Email Test qua GitHub Actions** để kiểm tra nhận thư từ Groupware!
