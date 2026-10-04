# Hướng dẫn đăng Ghost Authenticator lên Microsoft Store

Tài liệu này hướng dẫn chi tiết từng bước đóng gói và phát hành ứng dụng **Ghost Authenticator (.NET 8 WPF)** lên **Microsoft Store** thông qua Microsoft Partner Center bằng định dạng **MSIX**.

---

## 1. Cơ chế đóng gói tự động
Dự án đã được tích hợp sẵn công cụ tự động hóa đóng gói chuẩn Microsoft SDK:
- **File script**: `build-msix.bat`
- **Thư mục đầu ra**: `dist\GhostAuthenticator_1.0.0_x64.msix`
- **Công cụ sử dụng**: `Microsoft.Windows.SDK.BuildTools` (chứa `makeappx.exe` và `makepri.exe`)
- **Tài nguyên hình ảnh Store**: Nằm tại `Images\` (gồm đầy đủ các tỷ lệ Scale 100%, 125%, 150%, 200%, 400% và TargetSize 16x16 đến 256x256).

---

## 2. Quy trình đưa app lên Microsoft Store

### Bước 1: Đăng ký tài khoản Microsoft Partner Center
1. Truy cập: [partner.microsoft.com/dashboard/registration](https://partner.microsoft.com/dashboard/registration)
2. Đăng nhập bằng tài khoản Microsoft (Outlook / Live / Hotmail).
3. Chọn loại tài khoản cá nhân (**Individual developer**) hoặc doanh nghiệp (**Company**).
4. Hoàn tất xác minh danh tính.

---

### Bước 2: Giữ tên ứng dụng (Reserve App Name)
1. Trong giao diện Partner Center Dashboard, chọn **Apps and games** (hoặc **Windows & Xbox**).
2. Bấm **New product** -> Chọn **MSIX or PWA app**.
3. Nhập tên ứng dụng: **Ghost Authenticator**.
4. Bấm **Reserve product name** (Giữ tên thành công).

---

### Bước 3: Lấy thông tin định danh (Product Identity)
Sau khi giữ tên xong, vào mục:
**Product management** -> **Product identity**

Bạn sẽ thấy 3 thông tin quan trọng:
1. **Package/Identity/Name**: Ví dụ `12345NQATech.GhostAuthenticator`
2. **Package/Identity/Publisher**: Ví dụ `CN=A1B2C3D4-E5F6-7890-ABCD-1234567890AB`
3. **Package/Properties/PublisherDisplayName**: Ví dụ `Nguyen Quoc Anh`

---

### Bước 4: Cập nhật `Package.appxmanifest`
Mở file `D:\GhostAuthenticator\Package.appxmanifest` và cập nhật chính xác 3 thông tin trên vào:

```xml
  <Identity
    Name="[Điền Package/Identity/Name từ Partner Center vào đây]"
    Publisher="[Điền Package/Identity/Publisher từ Partner Center vào đây]"
    Version="1.0.0.0" />

  <Properties>
    <DisplayName>Ghost Authenticator</DisplayName>
    <PublisherDisplayName>[Điền PublisherDisplayName từ Partner Center vào đây]</PublisherDisplayName>
    <Logo>Images\StoreLogo.scale-100.png</Logo>
    ...
  </Properties>
```

> **Lưu ý**: Nếu thông tin trong `Package.appxmanifest` không khớp với Partner Center, khi tải gói lên hệ thống sẽ báo lỗi *"Package identity does not match reserved name"*.

---

### Bước 5: Build file MSIX hoàn chỉnh
Chạy file script đóng gói:
```cmd
cd /d D:\GhostAuthenticator
build-msix.bat
```
Script sẽ tự động:
1. `dotnet publish` project ở chế độ Release x64.
2. Sao chép các binary và `AppxManifest.xml` vào staging.
3. Tạo chỉ mục tài nguyên hiển thị DPI bằng `makepri.exe`.
4. Đóng gói ra file: **`dist\GhostAuthenticator_1.0.0_x64.msix`** (~13 MB).

---

### Bước 6: Tải gói lên và nộp duyệt (Submission)
1. Trong Partner Center, bấm **Start your submission**.
2. **Pricing and availability**: Chọn Miễn phí (**Free**) và chọn các thị trường phát hành (Toàn cầu / Worldwide).
3. **Properties**:
   - Category: **Security** (hoặc **Developer tools / Utilities**).
   - Display mode: Desktop.
4. **Age ratings**: Trả lời khảo sát IARC (App 2FA không chứa bạo lực, nội dung nhạy cảm -> rating phù hợp mọi lứa tuổi).
5. **Packages**: 
   - Kéo thả file **`dist\GhostAuthenticator_1.0.0_x64.msix`** vào ô upload.
   - Hệ thống sẽ tự động phân tích file, xác nhận kiến trúc `x64`, khả năng tương thích Windows 10/11 và kiểm tra tính hợp lệ.
6. **Store listings** (Giao diện hiển thị trên Microsoft Store):
   - **Description**: Mô tả app (sao chép từ `README.md`).
   - **Screenshots**: Chụp 1–4 ảnh màn hình app chạy trên Windows (chế độ Dark / Light).
   - **Privacy Policy URL**: 
     `https://nguyenquocanhz.github.io/ghost-authenticator/privacy.html`
   - **Support Contact URL**: 
     `https://nguyenquocanhz.github.io/ghost-authenticator/support.html`
7. **Notes for certification** (Ghi chú cho đội ngũ kiểm duyệt):
   - Ghi chú: *"Ghost Authenticator is a 100% offline 2FA/TOTP desktop application for Windows. It generates time-based OTP codes (RFC 6238). No login account or cloud connection is required."*
8. Bấm **Submit to the Store**.

---

### Bước 7: Kiểm duyệt và xuất bản
- Đội ngũ Microsoft sẽ kiểm duyệt tự động và thủ công (thời gian thường từ 24h đến 48h).
- Khi được duyệt, Microsoft sẽ **tự động ký chứng chỉ số chính thức của Microsoft** lên gói MSIX của bạn (bạn không cần phải tự mua chứng chỉ số đắt tiền).
- App sẽ xuất hiện trực tiếp trên ứng dụng Microsoft Store của hàng trăm triệu máy tính Windows 10 & Windows 11 toàn cầu.
