using System;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Diagnostics;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Win32;

namespace GhostAuthenticatorSetup
{
    public partial class MainWindow : Window
    {
        private int _currentStep = 1;
        private string _targetDir = "";

        public MainWindow()
        {
            InitializeComponent();
            
            // Calculate default installation folder
            string localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            TxtInstallPath.Text = Path.Combine(localAppData, "GhostAuthenticator");
            
            ShowStep(1);
        }

        private void ShowStep(int step)
        {
            _currentStep = step;

            // Toggle Panel Visibility
            Step1Panel.Visibility = step == 1 ? Visibility.Visible : Visibility.Collapsed;
            Step2Panel.Visibility = step == 2 ? Visibility.Visible : Visibility.Collapsed;
            Step3Panel.Visibility = step == 3 ? Visibility.Visible : Visibility.Collapsed;
            Step4Panel.Visibility = step == 4 ? Visibility.Visible : Visibility.Collapsed;
            Step5Panel.Visibility = step == 5 ? Visibility.Visible : Visibility.Collapsed;

            // Configure Navigation Buttons
            BtnBack.Visibility = (step > 1 && step < 4) ? Visibility.Visible : Visibility.Collapsed;
            BtnCancel.Visibility = (step < 4) ? Visibility.Visible : Visibility.Collapsed;

            if (step == 4)
            {
                BtnNext.Visibility = Visibility.Collapsed;
                RunInstallation();
            }
            else if (step == 5)
            {
                BtnNext.Visibility = Visibility.Visible;
                BtnNext.Content = "Hoàn tất";
                BtnNext.Style = (Style)Resources["BtnPrimary"];
            }
            else
            {
                BtnNext.Visibility = Visibility.Visible;
                BtnNext.Content = "Tiếp tục";
                BtnNext.Style = (Style)Resources["BtnPrimary"];
            }
        }

        private void BtnNext_Click(object sender, RoutedEventArgs e)
        {
            if (_currentStep == 1)
            {
                string path = TxtInstallPath.Text.Trim();
                if (string.IsNullOrEmpty(path))
                {
                    MessageBox.Show("Vui lòng chọn hoặc nhập đường dẫn thư mục cài đặt.", "Lỗi đường dẫn", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }
                _targetDir = path;
                ShowStep(2);
            }
            else if (_currentStep == 2)
            {
                if (ChkSetupPassword.IsChecked == true)
                {
                    string password = TxtNewPassword.Password;
                    string confirm = TxtConfirmPassword.Password;

                    if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(confirm))
                    {
                        MessageBox.Show("Vui lòng nhập mật khẩu và xác nhận mật khẩu để bảo vệ cơ sở dữ liệu.", "Cài đặt mật khẩu", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }

                    if (password.Length < 8)
                    {
                        MessageBox.Show("Mật khẩu chính phải có độ dài tối thiểu 8 ký tự để đảm bảo an toàn.", "Yêu cầu bảo mật", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }

                    if (password != confirm)
                    {
                        MessageBox.Show("Mật khẩu xác nhận không trùng khớp.", "Mật khẩu không khớp", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }
                }
                ShowStep(3);
            }
            else if (_currentStep == 3)
            {
                ShowStep(4);
            }
            else if (_currentStep == 5)
            {
                // Launch application if selected
                if (ChkLaunchApp.IsChecked == true)
                {
                    try
                    {
                        string exePath = Path.Combine(_targetDir, "AuthenticatorDesktop.exe");
                        if (File.Exists(exePath))
                        {
                            Process.Start(new ProcessStartInfo
                            {
                                FileName = exePath,
                                UseShellExecute = true
                            });
                        }
                    }
                    catch { /* Ignore launch errors */ }
                }

                Close();
            }
        }

        private void BtnBack_Click(object sender, RoutedEventArgs e)
        {
            if (_currentStep > 1 && _currentStep < 4)
            {
                ShowStep(_currentStep - 1);
            }
        }

        private void BtnCancel_Click(object sender, RoutedEventArgs e)
        {
            var result = MessageBox.Show("Bạn có chắc chắn muốn hủy bỏ quá trình cài đặt Ghost Authenticator?", "Hủy cài đặt", MessageBoxButton.YesNo, MessageBoxImage.Question);
            if (result == MessageBoxResult.Yes)
            {
                Close();
            }
        }

        private void BtnBrowse_Click(object sender, RoutedEventArgs e)
        {
            // Use Microsoft.Win32.OpenFolderDialog added in .NET 8.0
            var dialog = new OpenFolderDialog
            {
                Title = "Chọn thư mục cài đặt Ghost Authenticator",
                InitialDirectory = TxtInstallPath.Text
            };

            if (dialog.ShowDialog() == true)
            {
                TxtInstallPath.Text = dialog.FolderName;
            }
        }

        private void ChkSetupPassword_Changed(object sender, RoutedEventArgs e)
        {
            if (PasswordInputsPanel != null)
            {
                PasswordInputsPanel.IsEnabled = ChkSetupPassword.IsChecked == true;
            }
        }

        // ==================== CORE INSTALLATION ENGINE ====================

        private async void RunInstallation()
        {
            try
            {
                // Progress tracker
                UpdateProgress(10, "Đang khởi tạo thư mục cài đặt...");
                await Task.Delay(500);

                // Create folder
                if (!Directory.Exists(_targetDir))
                {
                    Directory.CreateDirectory(_targetDir);
                }

                UpdateProgress(30, "Đang giải nén tài nguyên tệp chạy...");
                await Task.Delay(500);

                string exePath = Path.Combine(_targetDir, "AuthenticatorDesktop.exe");
                string iconPath = Path.Combine(_targetDir, "logo.ico");

                // Extract embedded resource files
                ExtractEmbeddedFile("GhostAuthenticatorSetup.AuthenticatorDesktop.exe", exePath);
                ExtractEmbeddedFile("GhostAuthenticatorSetup.logo.ico", iconPath);

                UpdateProgress(50, "Đang tạo cấu hình bảo mật...");
                await Task.Delay(500);

                // Setup Master Password if requested
                if (ChkSetupPassword.IsChecked == true)
                {
                    string password = TxtNewPassword.Password;
                    string securityPath = Path.Combine(_targetDir, "security.dat");

                    // Setup encryption
                    byte[] salt = Crypto.GenerateRandomBytes(16);
                    byte[] key = Crypto.DeriveKey(password, salt);

                    byte[] plainToken = Encoding.UTF8.GetBytes("AUTH-OK");
                    byte[] cipherToken = Crypto.Encrypt(plainToken, key);

                    byte[] securityData = new byte[salt.Length + cipherToken.Length];
                    Array.Copy(salt, 0, securityData, 0, salt.Length);
                    Array.Copy(cipherToken, 0, securityData, salt.Length, cipherToken.Length);

                    File.WriteAllBytes(securityPath, securityData);
                }

                UpdateProgress(70, "Đang đăng ký phím tắt & lối tắt...");
                await Task.Delay(500);

                // Create shortcuts
                if (ChkDesktopShortcut.IsChecked == true)
                {
                    string desktopPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "Ghost Authenticator.lnk");
                    CreateShortcut(exePath, desktopPath, iconPath);
                }

                if (ChkStartShortcut.IsChecked == true)
                {
                    string startMenuFolder = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), @"Microsoft\Windows\Start Menu\Programs");
                    if (!Directory.Exists(startMenuFolder)) Directory.CreateDirectory(startMenuFolder);
                    string startPath = Path.Combine(startMenuFolder, "Ghost Authenticator.lnk");
                    CreateShortcut(exePath, startPath, iconPath);
                }

                UpdateProgress(90, "Đang tạo bộ gỡ cài đặt...");
                await Task.Delay(500);

                // Write Uninstall script
                string uninstallerPath = Path.Combine(_targetDir, "uninstall.cmd");
                WriteUninstallerCmd(uninstallerPath, _targetDir);

                // Register uninstaller in Add/Remove programs registry
                if (ChkRegisterUninstall.IsChecked == true)
                {
                    RegisterUninstallerInRegistry(_targetDir, uninstallerPath, iconPath);
                }

                UpdateProgress(100, "Hoàn tất cài đặt!");
                await Task.Delay(500);

                ShowStep(5);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Có lỗi xảy ra trong quá trình cài đặt:\n" + ex.Message, "Lỗi cài đặt", MessageBoxButton.OK, MessageBoxImage.Error);
                ShowStep(1);
            }
        }

        private void UpdateProgress(double percent, string status)
        {
            ProgressBarInstall.Value = percent;
            TxtProgressPercent.Text = $"{(int)percent}%";
            TxtProgressStatus.Text = status;
        }

        private void ExtractEmbeddedFile(string resourceName, string targetPath)
        {
            var assembly = Assembly.GetExecutingAssembly();
            using (var stream = assembly.GetManifestResourceStream(resourceName))
            {
                if (stream == null)
                {
                    throw new Exception($"Không tìm thấy tài nguyên hệ thống: {resourceName}");
                }

                using (var fileStream = new FileStream(targetPath, FileMode.Create, FileAccess.Write))
                {
                    stream.CopyTo(fileStream);
                }
            }
        }

        private static void CreateShortcut(string targetPath, string shortcutPath, string iconPath)
        {
            try
            {
                string powershellCode = $"$WshShell = New-Object -ComObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('{shortcutPath.Replace("'", "''")}'); $Shortcut.TargetPath = '{targetPath.Replace("'", "''")}'; $Shortcut.IconLocation = '{iconPath.Replace("'", "''")}'; $Shortcut.Save()";
                
                var psi = new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-NoProfile -ExecutionPolicy Bypass -Command \"{powershellCode}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false
                };
                Process.Start(psi)?.WaitForExit();
            }
            catch { /* Ignore shortcut failures */ }
        }

        private static void WriteUninstallerCmd(string filePath, string targetDir)
        {
            string uninstallScript = $@"@echo off
title Go cai dat Ghost Authenticator
echo Dang tien hanh go cai dat...
taskkill /IM AuthenticatorDesktop.exe /F >nul 2>&1
reg delete ""HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\GhostAuthenticator"" /f >nul 2>&1
del ""%userprofile%\Desktop\Ghost Authenticator.lnk"" >nul 2>&1
del ""%appdata%\Microsoft\Windows\Start Menu\Programs\Ghost Authenticator.lnk"" >nul 2>&1

echo Xoa tệp tin ung dung...
cd \
rd /s /q ""{targetDir}"" >nul 2>&1

echo Da go cai dat Ghost Authenticator hoan tat.
echo Nhan phim bat ky de thoat.
pause >nul
";
            File.WriteAllText(filePath, uninstallScript, Encoding.GetEncoding(1258)); // ANSI encoding compatible
        }

        private static void RegisterUninstallerInRegistry(string installDir, string uninstallerCmdPath, string iconPath)
        {
            try
            {
                using (var key = Registry.CurrentUser.CreateSubKey(@"Software\Microsoft\Windows\CurrentVersion\Uninstall\GhostAuthenticator"))
                {
                    if (key != null)
                    {
                        key.SetValue("DisplayName", "Ghost Authenticator");
                        key.SetValue("UninstallString", $"\"{uninstallerCmdPath}\"");
                        key.SetValue("DisplayIcon", iconPath);
                        key.SetValue("Publisher", "Nguyen Quoc Anh");
                        key.SetValue("DisplayVersion", "1.0.0");
                        key.SetValue("InstallLocation", installDir);
                        key.SetValue("NoModify", 1);
                        key.SetValue("NoRepair", 1);
                    }
                }
            }
            catch { /* Ignore Registry access errors */ }
        }
    }
}
