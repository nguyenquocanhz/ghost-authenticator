using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using Microsoft.Win32;

namespace AuthenticatorDesktop
{
    public partial class MainWindow : Window
    {
        private const string DataFileName = "accounts.dat";
        private const string SecurityFileName = "security.dat";
        private const string DeletedFileName = "deleted_accounts.dat";
        private readonly string _dataPath;
        private readonly string _securityPath;
        private readonly string _biometricPath;
        private readonly string _deletedPath;
        private readonly DispatcherTimer _timer;
        private bool _isDarkMode = false;
        private List<Account> _allAccounts = new();
        private List<Account> _deletedAccounts = new();
        private byte[]? _derivedKey;
        public ObservableCollection<Account> DisplayAccounts { get; } = new();

        public MainWindow()
        {
            InitializeComponent();
            _dataPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, DataFileName);
            _securityPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, SecurityFileName);
            _biometricPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "biometric.dat");
            _deletedPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, DeletedFileName);
            
            AccountsList.ItemsSource = DisplayAccounts;
            
            // Check if Master Password has been initialized
            if (!File.Exists(_securityPath))
            {
                // First run: show Welcome Choice Panel (Create New vs Restore Backup)
                WelcomeChoicePanel.Visibility = Visibility.Visible;
                SetupPasswordPanel.Visibility = Visibility.Collapsed;
                UnlockPanel.Visibility = Visibility.Collapsed;
                AuthGrid.Visibility = Visibility.Visible;
                MainAppGrid.Visibility = Visibility.Collapsed;
            }
            else
            {
                // Subsequent run: show Unlock Lockscreen
                SetupPasswordPanel.Visibility = Visibility.Collapsed;
                UnlockPanel.Visibility = Visibility.Visible;
                AuthGrid.Visibility = Visibility.Visible;
                MainAppGrid.Visibility = Visibility.Collapsed;
                
                // Focus PasswordBox
                Dispatcher.BeginInvoke(DispatcherPriority.Input, new Action(() =>
                {
                    TxtMasterPassword.Focus();
                }));

                // Check if Windows Hello is set up
                if (File.Exists(_biometricPath))
                {
                    BtnHelloUnlock.Visibility = Visibility.Visible;
                    ChkWindowsHello.IsChecked = true;
                    // Auto trigger Windows Hello unlock on startup
                    Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(TriggerWindowsHelloUnlock));
                }
            }

            // Set up timer (ticks every second to update pins and progress bar)
            _timer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _timer.Tick += Timer_Tick;
            _timer.Start();

            // Initial calculations
            UpdatePins();
            UpdateProgressBar();
        }

        // ==================== ONBOARDING & MASTER PASSWORD FLOW ====================

        private void BtnChoiceCreateNew_Click(object sender, RoutedEventArgs e)
        {
            WelcomeChoicePanel.Visibility = Visibility.Collapsed;
            SetupPasswordPanel.Visibility = Visibility.Visible;
            Dispatcher.BeginInvoke(DispatcherPriority.Input, new Action(() =>
            {
                TxtNewPassword.Focus();
            }));
        }

        private void BtnChoiceRestore_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog
            {
                Title = "Chọn file sao lưu để khôi phục (Encrypted .ghostbak, JSON hoặc CSV)",
                Filter = "Tệp sao lưu 2FA (*.ghostbak;*.json;*.csv;*.txt)|*.ghostbak;*.json;*.csv;*.txt|GhostBak Encrypted (*.ghostbak)|*.ghostbak|JSON Backup (*.json)|*.json|CSV/TXT (*.csv;*.txt)|*.csv;*.txt"
            };

            if (ofd.ShowDialog() == true)
            {
                string ext = Path.GetExtension(ofd.FileName).ToLower();

                if (ext == ".ghostbak")
                {
                    string password = Microsoft.VisualBasic.Interaction.InputBox(
                        "Nhập mật khẩu đã dùng để bảo vệ file sao lưu .ghostbak này:\n(Mật khẩu này cũng sẽ được thiết lập làm Mật Khẩu Chính cho ứng dụng)",
                        "Khôi Phục Bản Sao Lưu Encrypted .ghostbak",
                        "");

                    if (string.IsNullOrWhiteSpace(password))
                    {
                        MessageBox.Show("Vui lòng nhập mật khẩu để giải mã file sao lưu.", "Hủy khôi phục", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }

                    try
                    {
                        byte[] encryptedBytes = File.ReadAllBytes(ofd.FileName);
                        string json = Crypto.DecryptGhostBak(encryptedBytes, password);
                        var imported = JsonSerializer.Deserialize<List<Account>>(json);
                        if (imported == null || imported.Count == 0)
                        {
                            MessageBox.Show("File sao lưu không chứa tài khoản hợp lệ nào.", "Lỗi dữ liệu", MessageBoxButton.OK, MessageBoxImage.Error);
                            return;
                        }

                        // Initialize security vault with this password
                        byte[] salt = Crypto.GenerateRandomBytes(16);
                        byte[] key = Crypto.DeriveKey(password, salt);
                        byte[] plainToken = Encoding.UTF8.GetBytes("AUTH-OK");
                        byte[] cipherToken = Crypto.Encrypt(plainToken, key);
                        byte[] securityData = new byte[salt.Length + cipherToken.Length];
                        Array.Copy(salt, 0, securityData, 0, salt.Length);
                        Array.Copy(cipherToken, 0, securityData, salt.Length, cipherToken.Length);
                        File.WriteAllBytes(_securityPath, securityData);

                        _derivedKey = key;
                        _allAccounts = imported;
                        SaveAccounts();

                        // Open App
                        WelcomeChoicePanel.Visibility = Visibility.Collapsed;
                        AuthGrid.Visibility = Visibility.Collapsed;
                        MainAppGrid.Visibility = Visibility.Visible;
                        UpdateUIList();
                        UpdatePins();

                        MessageBox.Show($"Khôi phục thành công {imported.Count} tài khoản từ bản sao lưu .ghostbak!\nMật khẩu chính của ứng dụng đã được thiết lập theo mật khẩu file sao lưu.", "Khôi phục hoàn tất", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Giải mã file sao lưu thất bại. Mật khẩu không đúng hoặc file bị hư hỏng.\nChi tiết: " + ex.Message, "Lỗi giải mã", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
                else
                {
                    // JSON or CSV File
                    string password = Microsoft.VisualBasic.Interaction.InputBox(
                        "Tệp sao lưu này là bản rõ (JSON/CSV). Vui lòng đặt Mật Khẩu Chính (Master Password) mới để bảo vệ ứng dụng:",
                        "Thiết Lập Mật Khẩu Chính Khôi Phục",
                        "");

                    if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
                    {
                        MessageBox.Show("Mật khẩu chính phải có tối thiểu 8 ký tự.", "Mật khẩu không hợp lệ", MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }

                    try
                    {
                        string fileContent = File.ReadAllText(ofd.FileName);
                        List<Account> importedAccounts = new();

                        if (ext == ".json")
                        {
                            var parsed = JsonSerializer.Deserialize<List<Account>>(fileContent);
                            if (parsed != null) importedAccounts = parsed;
                        }
                        else
                        {
                            // CSV/TXT Parsing
                            _allAccounts = new List<Account>();
                            ImportFromCsvText(fileContent);
                            importedAccounts = new List<Account>(_allAccounts);
                        }

                        if (importedAccounts.Count == 0)
                        {
                            MessageBox.Show("Không tìm thấy dữ liệu tài khoản 2FA hợp lệ nào trong tệp tin.", "Lỗi dữ liệu", MessageBoxButton.OK, MessageBoxImage.Warning);
                            return;
                        }

                        // Initialize security vault with this password
                        byte[] salt = Crypto.GenerateRandomBytes(16);
                        byte[] key = Crypto.DeriveKey(password, salt);
                        byte[] plainToken = Encoding.UTF8.GetBytes("AUTH-OK");
                        byte[] cipherToken = Crypto.Encrypt(plainToken, key);
                        byte[] securityData = new byte[salt.Length + cipherToken.Length];
                        Array.Copy(salt, 0, securityData, 0, salt.Length);
                        Array.Copy(cipherToken, 0, securityData, salt.Length, cipherToken.Length);
                        File.WriteAllBytes(_securityPath, securityData);

                        _derivedKey = key;
                        _allAccounts = importedAccounts;
                        SaveAccounts();

                        // Open App
                        WelcomeChoicePanel.Visibility = Visibility.Collapsed;
                        AuthGrid.Visibility = Visibility.Collapsed;
                        MainAppGrid.Visibility = Visibility.Visible;
                        UpdateUIList();
                        UpdatePins();

                        MessageBox.Show($"Khôi phục thành công {importedAccounts.Count} tài khoản 2FA và khởi tạo kho bảo mật thành công!", "Khôi phục hoàn tất", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("Đọc file sao lưu thất bại: " + ex.Message, "Lỗi đọc tệp", MessageBoxButton.OK, MessageBoxImage.Error);
                    }
                }
            }
        }

        private void BtnSetupPassword_Click(object sender, RoutedEventArgs e)
        {
            string password = TxtNewPassword.Password;
            string confirm = TxtConfirmPassword.Password;

            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(confirm))
            {
                MessageBox.Show("Vui lòng nhập mật khẩu và xác nhận mật khẩu.", "Thiết lập mật khẩu", MessageBoxButton.OK, MessageBoxImage.Warning);
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

            try
            {
                // Setup US-Standard encryption (PBKDF2 SHA256 + AES256)
                byte[] salt = Crypto.GenerateRandomBytes(16);
                byte[] key = Crypto.DeriveKey(password, salt);

                byte[] plainToken = Encoding.UTF8.GetBytes("AUTH-OK");
                byte[] cipherToken = Crypto.Encrypt(plainToken, key);

                byte[] securityData = new byte[salt.Length + cipherToken.Length];
                Array.Copy(salt, 0, securityData, 0, salt.Length);
                Array.Copy(cipherToken, 0, securityData, salt.Length, cipherToken.Length);

                File.WriteAllBytes(_securityPath, securityData);

                // Save key in memory
                _derivedKey = key;

                // Initialize empty database
                _allAccounts = new List<Account>();
                SaveAccounts();

                // Unlock application
                AuthGrid.Visibility = Visibility.Collapsed;
                MainAppGrid.Visibility = Visibility.Visible;
                UpdateUIList();
                UpdatePins();

                MessageBox.Show("Thiết lập mật khẩu Master thành công. Cơ sở dữ liệu của bạn đã được mã hóa bằng AES-256.", "Hoàn tất thiết lập", MessageBoxButton.OK, MessageBoxImage.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Có lỗi xảy ra khi thiết lập mật khẩu: " + ex.Message, "Lỗi bảo mật", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BtnUnlock_Click(object sender, RoutedEventArgs e)
        {
            UnlockApplication();
        }

        private void TxtMasterPassword_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                UnlockApplication();
            }
        }

        private void TxtNewPassword_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                TxtConfirmPassword.Focus();
            }
        }

        private void TxtConfirmPassword_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Enter)
            {
                BtnSetupPassword_Click(this, new RoutedEventArgs());
            }
        }

        protected override void OnKeyDown(KeyEventArgs e)
        {
            base.OnKeyDown(e);

            // Esc to close modals
            if (e.Key == Key.Escape)
            {
                if (AddModal.Visibility == Visibility.Visible)
                {
                    AddModal.Visibility = Visibility.Collapsed;
                    e.Handled = true;
                }
                else if (AboutModal.Visibility == Visibility.Visible)
                {
                    AboutModal.Visibility = Visibility.Collapsed;
                    e.Handled = true;
                }
                else if (BackupImportModal.Visibility == Visibility.Visible)
                {
                    BackupImportModal.Visibility = Visibility.Collapsed;
                    e.Handled = true;
                }
            }

            // Ctrl shortcuts
            if (Keyboard.Modifiers == ModifierKeys.Control)
            {
                if (e.Key == Key.F || e.Key == Key.S)
                {
                    SearchBox.Focus();
                    SearchBox.SelectAll();
                    e.Handled = true;
                }
                else if (e.Key == Key.N)
                {
                    if (MainAppGrid.Visibility == Visibility.Visible)
                    {
                        BtnAdd_Click(this, new RoutedEventArgs());
                        e.Handled = true;
                    }
                }
                else if (e.Key == Key.C)
                {
                    if (AccountsList.SelectedItem is Account selected)
                    {
                        CopyOtpToClipboard(selected.Secret);
                        e.Handled = true;
                    }
                }
            }

            // Enter key on selected row in accounts list
            if (e.Key == Key.Enter && AccountsList.IsFocused)
            {
                if (AccountsList.SelectedItem is Account selected)
                {
                    CopyOtpToClipboard(selected.Secret);
                    e.Handled = true;
                }
            }
        }

        private void UnlockApplication()
        {
            string password = TxtMasterPassword.Password;

            if (string.IsNullOrEmpty(password))
            {
                MessageBox.Show("Vui lòng nhập mật khẩu để mở khóa.", "Mở khóa", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                if (!File.Exists(_securityPath))
                {
                    MessageBox.Show("Không tìm thấy tệp bảo mật. Vui lòng khởi động lại ứng dụng.", "Lỗi hệ thống", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                byte[] securityData = File.ReadAllBytes(_securityPath);
                if (securityData.Length < 16)
                {
                    MessageBox.Show("Tệp bảo mật bị hỏng. Vui lòng xóa tệp security.dat và cài đặt lại mật khẩu.", "Lỗi tệp", MessageBoxButton.OK, MessageBoxImage.Error);
                    return;
                }

                byte[] salt = new byte[16];
                Array.Copy(securityData, 0, salt, 0, 16);

                byte[] cipherToken = new byte[securityData.Length - 16];
                Array.Copy(securityData, 16, cipherToken, 0, cipherToken.Length);

                // Derive key using PBKDF2
                byte[] key = Crypto.DeriveKey(password, salt);

                // Attempt to decrypt verification token
                byte[] plainToken = Crypto.Decrypt(cipherToken, key);
                string token = Encoding.UTF8.GetString(plainToken);

                if (token == "AUTH-OK")
                {
                    // Unlock successful
                    _derivedKey = key;
                    
                    // Show Main UI
                    AuthGrid.Visibility = Visibility.Collapsed;
                    MainAppGrid.Visibility = Visibility.Visible;

                    // Load database
                    LoadAccounts();
                    
                    TxtMasterPassword.Password = "";
                }
                else
                {
                    MessageBox.Show("Mật khẩu chính không chính xác. Vui lòng thử lại.", "Mở khóa thất bại", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            catch (Exception)
            {
                MessageBox.Show("Mật khẩu chính không chính xác. Vui lòng thử lại.", "Mở khóa thất bại", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // ==================== TOTP LOOP ====================

        private void Timer_Tick(object? sender, EventArgs e)
        {
            UpdatePins();
            UpdateProgressBar();
        }

        private void UpdatePins()
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            int remaining = (int)(30 - (now % 30));

            foreach (var acc in _allAccounts)
            {
                acc.RemainingSeconds = remaining;

                string rawPin = Totp.GeneratePin(acc.Secret);
                if (rawPin == "ERROR")
                {
                    acc.FormattedPin = "SAI KHÓA";
                }
                else if (rawPin == "------")
                {
                    acc.FormattedPin = "--- ---";
                }
                else
                {
                    acc.FormattedPin = rawPin.Substring(0, 3) + " " + rawPin.Substring(3);
                }
            }
        }

        private void UpdateProgressBar()
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long remaining = 30 - (now % 30);
            TimeProgress.Value = remaining;
        }

        // ==================== STORAGE & SECURITY (AES-256) ====================

        private void LoadAccounts()
        {
            try
            {
                if (!File.Exists(_dataPath) || _derivedKey == null)
                {
                    UpdateUIList();
                    return;
                }

                byte[] encryptedBytes = File.ReadAllBytes(_dataPath);
                if (encryptedBytes.Length == 0)
                {
                    UpdateUIList();
                    return;
                }

                // Decrypt using AES-256 with derived key
                byte[] decryptedBytes = Crypto.Decrypt(encryptedBytes, _derivedKey);
                string json = Encoding.UTF8.GetString(decryptedBytes);
                
                _allAccounts = JsonSerializer.Deserialize<List<Account>>(json) ?? new List<Account>();

                // Load deleted accounts
                if (File.Exists(_deletedPath))
                {
                    byte[] encDeleted = File.ReadAllBytes(_deletedPath);
                    if (encDeleted.Length > 0)
                    {
                        byte[] decDeleted = Crypto.Decrypt(encDeleted, _derivedKey);
                        string delJson = Encoding.UTF8.GetString(decDeleted);
                        _deletedAccounts = JsonSerializer.Deserialize<List<Account>>(delJson) ?? new List<Account>();
                    }
                }
                else
                {
                    _deletedAccounts = new List<Account>();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Không thể giải mã cơ sở dữ liệu.\nChi tiết: " + ex.Message, "Lỗi giải mã", MessageBoxButton.OK, MessageBoxImage.Warning);
                _allAccounts = new List<Account>();
                _deletedAccounts = new List<Account>();
            }
            
            UpdateUIList();
        }

        private void SaveAccounts()
        {
            try
            {
                if (_derivedKey == null) return;

                string json = JsonSerializer.Serialize(_allAccounts);
                byte[] rawBytes = Encoding.UTF8.GetBytes(json);

                // Encrypt using AES-256 with derived key
                byte[] encryptedBytes = Crypto.Encrypt(rawBytes, _derivedKey);
                File.WriteAllBytes(_dataPath, encryptedBytes);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Không thể mã hóa cơ sở dữ liệu.\nLỗi: " + ex.Message, "Lỗi lưu trữ", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void SaveDeletedAccounts()
        {
            try
            {
                if (_derivedKey == null) return;

                string json = JsonSerializer.Serialize(_deletedAccounts);
                byte[] rawBytes = Encoding.UTF8.GetBytes(json);

                // Encrypt using AES-256 with derived key
                byte[] encryptedBytes = Crypto.Encrypt(rawBytes, _derivedKey);
                File.WriteAllBytes(_deletedPath, encryptedBytes);
            }
            catch (Exception ex)
            {
                MessageBox.Show("Không thể mã hóa danh sách đã xóa.\nLỗi: " + ex.Message, "Lỗi lưu trữ", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void UpdateUIList()
        {
            DisplayAccounts.Clear();
            
            var query = SearchBox.Text.Trim().ToLower();
            var filtered = _allAccounts.Where(acc => 
                acc.Issuer.ToLower().Contains(query) || 
                acc.Label.ToLower().Contains(query)
            );

            foreach (var acc in filtered)
            {
                DisplayAccounts.Add(acc);
            }

            // Toggle empty state placeholder
            EmptyState.Visibility = _allAccounts.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        }

        // ==================== UI EVENTS & INTERACTION ====================

        private void BtnAdd_Click(object sender, RoutedEventArgs e)
        {
            InputIssuer.Text = "";
            InputLabel.Text = "";
            InputSecret.Text = "";
            AddModal.Visibility = Visibility.Visible;
            InputIssuer.Focus();
        }

        private void BtnCloseModal_Click(object sender, RoutedEventArgs e)
        {
            AddModal.Visibility = Visibility.Collapsed;
        }

        private void ModalBackdrop_Click(object sender, MouseButtonEventArgs e)
        {
            closeAddModal();
        }

        private void closeAddModal()
        {
            AddModal.Visibility = Visibility.Collapsed;
        }

        private void BtnAbout_Click(object sender, RoutedEventArgs e)
        {
            AboutModal.Visibility = Visibility.Visible;
        }

        private void BtnCloseAbout_Click(object sender, RoutedEventArgs e)
        {
            AboutModal.Visibility = Visibility.Collapsed;
        }

        private void AboutBackdrop_Click(object sender, MouseButtonEventArgs e)
        {
            AboutModal.Visibility = Visibility.Collapsed;
        }

        private void BtnSubmitAdd_Click(object sender, RoutedEventArgs e)
        {
            string issuer = InputIssuer.Text.Trim();
            string label = InputLabel.Text.Trim();
            string secret = InputSecret.Text.Trim().Replace(" ", "");

            if (string.IsNullOrEmpty(issuer) || string.IsNullOrEmpty(label) || string.IsNullOrEmpty(secret))
            {
                MessageBox.Show("Vui lòng điền đầy đủ tất cả các trường.", "Nhập dữ liệu", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Test base32 validity
            try
            {
                Base32.ToBytes(secret);
            }
            catch
            {
                MessageBox.Show("Khóa bí mật Secret Key không hợp lệ (phải là định dạng Base32 chuẩn).", "Lỗi định dạng", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (_allAccounts.Any(a => a.Secret.Equals(secret, StringComparison.OrdinalIgnoreCase)))
            {
                MessageBox.Show("Khóa bí mật này đã tồn tại trong danh sách.", "Trùng lặp", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var newAcc = new Account
            {
                Id = Guid.NewGuid().ToString(),
                Issuer = issuer,
                Label = label,
                Secret = secret.ToUpperInvariant()
            };

            _allAccounts.Add(newAcc);
            SaveAccounts();
            UpdateUIList();
            UpdatePins();
            
            closeAddModal();
        }

        private void SearchBox_TextChanged(object sender, TextChangedEventArgs e)
        {
            UpdateUIList();
        }

        private void SearchBox_KeyDown(object sender, KeyEventArgs e)
        {
            if (e.Key == Key.Escape)
            {
                SearchBox.Text = "";
            }
        }

        // Copy PIN
        private void PinCode_Click(object sender, MouseButtonEventArgs e)
        {
            if (sender is TextBlock tb && tb.DataContext is Account acc)
            {
                CopyOtpToClipboard(acc.Secret);
            }
        }

        private void BtnCopyRow_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is Account acc)
            {
                CopyOtpToClipboard(acc.Secret);
            }
        }

        private void CopyOtpToClipboard(string secret)
        {
            string pin = Totp.GeneratePin(secret);
            if (pin != "ERROR" && pin != "------")
            {
                Clipboard.SetText(pin);
                
                // Show custom status dialog or system tray tooltip, simple window message works flatly
                // To keep it standard Google style, we use a simple temporary window label or just normal messagebox
                // Let's do a quiet Status notification in Titlebar or just normal Toast simulation:
                MessageBox.Show("Đã sao chép mã OTP vào clipboard!", "Sao chép thành công", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        // Delete Row
        private void BtnDeleteRow_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is Account acc)
            {
                var result = MessageBox.Show($"Bạn có chắc chắn muốn xóa tài khoản \"{acc.Issuer} ({acc.Label})\" không?\nTài khoản bị xóa sẽ được đưa vào Thùng rác và có thể khôi phục bất cứ lúc nào.", 
                    "Xác nhận xóa", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                
                if (result == MessageBoxResult.Yes)
                {
                    _allAccounts.Remove(acc);
                    SaveAccounts();

                    _deletedAccounts.Add(acc);
                    SaveDeletedAccounts();

                    UpdateUIList();
                    MessageBox.Show($"Đã chuyển tài khoản \"{acc.Issuer}\" vào Thùng rác. Bạn có thể khôi phục trong phần Sao lưu & Nhập liệu.", "Xóa thành công", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
        }

        private async void BtnViewSecret_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is Account acc)
            {
                try
                {
                    if (File.Exists(_biometricPath))
                    {
                        var availability = await Windows.Security.Credentials.UI.UserConsentVerifier.CheckAvailabilityAsync();
                        if (availability == Windows.Security.Credentials.UI.UserConsentVerifierAvailability.Available)
                        {
                            var result = await Windows.Security.Credentials.UI.UserConsentVerifier.RequestVerificationAsync($"Xác thực danh tính để xem khóa bí mật của {acc.Issuer}.");
                            if (result != Windows.Security.Credentials.UI.UserConsentVerificationResult.Verified)
                            {
                                return;
                            }
                        }
                    }

                    var msgBoxResult = MessageBox.Show($"Khóa bí mật của tài khoản \"{acc.Issuer} ({acc.Label})\" là:\n\n{acc.Secret}\n\nBạn có muốn sao chép khóa này vào bộ nhớ đệm không?", "Xem khóa bí mật", MessageBoxButton.YesNo, MessageBoxImage.Information);
                    if (msgBoxResult == MessageBoxResult.Yes)
                    {
                        Clipboard.SetText(acc.Secret);
                        MessageBox.Show("Đã sao chép khóa bí mật vào clipboard!", "Sao chép thành công", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Có lỗi xảy ra: " + ex.Message, "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        // ==================== THEME MANAGER ====================

        private void BtnTheme_Click(object sender, RoutedEventArgs e)
        {
            _isDarkMode = !_isDarkMode;
            
            if (_isDarkMode)
            {
                // Switch to Dark Theme
                Resources["WinBg"] = new SolidColorBrush(Color.FromRgb(0x20, 0x21, 0x24)); // Google Dark
                Resources["HeaderBg"] = new SolidColorBrush(Color.FromRgb(0x20, 0x21, 0x24));
                Resources["BorderBrush"] = new SolidColorBrush(Color.FromRgb(0x3C, 0x40, 0x43));
                Resources["TextPrimary"] = new SolidColorBrush(Color.FromRgb(0xE8, 0xEA, 0xED));
                Resources["TextSecondary"] = new SolidColorBrush(Color.FromRgb(0x9A, 0xA0, 0xA6));
                Resources["PrimaryBlue"] = new SolidColorBrush(Color.FromRgb(0x8A, 0xB4, 0xF8)); // Google Light Blue
                Resources["HoverBg"] = new SolidColorBrush(Color.FromRgb(0x2D, 0x2E, 0x30));
                Resources["ModalBg"] = new SolidColorBrush(Color.FromRgb(0x20, 0x21, 0x24));
                Resources["InputBg"] = new SolidColorBrush(Color.FromRgb(0x20, 0x21, 0x24));
                Resources["DangerRed"] = new SolidColorBrush(Color.FromRgb(0xF2, 0x8B, 0x82));
                ThemeIcon.Text = "\uE706"; // Light icon
            }
            else
            {
                // Switch to Light Theme
                Resources["WinBg"] = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));
                Resources["HeaderBg"] = new SolidColorBrush(Color.FromRgb(0xFF, 0xFF, 0xFF));
                Resources["BorderBrush"] = new SolidColorBrush(Color.FromRgb(0xE2, 0xE8, 0xF0));
                Resources["TextPrimary"] = new SolidColorBrush(Color.FromRgb(0x0F, 0x17, 0x2A));
                Resources["TextSecondary"] = new SolidColorBrush(Color.FromRgb(0x47, 0x55, 0x69));
                Resources["PrimaryBlue"] = new SolidColorBrush(Color.FromRgb(0x1A, 0x73, 0xE8)); // Google Blue
                Resources["HoverBg"] = new SolidColorBrush(Color.FromRgb(0xF1, 0xF5, 0xF9));
                Resources["ModalBg"] = new SolidColorBrush(Color.FromRgb(0xFF, 0xFF, 0xFF));
                Resources["InputBg"] = new SolidColorBrush(Color.FromRgb(0xF8, 0xFA, 0xFC));
                Resources["DangerRed"] = new SolidColorBrush(Color.FromRgb(0xDC, 0x26, 0x26));
                ThemeIcon.Text = "\uE708"; // Moon icon
            }
        }

        // ==================== BACKUP & BULK IMPORT & QR SCANNER ====================

        private void BtnBackup_Click(object sender, RoutedEventArgs e)
        {
            BackupImportModal.Visibility = Visibility.Visible;
            SwitchTab("QR");
        }

        private void BtnCloseBackupImport_Click(object sender, RoutedEventArgs e)
        {
            BackupImportModal.Visibility = Visibility.Collapsed;
        }

        private void BackupImportBackdrop_Click(object sender, MouseButtonEventArgs e)
        {
            BackupImportModal.Visibility = Visibility.Collapsed;
        }

        private void BtnTab_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is string tabName)
            {
                SwitchTab(tabName);
            }
        }

        private void SwitchTab(string tabName)
        {
            // Reset tab styling
            BtnTabQr.BorderBrush = Brushes.Transparent;
            BtnTabQr.Foreground = (SolidColorBrush)Resources["TextSecondary"];
            BtnTabQr.FontWeight = FontWeights.Normal;

            BtnTabJson.BorderBrush = Brushes.Transparent;
            BtnTabJson.Foreground = (SolidColorBrush)Resources["TextSecondary"];
            BtnTabJson.FontWeight = FontWeights.Normal;

            BtnTabCsv.BorderBrush = Brushes.Transparent;
            BtnTabCsv.Foreground = (SolidColorBrush)Resources["TextSecondary"];
            BtnTabCsv.FontWeight = FontWeights.Normal;

            BtnTabSheet.BorderBrush = Brushes.Transparent;
            BtnTabSheet.Foreground = (SolidColorBrush)Resources["TextSecondary"];
            BtnTabSheet.FontWeight = FontWeights.Normal;

            BtnTabTrash.BorderBrush = Brushes.Transparent;
            BtnTabTrash.Foreground = (SolidColorBrush)Resources["TextSecondary"];
            BtnTabTrash.FontWeight = FontWeights.Normal;

            // Hide panels
            PanelTabQr.Visibility = Visibility.Collapsed;
            PanelTabJson.Visibility = Visibility.Collapsed;
            PanelTabCsv.Visibility = Visibility.Collapsed;
            PanelTabSheet.Visibility = Visibility.Collapsed;
            PanelTabTrash.Visibility = Visibility.Collapsed;

            // Show selected panel
            if (tabName == "QR")
            {
                BtnTabQr.BorderBrush = (SolidColorBrush)Resources["PrimaryBlue"];
                BtnTabQr.Foreground = (SolidColorBrush)Resources["TextPrimary"];
                BtnTabQr.FontWeight = FontWeights.SemiBold;
                PanelTabQr.Visibility = Visibility.Visible;
            }
            else if (tabName == "JSON")
            {
                BtnTabJson.BorderBrush = (SolidColorBrush)Resources["PrimaryBlue"];
                BtnTabJson.Foreground = (SolidColorBrush)Resources["TextPrimary"];
                BtnTabJson.FontWeight = FontWeights.SemiBold;
                PanelTabJson.Visibility = Visibility.Visible;
            }
            else if (tabName == "CSV")
            {
                BtnTabCsv.BorderBrush = (SolidColorBrush)Resources["PrimaryBlue"];
                BtnTabCsv.Foreground = (SolidColorBrush)Resources["TextPrimary"];
                BtnTabCsv.FontWeight = FontWeights.SemiBold;
                PanelTabCsv.Visibility = Visibility.Visible;
            }
            else if (tabName == "SHEET")
            {
                BtnTabSheet.BorderBrush = (SolidColorBrush)Resources["PrimaryBlue"];
                BtnTabSheet.Foreground = (SolidColorBrush)Resources["TextPrimary"];
                BtnTabSheet.FontWeight = FontWeights.SemiBold;
                PanelTabSheet.Visibility = Visibility.Visible;
            }
            else if (tabName == "TRASH")
            {
                BtnTabTrash.BorderBrush = (SolidColorBrush)Resources["PrimaryBlue"];
                BtnTabTrash.Foreground = (SolidColorBrush)Resources["TextPrimary"];
                BtnTabTrash.FontWeight = FontWeights.SemiBold;
                PanelTabTrash.Visibility = Visibility.Visible;
                
                TrashList.ItemsSource = null;
                TrashList.ItemsSource = _deletedAccounts;
            }
        }

        // ==================== QR CODE SCANNER ENGINE ====================

        private bool ScanBitmapForQrCode(System.Drawing.Bitmap bitmap)
        {
            try
            {
                var reader = new ZXing.Windows.Compatibility.BarcodeReader
                {
                    AutoRotate = true,
                    Options = new ZXing.Common.DecodingOptions
                    {
                        TryHarder = true
                    }
                };

                var result = reader.Decode(bitmap);
                if (result != null && !string.IsNullOrWhiteSpace(result.Text))
                {
                    string uri = result.Text.Trim();
                    if (ParseAndAddOtpAuthUri(uri))
                    {
                        SaveAccounts();
                        UpdateUIList();
                        UpdatePins();
                        return true;
                    }
                    else
                    {
                        int idx = uri.IndexOf("otpauth://", StringComparison.OrdinalIgnoreCase);
                        if (idx >= 0)
                        {
                            string cleanUri = uri.Substring(idx);
                            if (ParseAndAddOtpAuthUri(cleanUri))
                            {
                                SaveAccounts();
                                UpdateUIList();
                                UpdatePins();
                                return true;
                            }
                        }
                    }
                }
            }
            catch { }
            return false;
        }

        private async void BtnScanScreenQr_Click(object sender, RoutedEventArgs e)
        {
            this.WindowState = WindowState.Minimized;
            await System.Threading.Tasks.Task.Delay(350);

            try
            {
                int screenWidth = (int)SystemParameters.PrimaryScreenWidth;
                int screenHeight = (int)SystemParameters.PrimaryScreenHeight;

                using (var bmp = new System.Drawing.Bitmap(screenWidth, screenHeight))
                {
                    using (var g = System.Drawing.Graphics.FromImage(bmp))
                    {
                        g.CopyFromScreen(0, 0, 0, 0, bmp.Size);
                    }

                    bool success = ScanBitmapForQrCode(bmp);

                    this.WindowState = WindowState.Normal;
                    this.Activate();

                    if (success)
                    {
                        MessageBox.Show("Quét mã QR trên màn hình thành công! Tài khoản 2FA mới đã được tự động thêm vào thiết bị.", "Quét QR Thành Công", MessageBoxButton.OK, MessageBoxImage.Information);
                        BackupImportModal.Visibility = Visibility.Collapsed;
                    }
                    else
                    {
                        MessageBox.Show("Không tìm thấy mã QR 2FA hợp lệ trên màn hình.\nVui lòng đảm bảo mã QR (trên Facebook, Google, Discord...) đang hiển thị rõ trên màn hình máy tính.", "Không tìm thấy QR", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                }
            }
            catch (Exception ex)
            {
                this.WindowState = WindowState.Normal;
                this.Activate();
                MessageBox.Show("Có lỗi xảy ra khi chụp và quét màn hình: " + ex.Message, "Lỗi quét QR", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BtnImportQrImage_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog
            {
                Title = "Chọn file ảnh chứa Mã QR 2FA",
                Filter = "Tệp hình ảnh (*.png;*.jpg;*.jpeg;*.bmp;*.webp)|*.png;*.jpg;*.jpeg;*.bmp;*.webp"
            };

            if (ofd.ShowDialog() == true)
            {
                try
                {
                    using (var bmp = new System.Drawing.Bitmap(ofd.FileName))
                    {
                        bool success = ScanBitmapForQrCode(bmp);
                        if (success)
                        {
                            MessageBox.Show("Đọc mã QR từ ảnh thành công! Tài khoản 2FA mới đã được thêm vào thiết bị.", "Thành công", MessageBoxButton.OK, MessageBoxImage.Information);
                            BackupImportModal.Visibility = Visibility.Collapsed;
                        }
                        else
                        {
                            MessageBox.Show("Không thể trích xuất thông tin 2FA từ hình ảnh này.\nVui lòng đảm bảo hình ảnh rõ nét và chứa mã QR chuẩn 2FA (otpauth://).", "Lỗi mã QR", MessageBoxButton.OK, MessageBoxImage.Warning);
                        }
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Đọc tệp hình ảnh thất bại: " + ex.Message, "Lỗi file", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void Window_Drop(object sender, DragEventArgs e)
        {
            if (e.Data.GetDataPresent(DataFormats.FileDrop))
            {
                string[] files = (string[])e.Data.GetData(DataFormats.FileDrop);
                if (files != null && files.Length > 0)
                {
                    int addedCount = 0;
                    foreach (var file in files)
                    {
                        string ext = System.IO.Path.GetExtension(file).ToLower();
                        if (ext == ".png" || ext == ".jpg" || ext == ".jpeg" || ext == ".bmp" || ext == ".webp")
                        {
                            try
                            {
                                using (var bmp = new System.Drawing.Bitmap(file))
                                {
                                    if (ScanBitmapForQrCode(bmp))
                                    {
                                        addedCount++;
                                    }
                                }
                            }
                            catch { }
                        }
                    }

                    if (addedCount > 0)
                    {
                        MessageBox.Show($"Thành công! Đã quét và nhập {addedCount} tài khoản 2FA mới từ hình ảnh kéo thả vào ứng dụng.", "Nhập Kéo & Thả Thành Công", MessageBoxButton.OK, MessageBoxImage.Information);
                        if (AddModal.Visibility == Visibility.Visible) AddModal.Visibility = Visibility.Collapsed;
                        if (BackupImportModal.Visibility == Visibility.Visible) BackupImportModal.Visibility = Visibility.Collapsed;
                    }
                    else
                    {
                        MessageBox.Show("Không trích xuất được tài khoản 2FA nào từ hình ảnh đã thả vào ứng dụng.\nVui lòng đảm bảo hình ảnh chứa mã QR chuẩn 2FA (otpauth://).", "Lỗi mã QR", MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                }
            }
        }

        private void BtnRestoreTrash_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is Account acc)
            {
                _deletedAccounts.Remove(acc);
                SaveDeletedAccounts();

                _allAccounts.Add(acc);
                SaveAccounts();

                UpdateUIList();
                UpdatePins();

                // Refresh ListBox
                TrashList.ItemsSource = null;
                TrashList.ItemsSource = _deletedAccounts;

                MessageBox.Show($"Đã khôi phục tài khoản \"{acc.Issuer}\" thành công!", "Khôi phục thành công", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void BtnDeleteTrashPermanent_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is Account acc)
            {
                var result = MessageBox.Show($"Bạn có chắc chắn muốn xóa vĩnh viễn tài khoản \"{acc.Issuer} ({acc.Label})\" không?\nHành động này không thể hoàn tác!", 
                    "Xác nhận xóa vĩnh viễn", MessageBoxButton.YesNo, MessageBoxImage.Warning);
                
                if (result == MessageBoxResult.Yes)
                {
                    _deletedAccounts.Remove(acc);
                    SaveDeletedAccounts();

                    // Refresh ListBox
                    TrashList.ItemsSource = null;
                    TrashList.ItemsSource = _deletedAccounts;

                    MessageBox.Show("Đã xóa tài khoản vĩnh viễn.", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
        }

        private void BtnEmptyTrash_Click(object sender, RoutedEventArgs e)
        {
            if (_deletedAccounts.Count == 0)
            {
                MessageBox.Show("Thùng rác hiện đang trống.", "Thùng rác trống", MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var result = MessageBox.Show("Bạn có chắc chắn muốn xóa vĩnh viễn toàn bộ tài khoản trong Thùng rác không?\nHành động này không thể hoàn tác!", 
                "Dọn sạch thùng rác", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            
            if (result == MessageBoxResult.Yes)
            {
                _deletedAccounts.Clear();
                SaveDeletedAccounts();

                // Refresh ListBox
                TrashList.ItemsSource = null;
                TrashList.ItemsSource = _deletedAccounts;

                MessageBox.Show("Thùng rác đã được dọn sạch.", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void BtnExportJson_Click(object sender, RoutedEventArgs e)
        {
            ExportBackup();
        }

        private void BtnImportJson_Click(object sender, RoutedEventArgs e)
        {
            ImportBackup();
        }

        private void BtnExportGhostBak_Click(object sender, RoutedEventArgs e)
        {
            if (_allAccounts.Count == 0)
            {
                MessageBox.Show("Không có tài khoản nào để sao lưu.", "Sao lưu", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string password = Microsoft.VisualBasic.Interaction.InputBox(
                "Nhập mật khẩu bảo vệ file sao lưu (bạn sẽ cần mật khẩu này để giải mã khi khôi phục):",
                "Mật Khẩu Sao Lưu Encrypted .ghostbak",
                "");

            if (string.IsNullOrWhiteSpace(password))
            {
                MessageBox.Show("Mật khẩu sao lưu không được để trống.", "Hủy sao lưu", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var sfd = new SaveFileDialog
            {
                Filter = "Ghost Authenticator Backup (*.ghostbak)|*.ghostbak",
                FileName = $"ghost_authenticator_backup_{DateTime.Now:yyyyMMdd}.ghostbak"
            };

            if (sfd.ShowDialog() == true)
            {
                try
                {
                    string json = JsonSerializer.Serialize(_allAccounts);
                    byte[] encryptedBytes = Crypto.EncryptGhostBak(json, password);
                    File.WriteAllBytes(sfd.FileName, encryptedBytes);
                    MessageBox.Show("Xuất file sao lưu mã hóa (.ghostbak) an toàn thành công!\nFile đã được bảo vệ bằng mật khẩu và có thể lưu trữ trên Cloud/USB mà không lo bị lộ 2FA.", "Sao lưu mã hóa thành công", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Có lỗi xảy ra khi tạo file sao lưu: " + ex.Message, "Lỗi sao lưu", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void BtnImportGhostBak_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog
            {
                Filter = "Ghost Authenticator Backup (*.ghostbak)|*.ghostbak"
            };

            if (ofd.ShowDialog() == true)
            {
                string password = Microsoft.VisualBasic.Interaction.InputBox(
                    "Nhập mật khẩu đã dùng để khóa file sao lưu .ghostbak này:",
                    "Giải Mã File Sao Lưu",
                    "");

                if (string.IsNullOrWhiteSpace(password))
                {
                    MessageBox.Show("Vui lòng nhập mật khẩu để giải mã file.", "Hủy mở file", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                try
                {
                    byte[] encryptedBytes = File.ReadAllBytes(ofd.FileName);
                    string json = Crypto.DecryptGhostBak(encryptedBytes, password);
                    var imported = JsonSerializer.Deserialize<List<Account>>(json);
                    if (imported == null) throw new Exception("File giải mã không chứa dữ liệu tài khoản hợp lệ.");

                    int added = 0;
                    foreach (var acc in imported)
                    {
                        if (!string.IsNullOrEmpty(acc.Issuer) && !string.IsNullOrEmpty(acc.Label) && !string.IsNullOrEmpty(acc.Secret))
                        {
                            if (AddAccountQuietly(acc.Issuer, acc.Label, acc.Secret))
                            {
                                if (string.IsNullOrEmpty(acc.Id)) acc.Id = Guid.NewGuid().ToString();
                                added++;
                            }
                        }
                    }

                    if (added > 0)
                    {
                        SaveAccounts();
                        UpdateUIList();
                        UpdatePins();
                        MessageBox.Show($"Giải mã và nhập thành công {added} tài khoản 2FA mới từ file sao lưu mã hóa!", "Khôi phục thành công", MessageBoxButton.OK, MessageBoxImage.Information);
                        BackupImportModal.Visibility = Visibility.Collapsed;
                    }
                    else
                    {
                        MessageBox.Show("Không tìm thấy tài khoản mới nào hợp lệ (hoặc tất cả tài khoản đã tồn tại).", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Giải mã file sao lưu thất bại. Mật khẩu không đúng hoặc file đã bị hư hỏng/chỉnh sửa.\nChi tiết: " + ex.Message, "Lỗi giải mã", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ExportBackup()
        {
            if (_allAccounts.Count == 0)
            {
                MessageBox.Show("Không có tài khoản nào để sao lưu.", "Sao lưu", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var sfd = new SaveFileDialog
            {
                Filter = "JSON files (*.json)|*.json",
                FileName = "authenticator_backup.json"
            };

            if (sfd.ShowDialog() == true)
            {
                try
                {
                    string json = JsonSerializer.Serialize(_allAccounts, new JsonSerializerOptions { WriteIndented = true });
                    File.WriteAllText(sfd.FileName, json);
                    MessageBox.Show("Xuất file sao lưu thành công!", "Sao lưu JSON", MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Có lỗi xảy ra khi ghi file: " + ex.Message, "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void ImportBackup()
        {
            var ofd = new OpenFileDialog
            {
                Filter = "JSON files (*.json)|*.json"
            };

            if (ofd.ShowDialog() == true)
            {
                try
                {
                    string json = File.ReadAllText(ofd.FileName);
                    var imported = JsonSerializer.Deserialize<List<Account>>(json);
                    if (imported == null) throw new Exception("File không đúng định dạng.");

                    int added = 0;
                    foreach (var acc in imported)
                    {
                        if (!string.IsNullOrEmpty(acc.Issuer) && !string.IsNullOrEmpty(acc.Label) && !string.IsNullOrEmpty(acc.Secret))
                        {
                            if (AddAccountQuietly(acc.Issuer, acc.Label, acc.Secret))
                            {
                                if (string.IsNullOrEmpty(acc.Id)) acc.Id = Guid.NewGuid().ToString();
                                added++;
                            }
                        }
                    }

                    if (added > 0)
                    {
                        SaveAccounts();
                        UpdateUIList();
                        UpdatePins();
                        MessageBox.Show($"Nhập thành công {added} tài khoản mới vào thiết bị!", "Hoàn tất", MessageBoxButton.OK, MessageBoxImage.Information);
                        BackupImportModal.Visibility = Visibility.Collapsed;
                    }
                    else
                    {
                        MessageBox.Show("Không tìm thấy tài khoản mới nào hợp lệ để nhập vào (hoặc tất cả đã trùng lặp).", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Nhập sao lưu thất bại. Định dạng file JSON không hợp lệ.\nChi tiết: " + ex.Message, "Lỗi file", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        // CSV/TXT File Bulk Import
        private void BtnImportCsvFile_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog
            {
                Filter = "CSV / TXT files (*.csv;*.txt)|*.csv;*.txt"
            };

            if (ofd.ShowDialog() == true)
            {
                try
                {
                    string fileContent = File.ReadAllText(ofd.FileName);
                    int added = ImportFromCsvText(fileContent);

                    if (added > 0)
                    {
                        SaveAccounts();
                        UpdateUIList();
                        UpdatePins();
                        MessageBox.Show($"Đã nhập thành công hàng loạt {added} tài khoản mới từ tệp tin!", "Nhập hàng loạt thành công", MessageBoxButton.OK, MessageBoxImage.Information);
                        BackupImportModal.Visibility = Visibility.Collapsed;
                    }
                    else
                    {
                        MessageBox.Show("Không tìm thấy thông tin tài khoản 2FA hợp lệ mới nào trong tệp tin.", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Đọc tệp tin thất bại. Lỗi: " + ex.Message, "Lỗi đọc tệp", MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        // Google Sheet CSV Import
        private async void BtnImportFromSheet_Click(object sender, RoutedEventArgs e)
        {
            string url = InputSheetUrl.Text.Trim();
            if (string.IsNullOrEmpty(url))
            {
                MessageBox.Show("Vui lòng nhập đường dẫn CSV xuất bản của Google Sheet.", "Nhập Google Sheet", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!url.StartsWith("http://", StringComparison.OrdinalIgnoreCase) && !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
            {
                MessageBox.Show("Đường dẫn liên kết không hợp lệ.", "Nhập Google Sheet", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                using (var client = new System.Net.Http.HttpClient())
                {
                    client.Timeout = TimeSpan.FromSeconds(10);
                    var response = await client.GetAsync(url);
                    response.EnsureSuccessStatusCode();

                    string csvContent = await response.Content.ReadAsStringAsync();
                    int added = ImportFromCsvText(csvContent);

                    if (added > 0)
                    {
                        SaveAccounts();
                        UpdateUIList();
                        UpdatePins();
                        MessageBox.Show($"Đồng bộ thành công! Đã thêm {added} tài khoản mới từ Google Sheet.", "Hoàn tất đồng bộ", MessageBoxButton.OK, MessageBoxImage.Information);
                        InputSheetUrl.Text = "";
                        BackupImportModal.Visibility = Visibility.Collapsed;
                    }
                    else
                    {
                        MessageBox.Show("Đã tải dữ liệu Google Sheet nhưng không tìm thấy thông tin tài khoản 2FA mới nào (hoặc đã bị trùng lặp).", "Thông báo", MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Kết nối và tải dữ liệu từ Google Sheet thất bại.\nChi tiết: " + ex.Message, "Lỗi đồng bộ", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // Core CSV/TXT Parsing Engine
        private int ImportFromCsvText(string text)
        {
            int added = 0;
            var lines = text.Split(new[] { "\r\n", "\r", "\n" }, StringSplitOptions.RemoveEmptyEntries);
            foreach (var line in lines)
            {
                string cleanLine = line.Trim();
                if (string.IsNullOrEmpty(cleanLine)) continue;

                if (cleanLine.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
                {
                    if (ParseAndAddOtpAuthUri(cleanLine)) added++;
                }
                else
                {
                    // Comma/Semicolon/Tab separated: Issuer, Label, Secret
                    var parts = cleanLine.Split(new[] { ',', ';', '\t' }, 3);
                    if (parts.Length >= 2)
                    {
                        string issuer = parts[0].Trim();
                        string secret = parts[parts.Length - 1].Trim().Replace(" ", "");
                        string label = parts.Length == 3 ? parts[1].Trim() : issuer;

                        try
                        {
                            Base32.ToBytes(secret);
                            if (AddAccountQuietly(issuer, label, secret)) added++;
                        }
                        catch { /* Skip invalid keys */ }
                    }
                }
            }
            return added;
        }

        private bool ParseAndAddOtpAuthUri(string uri)
        {
            try
            {
                if (!uri.StartsWith("otpauth://totp/", StringComparison.OrdinalIgnoreCase)) return false;
                
                var uriObj = new Uri(uri);
                string labelPath = Uri.UnescapeDataString(uriObj.LocalPath).TrimStart('/');
                string issuer = "";
                string label = labelPath;

                if (labelPath.Contains(":"))
                {
                    var parts = labelPath.Split(':', 2);
                    issuer = parts[0].Trim();
                    label = parts[1].Trim();
                }

                var query = uriObj.Query;
                if (string.IsNullOrEmpty(query)) return false;

                string secret = GetQueryParam(query, "secret");
                string queryIssuer = GetQueryParam(query, "issuer");

                if (string.IsNullOrEmpty(secret)) return false;
                if (!string.IsNullOrEmpty(queryIssuer)) issuer = queryIssuer;
                if (string.IsNullOrEmpty(issuer)) issuer = "2FA";

                try
                {
                    Base32.ToBytes(secret);
                    return AddAccountQuietly(issuer, label, secret);
                }
                catch { return false; }
            }
            catch { return false; }
        }

        private static string GetQueryParam(string query, string name)
        {
            if (string.IsNullOrEmpty(query)) return "";
            var pairs = query.TrimStart('?').Split('&');
            foreach (var pair in pairs)
            {
                var parts = pair.Split('=', 2);
                if (parts.Length == 2 && parts[0].Equals(name, StringComparison.OrdinalIgnoreCase))
                {
                    return Uri.UnescapeDataString(parts[1]);
                }
            }
            return "";
        }

        private bool AddAccountQuietly(string issuer, string label, string secret)
        {
            secret = secret.ToUpperInvariant();
            if (_allAccounts.Any(x => x.Secret.Equals(secret, StringComparison.OrdinalIgnoreCase)))
                return false;

            _allAccounts.Add(new Account
            {
                Id = Guid.NewGuid().ToString(),
                Issuer = issuer,
                Label = label,
                Secret = secret
            });
            return true;
        }

        // ==================== BIOMETRIC UNLOCK (WINDOWS HELLO) ====================

        private void BtnHelloUnlock_Click(object sender, RoutedEventArgs e)
        {
            TriggerWindowsHelloUnlock();
        }

        private async void TriggerWindowsHelloUnlock()
        {
            if (!File.Exists(_biometricPath)) return;

            try
            {
                var availability = await Windows.Security.Credentials.UI.UserConsentVerifier.CheckAvailabilityAsync();
                if (availability != Windows.Security.Credentials.UI.UserConsentVerifierAvailability.Available)
                {
                    MessageBox.Show("Tính năng Windows Hello hiện không khả dụng trên thiết bị này.", "Xác thực thất bại", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                var result = await Windows.Security.Credentials.UI.UserConsentVerifier.RequestVerificationAsync("Xác thực nhận diện khuôn mặt hoặc vân tay để mở khóa tài khoản Ghost Authenticator.");
                if (result == Windows.Security.Credentials.UI.UserConsentVerificationResult.Verified)
                {
                    byte[] encryptedKey = File.ReadAllBytes(_biometricPath);
                    byte[] key = ProtectedData.Unprotect(encryptedKey, null, DataProtectionScope.CurrentUser);

                    _derivedKey = key;

                    // Open App
                    AuthGrid.Visibility = Visibility.Collapsed;
                    MainAppGrid.Visibility = Visibility.Visible;

                    LoadAccounts();
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Có lỗi xảy ra khi xác thực bằng Windows Hello:\n" + ex.Message, "Lỗi xác thực", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ChkWindowsHello_Checked(object sender, RoutedEventArgs e)
        {
            if (_derivedKey == null) return;

            try
            {
                var availability = await Windows.Security.Credentials.UI.UserConsentVerifier.CheckAvailabilityAsync();
                if (availability != Windows.Security.Credentials.UI.UserConsentVerifierAvailability.Available)
                {
                    MessageBox.Show("Thiết bị của bạn không hỗ trợ hoặc chưa cấu hình Windows Hello (FaceID / Vân tay / PIN).\nVui lòng bật Windows Hello trong Windows Settings.", "Không hỗ trợ", MessageBoxButton.OK, MessageBoxImage.Warning);
                    ChkWindowsHello.IsChecked = false;
                    return;
                }

                // Verify user consent first to confirm setup
                var result = await Windows.Security.Credentials.UI.UserConsentVerifier.RequestVerificationAsync("Xác nhận danh tính để kích hoạt mở khóa bằng Windows Hello.");
                if (result == Windows.Security.Credentials.UI.UserConsentVerificationResult.Verified)
                {
                    // Encrypt derived AES key using DPAPI
                    byte[] encryptedKey = ProtectedData.Protect(_derivedKey, null, DataProtectionScope.CurrentUser);
                    File.WriteAllBytes(_biometricPath, encryptedKey);

                    BtnHelloUnlock.Visibility = Visibility.Visible;
                }
                else
                {
                    ChkWindowsHello.IsChecked = false;
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Lỗi thiết lập Windows Hello: " + ex.Message, "Lỗi", MessageBoxButton.OK, MessageBoxImage.Error);
                ChkWindowsHello.IsChecked = false;
            }
        }

        private void ChkWindowsHello_Unchecked(object sender, RoutedEventArgs e)
        {
            try
            {
                if (File.Exists(_biometricPath))
                {
                    File.Delete(_biometricPath);
                }
                BtnHelloUnlock.Visibility = Visibility.Collapsed;
            }
            catch { /* Ignore delete errors */ }
        }
    }

    // ==================== ACCOUNT MODEL ====================

    public class Account : INotifyPropertyChanged
    {
        public string Id { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string Label { get; set; } = string.Empty;
        public string Secret { get; set; } = string.Empty;

        private string _formattedPin = "------";
        public string FormattedPin
        {
            get => _formattedPin;
            set
            {
                if (_formattedPin != value)
                {
                    _formattedPin = value;
                    OnPropertyChanged(nameof(FormattedPin));
                }
            }
        }
        private int _remainingSeconds = 30;
        public int RemainingSeconds
        {
            get => _remainingSeconds;
            set
            {
                if (_remainingSeconds != value)
                {
                    _remainingSeconds = value;
                    OnPropertyChanged(nameof(RemainingSeconds));
                    OnPropertyChanged(nameof(RemainingSecondsText));
                }
            }
        }

        public string RemainingSecondsText => $"{RemainingSeconds}s";

        public string IssuerAbbr
        {
            get
            {
                if (string.IsNullOrEmpty(Issuer)) return "2F";
                var clean = Issuer.Trim();
                if (clean.Length <= 2) return clean.ToUpperInvariant();
                return clean.Substring(0, 2).ToUpperInvariant();
            }
        }

        public event PropertyChangedEventHandler? PropertyChanged;
        protected void OnPropertyChanged(string propertyName)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }
    }
}
