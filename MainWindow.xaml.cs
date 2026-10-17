using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
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
        private const string HelloFileName = "hello.dat";
        // Version 1.0.0 stored the vault key under DPAPI only; any program running as the
        // user could read it. It is removed on startup and Hello must be enabled again.
        private const string LegacyBiometricFileName = "biometric.dat";
        private const string SettingsFileName = "settings.json";

        private static readonly byte[] AuthToken = Encoding.UTF8.GetBytes("AUTH-OK");
        private static readonly TimeSpan ClipboardClearDelay = TimeSpan.FromSeconds(30);
        private static readonly TimeSpan IdleLockTimeout = TimeSpan.FromMinutes(5);
        private const int FreeUnlockAttempts = 5;

        private readonly string _dataPath;
        private readonly string _securityPath;
        private readonly string _helloPath;
        private readonly string _deletedPath;
        private readonly string _settingsPath;
        private readonly AppSettings _settings;
        private readonly DispatcherTimer _timer;
        private readonly DispatcherTimer _toastTimer;
        private bool _isDarkMode = false;
        private List<Account> _allAccounts = new();
        private List<Account> _deletedAccounts = new();
        private byte[]? _derivedKey;
        private DateTime _lastActivityUtc = DateTime.UtcNow;
        private int _failedUnlockAttempts;
        private DateTime _unlockBlockedUntilUtc = DateTime.MinValue;
        private bool _isUnlocking;
        private bool _suppressHelloToggle;
        private bool _suppressLanguageChange;
        private bool _helloResetNotice;
        public ObservableCollection<Account> DisplayAccounts { get; } = new();

        public MainWindow()
        {
            InitializeComponent();
            string dataDir = GetDataDirectory();
            _dataPath = Path.Combine(dataDir, DataFileName);
            _securityPath = Path.Combine(dataDir, SecurityFileName);
            _helloPath = Path.Combine(dataDir, HelloFileName);
            _deletedPath = Path.Combine(dataDir, DeletedFileName);
            _settingsPath = Path.Combine(dataDir, SettingsFileName);

            _settings = AppSettings.Load(_settingsPath);
            ApplyTheme(_settings.DarkMode ?? AppSettings.SystemPrefersDark());

            _helloResetNotice = RemoveLegacyBiometricKey(dataDir);

            _suppressLanguageChange = true;
            LanguageBox.SelectedIndex = Loc.Language == Loc.Vietnamese ? 0 : 1;
            _suppressLanguageChange = false;

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
                ShowUnlockScreen();

                // Auto trigger Windows Hello unlock on startup, quietly if it is unavailable
                if (File.Exists(_helloPath))
                {
                    Dispatcher.BeginInvoke(DispatcherPriority.Loaded, new Action(() => TriggerWindowsHelloUnlock(silent: true)));
                }
            }

            // Set up timer (ticks every second to update pins, progress bar and idle lock)
            _timer = new DispatcherTimer
            {
                Interval = TimeSpan.FromSeconds(1)
            };
            _timer.Tick += Timer_Tick;
            _timer.Start();

            _toastTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(2.5) };
            _toastTimer.Tick += (_, _) =>
            {
                _toastTimer.Stop();
                ToastBorder.Visibility = Visibility.Collapsed;
            };

            // Any input counts as activity for the idle auto-lock.
            PreviewMouseMove += (_, _) => _lastActivityUtc = DateTime.UtcNow;
            PreviewKeyDown += (_, _) => _lastActivityUtc = DateTime.UtcNow;

            // Lock the vault when Windows is locked (Win+L, lid close, user switch).
            SystemEvents.SessionSwitch += OnSessionSwitch;
            Closed += (_, _) =>
            {
                SystemEvents.SessionSwitch -= OnSessionSwitch;
                SecureClipboard.ClearIfUnchanged();
                ClearKey();
            };

            // Initial calculations
            UpdatePins();
            UpdateProgressBar();
        }

        // ==================== DATA LOCATION ====================

        // The install folder is read-only for Microsoft Store (MSIX) and Program Files
        // installs, so the vault lives in the user's local app data instead.
        private static string GetDataDirectory()
        {
            string dataDir = AppSettings.DataDirectory;
            Directory.CreateDirectory(dataDir);
            MigrateLegacyData(dataDir);
            return dataDir;
        }

        // Earlier versions kept the vault next to the executable. Copy it over once so
        // existing users keep their accounts. The originals are left in place.
        private static void MigrateLegacyData(string dataDir)
        {
            if (File.Exists(Path.Combine(dataDir, SecurityFileName))) return;

            string legacyDir = AppDomain.CurrentDomain.BaseDirectory;
            if (!File.Exists(Path.Combine(legacyDir, SecurityFileName))) return;

            var copied = new List<string>();
            try
            {
                foreach (var name in new[] { SecurityFileName, DataFileName, DeletedFileName })
                {
                    string source = Path.Combine(legacyDir, name);
                    if (!File.Exists(source)) continue;

                    string target = Path.Combine(dataDir, name);
                    File.Copy(source, target, overwrite: false);
                    copied.Add(target);
                }
            }
            catch (Exception)
            {
                // Roll back a partial copy so the next start retries cleanly
                // instead of opening a vault with missing files.
                foreach (var file in copied)
                {
                    try { File.Delete(file); } catch { /* Ignore cleanup errors */ }
                }
            }
        }

        // Returns true when an old DPAPI-only Windows Hello key was found and removed.
        private static bool RemoveLegacyBiometricKey(string dataDir)
        {
            string legacyPath = Path.Combine(dataDir, LegacyBiometricFileName);
            if (!File.Exists(legacyPath)) return false;

            try
            {
                File.Delete(legacyPath);
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        // ==================== VAULT KEY HANDLING ====================

        // Creates security.dat for a new master password and returns the vault key.
        private byte[] InitializeVault(string password)
        {
            byte[] salt = Crypto.GenerateRandomBytes(Crypto.SaltSize);
            byte[] key = Crypto.DeriveKey(password, salt);
            WriteSecurityFile(salt, key);
            return key;
        }

        private void WriteSecurityFile(byte[] salt, byte[] key)
        {
            byte[] cipherToken = Crypto.Encrypt(AuthToken, key);
            byte[] securityData = new byte[salt.Length + cipherToken.Length];
            Array.Copy(salt, 0, securityData, 0, salt.Length);
            Array.Copy(cipherToken, 0, securityData, salt.Length, cipherToken.Length);
            AtomicFile.WriteAllBytes(_securityPath, securityData);
        }

        private static bool IsTokenValid(byte[] securityData, byte[] key)
        {
            if (securityData.Length <= Crypto.SaltSize) return false;

            byte[] cipherToken = securityData.AsSpan(Crypto.SaltSize).ToArray();
            try
            {
                byte[] plainToken = Crypto.Decrypt(cipherToken, key);
                return CryptographicOperations.FixedTimeEquals(plainToken, AuthToken);
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        // True when key unlocks the vault currently on disk.
        private bool IsVaultKey(byte[] key)
        {
            return File.Exists(_securityPath) && IsTokenValid(File.ReadAllBytes(_securityPath), key);
        }

        private void ClearKey()
        {
            if (_derivedKey != null)
            {
                CryptographicOperations.ZeroMemory(_derivedKey);
                _derivedKey = null;
            }
        }

        // A new vault makes any previous Windows Hello key useless; remove it.
        private void RemoveHelloKey()
        {
            try
            {
                if (File.Exists(_helloPath)) File.Delete(_helloPath);
            }
            catch (Exception) { /* Ignore delete errors */ }

            _ = WindowsHelloKey.DeleteAsync();
            BtnHelloUnlock.Visibility = Visibility.Collapsed;
            SetHelloCheckbox(false);
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

        private async void BtnChoiceRestore_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog
            {
                Title = Loc.T("Restore_DialogTitle"),
                Filter = Loc.T("Restore_Filter")
            };

            if (ofd.ShowDialog() != true) return;

            string ext = Path.GetExtension(ofd.FileName).ToLower();

            if (ext == ".ghostbak")
            {
                string? password = PasswordDialog.Prompt(this,
                    Loc.T("Restore_GhostbakTitle"),
                    Loc.T("Restore_GhostbakPrompt"));
                if (password == null) return;

                try
                {
                    byte[] encryptedBytes = File.ReadAllBytes(ofd.FileName);
                    string json = await RunBusyAsync(() => Crypto.DecryptGhostBak(encryptedBytes, password));
                    var imported = JsonSerializer.Deserialize<List<Account>>(json);
                    if (imported == null || imported.Count == 0)
                    {
                        MessageBox.Show(Loc.T("Restore_NoAccounts"), Loc.T("Title_DataError"), MessageBoxButton.OK, MessageBoxImage.Error);
                        return;
                    }

                    byte[] key = await RunBusyAsync(() => InitializeVault(password));
                    EnterNewVault(key, imported);

                    MessageBox.Show(Loc.F("Restore_GhostbakDone", imported.Count), Loc.T("Title_RestoreDone"), MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex) when (ex is CryptographicException || ex is InvalidDataException || ex is JsonException)
                {
                    MessageBox.Show(Loc.T("Restore_DecryptFailed"), Loc.T("Title_DecryptError"), MessageBoxButton.OK, MessageBoxImage.Error);
                }
                catch (Exception ex)
                {
                    MessageBox.Show(Loc.T("Restore_Failed") + ex.Message, Loc.T("Title_RestoreError"), MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
            else
            {
                // JSON or CSV File
                string? password = PasswordDialog.Prompt(this,
                    Loc.T("Restore_PlainTitle"),
                    Loc.T("Restore_PlainPrompt"),
                    requireConfirm: true, minLength: 8);
                if (password == null) return;

                try
                {
                    string fileContent = File.ReadAllText(ofd.FileName);
                    List<Account> importedAccounts = new();

                    if (ext == ".json")
                    {
                        var parsed = JsonSerializer.Deserialize<List<Account>>(fileContent);
                        if (parsed != null)
                        {
                            _allAccounts = new List<Account>();
                            ImportAccounts(parsed);
                            importedAccounts = new List<Account>(_allAccounts);
                        }
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
                        _allAccounts = new List<Account>();
                        MessageBox.Show(Loc.T("Restore_NoValidData"), Loc.T("Title_DataError"), MessageBoxButton.OK, MessageBoxImage.Warning);
                        return;
                    }

                    byte[] key = await RunBusyAsync(() => InitializeVault(password));
                    EnterNewVault(key, importedAccounts);

                    MessageBox.Show(Loc.F("Restore_PlainDone", importedAccounts.Count), Loc.T("Title_RestoreDone"), MessageBoxButton.OK, MessageBoxImage.Information);
                }
                catch (Exception ex)
                {
                    _allAccounts = new List<Account>();
                    MessageBox.Show(Loc.T("Restore_ReadFailed") + ex.Message, Loc.T("Title_FileReadError"), MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private async void BtnSetupPassword_Click(object sender, RoutedEventArgs e)
        {
            string password = TxtNewPassword.Password;
            string confirm = TxtConfirmPassword.Password;

            if (string.IsNullOrEmpty(password) || string.IsNullOrEmpty(confirm))
            {
                MessageBox.Show(Loc.T("Setup_Missing"), Loc.T("Setup_Button"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (password.Length < 8)
            {
                MessageBox.Show(Loc.T("Setup_TooShort"), Loc.T("Title_SecurityRequirement"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (password != confirm)
            {
                MessageBox.Show(Loc.T("Setup_Mismatch"), Loc.T("Title_PasswordMismatch"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            try
            {
                // Setup US-Standard encryption (PBKDF2 SHA256 + AES-256-GCM)
                byte[] key = await RunBusyAsync(() => InitializeVault(password));

                TxtNewPassword.Password = "";
                TxtConfirmPassword.Password = "";

                // Initialize empty database and unlock application
                EnterNewVault(key, new List<Account>());

                ShowToast(Loc.T("Setup_Done"));
            }
            catch (Exception ex)
            {
                MessageBox.Show(Loc.T("Setup_Failed") + ex.Message, Loc.T("Title_SecurityError"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        // Opens a vault that was just created (new password or restore).
        private void EnterNewVault(byte[] key, List<Account> accounts)
        {
            RemoveHelloKey();

            ClearKey();
            _derivedKey = key;
            _allAccounts = accounts;
            _deletedAccounts = new List<Account>();
            SaveAccounts();
            SaveDeletedAccounts();

            ShowMainApp();
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

            // Shortcuts only apply while the vault is open
            if (MainAppGrid.Visibility != Visibility.Visible) return;

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
                    BtnAdd_Click(this, new RoutedEventArgs());
                    e.Handled = true;
                }
                else if (e.Key == Key.L)
                {
                    LockApplication();
                    e.Handled = true;
                }
                else if (e.Key == Key.C && Keyboard.FocusedElement is not TextBox)
                {
                    if (AccountsList.SelectedItem is Account selected)
                    {
                        CopyOtp(selected);
                        e.Handled = true;
                    }
                }
            }

            // Enter key on selected row in accounts list (focus is on the row, not the list)
            if (e.Key == Key.Enter && AccountsList.IsKeyboardFocusWithin)
            {
                if (AccountsList.SelectedItem is Account selected)
                {
                    CopyOtp(selected);
                    e.Handled = true;
                }
            }
        }

        private async void UnlockApplication()
        {
            if (_isUnlocking) return;

            if (DateTime.UtcNow < _unlockBlockedUntilUtc)
            {
                int seconds = (int)Math.Ceiling((_unlockBlockedUntilUtc - DateTime.UtcNow).TotalSeconds);
                MessageBox.Show(Loc.F("Unlock_Throttled", seconds), Loc.T("Title_UnlockPaused"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string password = TxtMasterPassword.Password;

            if (string.IsNullOrEmpty(password))
            {
                MessageBox.Show(Loc.T("Unlock_Empty"), Loc.T("Unlock_Button"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!File.Exists(_securityPath))
            {
                MessageBox.Show(Loc.T("Unlock_NoSecurityFile"), Loc.T("Title_SystemError"), MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            byte[] securityData = File.ReadAllBytes(_securityPath);
            if (securityData.Length <= Crypto.SaltSize)
            {
                MessageBox.Show(Loc.T("Unlock_SecurityCorrupt"), Loc.T("Title_FileError"), MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            _isUnlocking = true;
            try
            {
                byte[] salt = securityData.AsSpan(0, Crypto.SaltSize).ToArray();

                // Derive key using PBKDF2 off the UI thread so the window stays responsive
                byte[] key = await RunBusyAsync(() => Crypto.DeriveKey(password, salt));

                if (IsTokenValid(securityData, key))
                {
                    TxtMasterPassword.Password = "";
                    _failedUnlockAttempts = 0;
                    OpenVault(key);
                }
                else
                {
                    CryptographicOperations.ZeroMemory(key);
                    RegisterFailedUnlock();
                    MessageBox.Show(Loc.T("Unlock_WrongPassword"), Loc.T("Title_UnlockFailed"), MessageBoxButton.OK, MessageBoxImage.Error);
                    TxtMasterPassword.SelectAll();
                    TxtMasterPassword.Focus();
                }
            }
            finally
            {
                _isUnlocking = false;
            }
        }

        // Slows down repeated guessing: after 5 wrong passwords, wait 30s, then 60s, ... up to 5 minutes.
        private void RegisterFailedUnlock()
        {
            _failedUnlockAttempts++;
            if (_failedUnlockAttempts < FreeUnlockAttempts) return;

            int extra = Math.Min(_failedUnlockAttempts - FreeUnlockAttempts, 4);
            int seconds = Math.Min(30 * (1 << extra), 300);
            _unlockBlockedUntilUtc = DateTime.UtcNow.AddSeconds(seconds);
        }

        // Opens the existing vault with a verified key.
        private void OpenVault(byte[] key)
        {
            ClearKey();
            _derivedKey = key;

            ShowMainApp();
            if (!LoadAccounts()) return;
            UpgradeStorageFormat();

            if (_helloResetNotice)
            {
                _helloResetNotice = false;
                MessageBox.Show(Loc.T("Hello_Upgraded"), Loc.T("Title_SecurityUpgrade"), MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        private void ShowMainApp()
        {
            WelcomeChoicePanel.Visibility = Visibility.Collapsed;
            SetupPasswordPanel.Visibility = Visibility.Collapsed;
            AuthGrid.Visibility = Visibility.Collapsed;
            MainAppGrid.Visibility = Visibility.Visible;
            _lastActivityUtc = DateTime.UtcNow;
            UpdateUIList();
            UpdatePins();
        }

        private void ShowUnlockScreen()
        {
            WelcomeChoicePanel.Visibility = Visibility.Collapsed;
            SetupPasswordPanel.Visibility = Visibility.Collapsed;
            UnlockPanel.Visibility = Visibility.Visible;
            AuthGrid.Visibility = Visibility.Visible;
            MainAppGrid.Visibility = Visibility.Collapsed;

            bool helloEnabled = File.Exists(_helloPath);
            BtnHelloUnlock.Visibility = helloEnabled ? Visibility.Visible : Visibility.Collapsed;
            SetHelloCheckbox(helloEnabled);

            Dispatcher.BeginInvoke(DispatcherPriority.Input, new Action(() =>
            {
                TxtMasterPassword.Focus();
            }));
        }

        // ==================== AUTO LOCK ====================

        private void BtnLock_Click(object sender, RoutedEventArgs e)
        {
            LockApplication();
        }

        private void OnSessionSwitch(object sender, SessionSwitchEventArgs e)
        {
            if (e.Reason == SessionSwitchReason.SessionLock)
            {
                Dispatcher.BeginInvoke(new Action(LockApplication));
            }
        }

        // Wipes the key and decrypted accounts from memory and returns to the lock screen.
        private void LockApplication()
        {
            if (_derivedKey == null) return;

            SecureClipboard.ClearIfUnchanged();
            ClearKey();

            _allAccounts = new List<Account>();
            _deletedAccounts = new List<Account>();
            DisplayAccounts.Clear();
            TrashList.ItemsSource = null;

            AddModal.Visibility = Visibility.Collapsed;
            AboutModal.Visibility = Visibility.Collapsed;
            BackupImportModal.Visibility = Visibility.Collapsed;
            InputSecret.Text = "";
            SearchBox.Text = "";

            ShowUnlockScreen();
        }

        // ==================== TOTP LOOP ====================

        private void Timer_Tick(object? sender, EventArgs e)
        {
            UpdatePins();
            UpdateProgressBar();

            if (_derivedKey != null && DateTime.UtcNow - _lastActivityUtc > IdleLockTimeout)
            {
                LockApplication();
            }
        }

        private void UpdatePins()
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();

            foreach (var acc in _allAccounts)
            {
                int period = acc.Period > 0 ? acc.Period : Totp.DefaultPeriod;
                acc.RemainingSeconds = (int)(period - (now % period));
                acc.FormattedPin = FormatPin(Totp.GeneratePin(acc.Secret, acc.Algorithm, acc.Digits, period));
            }
        }

        private static string FormatPin(string rawPin)
        {
            if (rawPin == "ERROR") return Loc.T("Pin_InvalidKey");
            if (rawPin == "------") return "--- ---";

            // 6 digits -> "123 456", 8 digits -> "1234 5678"
            int split = rawPin.Length / 2;
            return rawPin.Substring(0, split) + " " + rawPin.Substring(split);
        }

        private void UpdateProgressBar()
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            long remaining = 30 - (now % 30);
            TimeProgress.Value = remaining;
        }

        // ==================== STORAGE & SECURITY (AES-256-GCM) ====================

        // Returns false when the vault could not be opened safely and the app was locked again.
        private bool LoadAccounts()
        {
            try
            {
                _allAccounts = LoadAccountFile(_dataPath, Loc.T("Store_AccountList"));
                _deletedAccounts = LoadAccountFile(_deletedPath, Loc.T("Store_Trash"));
            }
            catch (IOException ex)
            {
                MessageBox.Show(Loc.T("Store_ReadFailed") + ex.Message, Loc.T("Title_StorageError"), MessageBoxButton.OK, MessageBoxImage.Error);
                LockApplication();
                return false;
            }

            UpdateUIList();
            UpdatePins();
            return true;
        }

        // A file that cannot be decrypted is moved aside instead of being replaced by an
        // empty list on the next save, so the user can still recover it.
        private List<Account> LoadAccountFile(string path, string description)
        {
            if (_derivedKey == null || !File.Exists(path)) return new List<Account>();

            byte[] encryptedBytes = File.ReadAllBytes(path);
            if (encryptedBytes.Length == 0) return new List<Account>();

            try
            {
                byte[] decryptedBytes = Crypto.Decrypt(encryptedBytes, _derivedKey);
                return JsonSerializer.Deserialize<List<Account>>(Encoding.UTF8.GetString(decryptedBytes)) ?? new List<Account>();
            }
            catch (Exception ex) when (ex is CryptographicException || ex is JsonException)
            {
                string keptPath = $"{path}.corrupt-{DateTime.Now:yyyyMMddHHmmss}";
                File.Move(path, keptPath);
                MessageBox.Show(Loc.F("Store_Corrupt", description, keptPath), Loc.T("Title_DecryptError"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return new List<Account>();
            }
        }

        // Re-encrypts files written by version 1.0.0 (AES-CBC) with AES-GCM.
        private void UpgradeStorageFormat()
        {
            if (_derivedKey == null) return;

            try
            {
                byte[] securityData = File.ReadAllBytes(_securityPath);
                bool legacy = !Crypto.IsCurrentFormat(securityData.AsSpan(Crypto.SaltSize).ToArray())
                    || IsLegacyFile(_dataPath)
                    || IsLegacyFile(_deletedPath);
                if (!legacy) return;

                SaveAccounts();
                SaveDeletedAccounts();
                WriteSecurityFile(securityData.AsSpan(0, Crypto.SaltSize).ToArray(), _derivedKey);
            }
            catch (IOException)
            {
                // Try again on the next unlock.
            }
        }

        private static bool IsLegacyFile(string path)
        {
            if (!File.Exists(path)) return false;
            byte[] data = File.ReadAllBytes(path);
            return data.Length > 0 && !Crypto.IsCurrentFormat(data);
        }

        private void SaveAccounts()
        {
            SaveAccountFile(_dataPath, _allAccounts, Loc.T("Store_SaveFailed"));
        }

        private void SaveDeletedAccounts()
        {
            SaveAccountFile(_deletedPath, _deletedAccounts, Loc.T("Store_SaveTrashFailed"));
        }

        private void SaveAccountFile(string path, List<Account> accounts, string errorMessage)
        {
            try
            {
                if (_derivedKey == null) return;

                byte[] rawBytes = JsonSerializer.SerializeToUtf8Bytes(accounts);
                byte[] encryptedBytes = Crypto.Encrypt(rawBytes, _derivedKey);
                CryptographicOperations.ZeroMemory(rawBytes);
                AtomicFile.WriteAllBytes(path, encryptedBytes);
            }
            catch (Exception ex)
            {
                MessageBox.Show(errorMessage + Loc.T("Common_ErrorPrefix") + ex.Message, Loc.T("Title_StorageError"), MessageBoxButton.OK, MessageBoxImage.Error);
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

            // Toggle empty state placeholder: no accounts at all vs. no search results
            if (_allAccounts.Count == 0)
            {
                EmptyTitle.Text = Loc.T("Empty_NoAccounts");
                EmptyHint.Text = Loc.T("Empty_NoAccountsHint");
                EmptyState.Visibility = Visibility.Visible;
            }
            else if (DisplayAccounts.Count == 0)
            {
                EmptyTitle.Text = Loc.F("Empty_NoMatch", SearchBox.Text.Trim());
                EmptyHint.Text = Loc.T("Empty_NoMatchHint");
                EmptyState.Visibility = Visibility.Visible;
            }
            else
            {
                EmptyState.Visibility = Visibility.Collapsed;
            }
        }

        // ==================== UI EVENTS & INTERACTION ====================

        private void ShowToast(string message)
        {
            ToastText.Text = message;
            ToastBorder.Visibility = Visibility.Visible;
            _toastTimer.Stop();
            _toastTimer.Start();
        }

        // Runs slow work (PBKDF2) off the UI thread with a wait cursor.
        private async Task<T> RunBusyAsync<T>(Func<T> work)
        {
            Mouse.OverrideCursor = Cursors.Wait;
            IsEnabled = false;
            try
            {
                return await Task.Run(work);
            }
            finally
            {
                IsEnabled = true;
                Mouse.OverrideCursor = null;
            }
        }

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
            closeAddModal();
        }

        private void ModalBackdrop_Click(object sender, MouseButtonEventArgs e)
        {
            closeAddModal();
        }

        private void closeAddModal()
        {
            AddModal.Visibility = Visibility.Collapsed;
            InputSecret.Text = "";
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
                MessageBox.Show(Loc.T("Add_MissingFields"), Loc.T("Title_InputData"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Test base32 validity
            try
            {
                if (Base32.ToBytes(secret).Length == 0) throw new ArgumentException();
            }
            catch
            {
                MessageBox.Show(Loc.T("Add_InvalidSecret"), Loc.T("Title_FormatError"), MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            if (!AddAccountQuietly(issuer, label, secret))
            {
                MessageBox.Show(Loc.T("Add_Duplicate"), Loc.T("Title_Duplicate"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            SaveAccounts();
            UpdateUIList();
            UpdatePins();

            closeAddModal();
            ShowToast(Loc.F("Add_Done", issuer));
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
                CopyOtp(acc);
            }
        }

        private void BtnCopyRow_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is Account acc)
            {
                CopyOtp(acc);
            }
        }

        // Copies the current code without a blocking dialog; the clipboard is cleared after 30s.
        private void CopyOtp(Account acc)
        {
            string pin = Totp.GeneratePin(acc.Secret, acc.Algorithm, acc.Digits, acc.Period);
            if (pin == "ERROR" || pin == "------")
            {
                ShowToast(Loc.T("Copy_InvalidKey"));
                return;
            }

            if (SecureClipboard.SetText(pin, ClipboardClearDelay))
            {
                ShowToast(Loc.F("Copy_Done", acc.Issuer));
            }
            else
            {
                ShowToast(Loc.T("Copy_Busy"));
            }
        }

        // Delete Row
        private void BtnDeleteRow_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is Account acc)
            {
                var result = MessageBox.Show(Loc.F("Delete_Confirm", acc.Issuer, acc.Label),
                    Loc.T("Title_ConfirmDelete"), MessageBoxButton.YesNo, MessageBoxImage.Warning);

                if (result == MessageBoxResult.Yes)
                {
                    // Save to the trash first so a crash in between cannot lose the account
                    _deletedAccounts.Add(acc);
                    SaveDeletedAccounts();

                    _allAccounts.Remove(acc);
                    SaveAccounts();

                    UpdateUIList();
                    ShowToast(Loc.F("Delete_Done", acc.Issuer));
                }
            }
        }

        private async void BtnViewSecret_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is Account acc)
            {
                if (!await ConfirmIdentityAsync(Loc.F("Secret_Reason", acc.Issuer))) return;

                var msgBoxResult = MessageBox.Show(Loc.F("Secret_Show", acc.Issuer, acc.Label, acc.Secret), Loc.T("Row_ViewName"), MessageBoxButton.YesNo, MessageBoxImage.Information);
                if (msgBoxResult == MessageBoxResult.Yes)
                {
                    ShowToast(SecureClipboard.SetText(acc.Secret, ClipboardClearDelay)
                        ? Loc.T("Secret_Copied")
                        : Loc.T("Copy_Busy"));
                }
            }
        }

        // Re-verifies the user before revealing secrets: Windows Hello when enabled,
        // otherwise (or if Hello is cancelled) the master password.
        private async Task<bool> ConfirmIdentityAsync(string reason)
        {
            if (_derivedKey == null) return false;

            try
            {
                if (File.Exists(_helloPath) && await WindowsHelloKey.IsSupportedAsync())
                {
                    byte[]? helloKey = await WindowsHelloKey.UnwrapAsync(File.ReadAllBytes(_helloPath));
                    if (helloKey != null)
                    {
                        bool matches = _derivedKey != null && CryptographicOperations.FixedTimeEquals(helloKey, _derivedKey);
                        CryptographicOperations.ZeroMemory(helloKey);
                        if (matches) return true;
                    }
                }
            }
            catch (Exception)
            {
                // Fall back to the master password below.
            }

            string? password = PasswordDialog.Prompt(this, Loc.T("Verify_Title"), Loc.F("Verify_Prompt", reason));
            if (password == null || _derivedKey == null) return false;

            byte[] securityData = File.ReadAllBytes(_securityPath);
            byte[] salt = securityData.AsSpan(0, Crypto.SaltSize).ToArray();
            byte[] key = await RunBusyAsync(() => Crypto.DeriveKey(password, salt));

            bool ok = _derivedKey != null && CryptographicOperations.FixedTimeEquals(key, _derivedKey);
            CryptographicOperations.ZeroMemory(key);

            if (!ok)
            {
                MessageBox.Show(Loc.T("Verify_WrongPassword"), Loc.T("Title_VerifyFailed"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
            return ok;
        }

        // ==================== THEME MANAGER ====================

        private void BtnTheme_Click(object sender, RoutedEventArgs e)
        {
            ApplyTheme(!_isDarkMode);
            _settings.DarkMode = _isDarkMode;
            _settings.Save(_settingsPath);
        }

        private void ApplyTheme(bool dark)
        {
            _isDarkMode = dark;

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

        // ==================== LANGUAGE ====================

        // Text is loaded when the window is built, so a new language applies after a restart.
        private void LanguageBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
        {
            if (_suppressLanguageChange) return;
            if (LanguageBox.SelectedItem is not ComboBoxItem item || item.Tag is not string language) return;

            _settings.Language = language;
            _settings.Save(_settingsPath);

            string message = language == Loc.Vietnamese
                ? "Khởi động lại ứng dụng để áp dụng ngôn ngữ mới."
                : "Restart the app to apply the new language.";
            ShowToast(message);
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
            var tabs = new (Button Button, UIElement Panel, string Name)[]
            {
                (BtnTabQr, PanelTabQr, "QR"),
                (BtnTabJson, PanelTabJson, "JSON"),
                (BtnTabCsv, PanelTabCsv, "CSV"),
                (BtnTabSheet, PanelTabSheet, "SHEET"),
                (BtnTabTrash, PanelTabTrash, "TRASH"),
            };

            foreach (var tab in tabs)
            {
                bool selected = tab.Name == tabName;
                tab.Button.BorderThickness = selected ? new Thickness(0, 0, 0, 2) : new Thickness(0);
                tab.Button.BorderBrush = selected ? (SolidColorBrush)Resources["PrimaryBlue"] : Brushes.Transparent;
                tab.Button.Foreground = (SolidColorBrush)Resources[selected ? "TextPrimary" : "TextSecondary"];
                tab.Button.FontWeight = selected ? FontWeights.SemiBold : FontWeights.Normal;
                tab.Panel.Visibility = selected ? Visibility.Visible : Visibility.Collapsed;
            }

            if (tabName == "TRASH")
            {
                RefreshTrashList();
            }
        }

        private void RefreshTrashList()
        {
            TrashList.ItemsSource = null;
            TrashList.ItemsSource = _deletedAccounts;
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
                    int idx = uri.IndexOf("otpauth://", StringComparison.OrdinalIgnoreCase);
                    if (idx >= 0 && ParseAndAddOtpAuthUri(uri.Substring(idx)))
                    {
                        SaveAccounts();
                        UpdateUIList();
                        UpdatePins();
                        return true;
                    }
                }
            }
            catch { }
            return false;
        }

        private async void BtnScanScreenQr_Click(object sender, RoutedEventArgs e)
        {
            // SystemParameters are in device-independent units; the capture needs real pixels,
            // otherwise only part of the screen is scanned on 125%/150% scaling.
            var dpi = VisualTreeHelper.GetDpi(this);
            int left = (int)Math.Floor(SystemParameters.VirtualScreenLeft * dpi.DpiScaleX);
            int top = (int)Math.Floor(SystemParameters.VirtualScreenTop * dpi.DpiScaleY);
            int width = (int)Math.Ceiling(SystemParameters.VirtualScreenWidth * dpi.DpiScaleX);
            int height = (int)Math.Ceiling(SystemParameters.VirtualScreenHeight * dpi.DpiScaleY);

            this.WindowState = WindowState.Minimized;
            await Task.Delay(350);

            try
            {
                bool success;
                using (var bmp = new System.Drawing.Bitmap(width, height))
                {
                    using (var g = System.Drawing.Graphics.FromImage(bmp))
                    {
                        g.CopyFromScreen(left, top, 0, 0, bmp.Size);
                    }

                    success = ScanBitmapForQrCode(bmp);
                }

                this.WindowState = WindowState.Normal;
                this.Activate();

                if (success)
                {
                    BackupImportModal.Visibility = Visibility.Collapsed;
                    closeAddModal();
                    ShowToast(Loc.T("Qr_ScanDone"));
                }
                else
                {
                    MessageBox.Show(Loc.T("Qr_NotFound"), Loc.T("Title_QrNotFound"), MessageBoxButton.OK, MessageBoxImage.Warning);
                }
            }
            catch (Exception ex)
            {
                this.WindowState = WindowState.Normal;
                this.Activate();
                MessageBox.Show(Loc.T("Qr_ScanFailed") + ex.Message, Loc.T("Title_QrError"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void BtnImportQrImage_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog
            {
                Title = Loc.T("Qr_PickTitle"),
                Filter = Loc.T("Qr_ImageFilter")
            };

            if (ofd.ShowDialog() == true)
            {
                try
                {
                    using (var bmp = new System.Drawing.Bitmap(ofd.FileName))
                    {
                        if (ScanBitmapForQrCode(bmp))
                        {
                            BackupImportModal.Visibility = Visibility.Collapsed;
                            closeAddModal();
                            ShowToast(Loc.T("Qr_ImageDone"));
                        }
                        else
                        {
                            MessageBox.Show(Loc.T("Qr_ImageInvalid"), Loc.T("Title_QrCodeError"), MessageBoxButton.OK, MessageBoxImage.Warning);
                        }
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(Loc.T("Qr_ImageReadFailed") + ex.Message, Loc.T("Title_FileErrorShort"), MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private void Window_Drop(object sender, DragEventArgs e)
        {
            // Dropping files on the lock screen must not touch the vault
            if (_derivedKey == null) return;

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
                        if (AddModal.Visibility == Visibility.Visible) closeAddModal();
                        if (BackupImportModal.Visibility == Visibility.Visible) BackupImportModal.Visibility = Visibility.Collapsed;
                        ShowToast(Loc.F("Drop_Done", addedCount));
                    }
                    else
                    {
                        MessageBox.Show(Loc.T("Drop_None"), Loc.T("Title_QrCodeError"), MessageBoxButton.OK, MessageBoxImage.Warning);
                    }
                }
            }
        }

        private void BtnRestoreTrash_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is Account acc)
            {
                // Save the account list first so a crash in between cannot lose the account
                if (!_allAccounts.Any(a => a.Secret.Equals(acc.Secret, StringComparison.OrdinalIgnoreCase)))
                {
                    _allAccounts.Add(acc);
                    SaveAccounts();
                }

                _deletedAccounts.Remove(acc);
                SaveDeletedAccounts();

                UpdateUIList();
                UpdatePins();
                RefreshTrashList();

                ShowToast(Loc.F("Trash_Restored", acc.Issuer));
            }
        }

        private void BtnDeleteTrashPermanent_Click(object sender, RoutedEventArgs e)
        {
            if (sender is Button btn && btn.Tag is Account acc)
            {
                var result = MessageBox.Show(Loc.F("Trash_ConfirmDelete", acc.Issuer, acc.Label),
                    Loc.T("Title_ConfirmDeleteForever"), MessageBoxButton.YesNo, MessageBoxImage.Warning);

                if (result == MessageBoxResult.Yes)
                {
                    _deletedAccounts.Remove(acc);
                    SaveDeletedAccounts();
                    RefreshTrashList();

                    ShowToast(Loc.T("Trash_Deleted"));
                }
            }
        }

        private void BtnEmptyTrash_Click(object sender, RoutedEventArgs e)
        {
            if (_deletedAccounts.Count == 0)
            {
                ShowToast(Loc.T("Trash_IsEmpty"));
                return;
            }

            var result = MessageBox.Show(Loc.T("Trash_ConfirmEmpty"),
                Loc.T("Title_EmptyTrash"), MessageBoxButton.YesNo, MessageBoxImage.Warning);

            if (result == MessageBoxResult.Yes)
            {
                _deletedAccounts.Clear();
                SaveDeletedAccounts();
                RefreshTrashList();

                ShowToast(Loc.T("Trash_Emptied"));
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

        private async void BtnExportGhostBak_Click(object sender, RoutedEventArgs e)
        {
            if (_allAccounts.Count == 0)
            {
                MessageBox.Show(Loc.T("Backup_NoAccounts"), Loc.T("Tab_Backup"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            string? password = PasswordDialog.Prompt(this,
                Loc.T("Export_PasswordTitle"),
                Loc.T("Export_PasswordPrompt"),
                requireConfirm: true, minLength: 8);
            if (password == null) return;

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
                    byte[] encryptedBytes = await RunBusyAsync(() => Crypto.EncryptGhostBak(json, password));
                    AtomicFile.WriteAllBytes(sfd.FileName, encryptedBytes);
                    ShowToast(Loc.T("Export_Done"));
                }
                catch (Exception ex)
                {
                    MessageBox.Show(Loc.T("Export_Failed") + ex.Message, Loc.T("Title_BackupError"), MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        private async void BtnImportGhostBak_Click(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog
            {
                Filter = "Ghost Authenticator Backup (*.ghostbak)|*.ghostbak"
            };

            if (ofd.ShowDialog() != true) return;

            string? password = PasswordDialog.Prompt(this, Loc.T("Import_PasswordTitle"), Loc.T("Import_PasswordPrompt"));
            if (password == null) return;

            try
            {
                byte[] encryptedBytes = File.ReadAllBytes(ofd.FileName);
                string json = await RunBusyAsync(() => Crypto.DecryptGhostBak(encryptedBytes, password));
                var imported = JsonSerializer.Deserialize<List<Account>>(json);
                if (imported == null) throw new InvalidDataException(Loc.T("Import_NoData"));

                int added = ImportAccounts(imported);
                if (added > 0)
                {
                    SaveAccounts();
                    UpdateUIList();
                    UpdatePins();
                    BackupImportModal.Visibility = Visibility.Collapsed;
                    ShowToast(Loc.F("Import_GhostbakDone", added));
                }
                else
                {
                    MessageBox.Show(Loc.T("Import_NothingNew"), Loc.T("Title_Info"), MessageBoxButton.OK, MessageBoxImage.Information);
                }
            }
            catch (Exception ex) when (ex is CryptographicException || ex is InvalidDataException || ex is JsonException)
            {
                MessageBox.Show(Loc.T("Import_DecryptFailed"), Loc.T("Title_DecryptError"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
            catch (Exception ex)
            {
                MessageBox.Show(Loc.T("Restore_ReadFailed") + ex.Message, Loc.T("Title_FileErrorShort"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private void ExportBackup()
        {
            if (_allAccounts.Count == 0)
            {
                MessageBox.Show(Loc.T("Backup_NoAccounts"), Loc.T("Tab_Backup"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var confirm = MessageBox.Show(Loc.T("Json_ExportWarning"),
                Loc.T("Title_SecurityWarning"), MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
            if (confirm != MessageBoxResult.Yes) return;

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
                    ShowToast(Loc.T("Json_ExportDone"));
                }
                catch (Exception ex)
                {
                    MessageBox.Show(Loc.T("Json_WriteFailed") + ex.Message, Loc.T("Title_Error"), MessageBoxButton.OK, MessageBoxImage.Error);
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
                    if (imported == null) throw new InvalidDataException(Loc.T("Json_InvalidFormat"));

                    int added = ImportAccounts(imported);
                    if (added > 0)
                    {
                        SaveAccounts();
                        UpdateUIList();
                        UpdatePins();
                        BackupImportModal.Visibility = Visibility.Collapsed;
                        ShowToast(Loc.F("Json_ImportDone", added));
                    }
                    else
                    {
                        MessageBox.Show(Loc.T("Json_NothingNew"), Loc.T("Title_Info"), MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(Loc.T("Json_ImportFailed") + ex.Message, Loc.T("Title_FileErrorShort"), MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        // Adds valid, non-duplicate accounts from a backup and returns how many were added.
        private int ImportAccounts(IEnumerable<Account> imported)
        {
            int added = 0;
            foreach (var acc in imported)
            {
                if (string.IsNullOrEmpty(acc.Issuer) || string.IsNullOrEmpty(acc.Label) || string.IsNullOrEmpty(acc.Secret))
                    continue;

                string? algorithm = Totp.NormalizeAlgorithm(acc.Algorithm);
                int digits = acc.Digits == 0 ? Totp.DefaultDigits : acc.Digits;
                int period = acc.Period == 0 ? Totp.DefaultPeriod : acc.Period;
                if (algorithm == null || digits < 6 || digits > 8 || period <= 0)
                    continue;

                try
                {
                    if (Base32.ToBytes(acc.Secret).Length == 0) continue;
                }
                catch
                {
                    continue;
                }

                if (AddAccountQuietly(acc.Issuer, acc.Label, acc.Secret, algorithm, digits, period))
                {
                    added++;
                }
            }
            return added;
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
                        BackupImportModal.Visibility = Visibility.Collapsed;
                        ShowToast(Loc.F("Csv_ImportDone", added));
                    }
                    else
                    {
                        MessageBox.Show(Loc.T("Csv_NothingNew"), Loc.T("Title_Info"), MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
                catch (Exception ex)
                {
                    MessageBox.Show(Loc.T("Csv_ReadFailed") + ex.Message, Loc.T("Title_FileReadError"), MessageBoxButton.OK, MessageBoxImage.Error);
                }
            }
        }

        // Google Sheet CSV Import
        private async void BtnImportFromSheet_Click(object sender, RoutedEventArgs e)
        {
            string url = InputSheetUrl.Text.Trim();
            if (string.IsNullOrEmpty(url))
            {
                MessageBox.Show(Loc.T("Sheet_UrlMissing"), Loc.T("Title_Sheet"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            // Secrets must never travel over plain HTTP
            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri? sheetUri) || sheetUri.Scheme != Uri.UriSchemeHttps)
            {
                MessageBox.Show(Loc.T("Sheet_HttpsOnly"), Loc.T("Title_Sheet"), MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var confirm = MessageBox.Show(Loc.T("Sheet_PublicWarning"),
                Loc.T("Title_SecurityWarning"), MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
            if (confirm != MessageBoxResult.Yes) return;

            try
            {
                using (var client = new System.Net.Http.HttpClient())
                {
                    client.Timeout = TimeSpan.FromSeconds(10);
                    client.MaxResponseContentBufferSize = 1024 * 1024;
                    var response = await client.GetAsync(sheetUri);
                    response.EnsureSuccessStatusCode();

                    string csvContent = await response.Content.ReadAsStringAsync();
                    if (_derivedKey == null) return; // Locked while downloading

                    int added = ImportFromCsvText(csvContent);

                    if (added > 0)
                    {
                        SaveAccounts();
                        UpdateUIList();
                        UpdatePins();
                        InputSheetUrl.Text = "";
                        BackupImportModal.Visibility = Visibility.Collapsed;
                        MessageBox.Show(Loc.F("Sheet_Done", added), Loc.T("Title_SyncDone"), MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                    else
                    {
                        MessageBox.Show(Loc.T("Sheet_NothingNew"), Loc.T("Title_Info"), MessageBoxButton.OK, MessageBoxImage.Information);
                    }
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show(Loc.T("Sheet_Failed") + ex.Message, Loc.T("Title_SyncError"), MessageBoxButton.OK, MessageBoxImage.Error);
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
                            if (Base32.ToBytes(secret).Length == 0) continue;
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

                // Honour algorithm/digits/period; ignoring them produces wrong codes silently
                string algorithmParam = GetQueryParam(query, "algorithm");
                string? algorithm = Totp.NormalizeAlgorithm(string.IsNullOrEmpty(algorithmParam) ? null : algorithmParam);
                if (algorithm == null) return false;

                string digitsParam = GetQueryParam(query, "digits");
                int digits = Totp.DefaultDigits;
                if (!string.IsNullOrEmpty(digitsParam) && (!int.TryParse(digitsParam, out digits) || digits < 6 || digits > 8)) return false;

                string periodParam = GetQueryParam(query, "period");
                int period = Totp.DefaultPeriod;
                if (!string.IsNullOrEmpty(periodParam) && (!int.TryParse(periodParam, out period) || period <= 0 || period > 300)) return false;

                if (Base32.ToBytes(secret).Length == 0) return false;
                return AddAccountQuietly(issuer, label, secret, algorithm, digits, period);
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

        private bool AddAccountQuietly(string issuer, string label, string secret,
            string algorithm = Totp.DefaultAlgorithm, int digits = Totp.DefaultDigits, int period = Totp.DefaultPeriod)
        {
            secret = secret.Replace(" ", "").ToUpperInvariant();
            if (_allAccounts.Any(x => x.Secret.Equals(secret, StringComparison.OrdinalIgnoreCase)))
                return false;

            _allAccounts.Add(new Account
            {
                Id = Guid.NewGuid().ToString(),
                Issuer = issuer,
                Label = label,
                Secret = secret,
                Algorithm = algorithm,
                Digits = digits,
                Period = period
            });
            return true;
        }

        // ==================== BIOMETRIC UNLOCK (WINDOWS HELLO) ====================

        private void SetHelloCheckbox(bool isChecked)
        {
            _suppressHelloToggle = true;
            ChkWindowsHello.IsChecked = isChecked;
            _suppressHelloToggle = false;
        }

        private void BtnHelloUnlock_Click(object sender, RoutedEventArgs e)
        {
            TriggerWindowsHelloUnlock(silent: false);
        }

        private async void TriggerWindowsHelloUnlock(bool silent)
        {
            if (!File.Exists(_helloPath) || _derivedKey != null) return;

            try
            {
                if (!await WindowsHelloKey.IsSupportedAsync())
                {
                    if (!silent)
                        MessageBox.Show(Loc.T("Hello_Unavailable"), "Windows Hello", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                byte[]? key = await WindowsHelloKey.UnwrapAsync(File.ReadAllBytes(_helloPath));
                if (key == null)
                {
                    if (!silent)
                        MessageBox.Show(Loc.T("Hello_Failed"), "Windows Hello", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                // Unlocked with the password while Hello was showing
                if (_derivedKey != null)
                {
                    CryptographicOperations.ZeroMemory(key);
                    return;
                }

                // The vault was re-created since Hello was enabled; this key no longer fits
                if (!IsVaultKey(key))
                {
                    CryptographicOperations.ZeroMemory(key);
                    RemoveHelloKey();
                    MessageBox.Show(Loc.T("Hello_Stale"), "Windows Hello", MessageBoxButton.OK, MessageBoxImage.Warning);
                    return;
                }

                _failedUnlockAttempts = 0;
                OpenVault(key);
            }
            catch (Exception ex)
            {
                if (!silent)
                    MessageBox.Show(Loc.T("Hello_Error") + ex.Message, Loc.T("Title_AuthError"), MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private async void ChkWindowsHello_Checked(object sender, RoutedEventArgs e)
        {
            if (_suppressHelloToggle) return;

            if (_derivedKey == null)
            {
                SetHelloCheckbox(false);
                return;
            }

            byte[] keyCopy = (byte[])_derivedKey.Clone();
            try
            {
                if (!await WindowsHelloKey.IsSupportedAsync())
                {
                    MessageBox.Show(Loc.T("Hello_NotSupported"), Loc.T("Title_NotSupported"), MessageBoxButton.OK, MessageBoxImage.Warning);
                    SetHelloCheckbox(false);
                    return;
                }

                byte[]? blob = await WindowsHelloKey.WrapAsync(keyCopy);
                if (blob == null || _derivedKey == null)
                {
                    SetHelloCheckbox(false);
                    ShowToast(Loc.T("Hello_Cancelled"));
                    return;
                }

                AtomicFile.WriteAllBytes(_helloPath, blob);
                BtnHelloUnlock.Visibility = Visibility.Visible;
                ShowToast(Loc.T("Hello_Enabled"));
            }
            catch (Exception ex)
            {
                MessageBox.Show(Loc.T("Hello_SetupFailed") + ex.Message, Loc.T("Title_Error"), MessageBoxButton.OK, MessageBoxImage.Error);
                SetHelloCheckbox(false);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(keyCopy);
            }
        }

        private void ChkWindowsHello_Unchecked(object sender, RoutedEventArgs e)
        {
            if (_suppressHelloToggle) return;

            RemoveHelloKey();
            ShowToast(Loc.T("Hello_Disabled"));
        }
    }

    // ==================== ACCOUNT MODEL ====================

    public class Account : INotifyPropertyChanged
    {
        public string Id { get; set; } = string.Empty;
        public string Issuer { get; set; } = string.Empty;
        public string Label { get; set; } = string.Empty;
        public string Secret { get; set; } = string.Empty;

        // otpauth parameters; defaults match accounts saved by version 1.0.0
        public string Algorithm { get; set; } = Totp.DefaultAlgorithm;
        public int Digits { get; set; } = Totp.DefaultDigits;
        public int Period { get; set; } = Totp.DefaultPeriod;

        private string _formattedPin = "------";
        [System.Text.Json.Serialization.JsonIgnore]
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
        [System.Text.Json.Serialization.JsonIgnore]
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

        [System.Text.Json.Serialization.JsonIgnore]
        public string RemainingSecondsText => $"{RemainingSeconds}s";

        [System.Text.Json.Serialization.JsonIgnore]
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
