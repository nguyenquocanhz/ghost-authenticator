using System;
using System.IO;
using System.Text.Json;
using Microsoft.Win32;

namespace AuthenticatorDesktop
{
    // Non-secret UI preferences. Stored in plain JSON next to the vault.
    public sealed class AppSettings
    {
        public bool? DarkMode { get; set; }

        // "vi" or "en"; null follows the Windows display language.
        public string? Language { get; set; }

        public static string DataDirectory => Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "GhostAuthenticator");

        public static string DefaultPath => Path.Combine(DataDirectory, "settings.json");

        public static AppSettings Load(string path)
        {
            try
            {
                if (File.Exists(path))
                {
                    return JsonSerializer.Deserialize<AppSettings>(File.ReadAllText(path)) ?? new AppSettings();
                }
            }
            catch (Exception)
            {
                // A broken settings file only resets preferences.
            }
            return new AppSettings();
        }

        public void Save(string path)
        {
            try
            {
                AtomicFile.WriteAllBytes(path, JsonSerializer.SerializeToUtf8Bytes(this));
            }
            catch (Exception)
            {
                // Preferences are best effort.
            }
        }

        // Follows the Windows "app mode" setting until the user picks a theme in the app.
        public static bool SystemPrefersDark()
        {
            try
            {
                using var key = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize");
                return key?.GetValue("AppsUseLightTheme") is int value && value == 0;
            }
            catch (Exception)
            {
                return false;
            }
        }
    }
}
