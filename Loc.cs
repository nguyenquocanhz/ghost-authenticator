using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Text;
using System.Windows.Markup;

namespace AuthenticatorDesktop
{
    // UI text in Vietnamese and English, loaded from the embedded Strings.lang table.
    public static class Loc
    {
        public const string Vietnamese = "vi";
        public const string English = "en";

        private static readonly Dictionary<string, string> Vi = new();
        private static readonly Dictionary<string, string> En = new();
        private static Dictionary<string, string> _current = En;

        public static string Language { get; private set; } = English;

        static Loc()
        {
            Load();
        }

        // Picks the saved language, otherwise Vietnamese on Vietnamese Windows and English elsewhere.
        public static void Initialize(string? savedLanguage)
        {
            string language = savedLanguage == Vietnamese || savedLanguage == English
                ? savedLanguage
                : CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == Vietnamese ? Vietnamese : English;

            Language = language;
            _current = language == Vietnamese ? Vi : En;
        }

        public static string T(string key)
        {
            return _current.TryGetValue(key, out var text) ? text : key;
        }

        public static string F(string key, params object[] args)
        {
            return string.Format(T(key), args);
        }

        public static IReadOnlyCollection<string> Keys(string language)
        {
            return (language == Vietnamese ? Vi : En).Keys;
        }

        private static void Load()
        {
            using var stream = typeof(Loc).Assembly.GetManifestResourceStream("AuthenticatorDesktop.Strings.lang");
            if (stream == null) return;

            using var reader = new StreamReader(stream, Encoding.UTF8);
            string? line;
            while ((line = reader.ReadLine()) != null)
            {
                if (line.Length == 0 || line.StartsWith('#')) continue;

                // kind‖key‖Vietnamese‖English
                var parts = line.Split('‖');
                if (parts.Length != 4) continue;

                Vi[parts[1]] = Unescape(parts[2]);
                En[parts[1]] = Unescape(parts[3]);
            }
        }

        private static string Unescape(string text)
        {
            return text.Replace("\\n", "\n");
        }
    }

    // XAML usage: Text="{local:Loc Welcome_Title}"
    [MarkupExtensionReturnType(typeof(string))]
    public sealed class LocExtension : MarkupExtension
    {
        public LocExtension(string key)
        {
            Key = key;
        }

        [ConstructorArgument("key")]
        public string Key { get; set; }

        public override object ProvideValue(IServiceProvider serviceProvider)
        {
            return Loc.T(Key);
        }
    }
}
