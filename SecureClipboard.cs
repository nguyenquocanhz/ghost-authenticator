using System;
using System.IO;
using System.Windows;
using System.Windows.Threading;

namespace AuthenticatorDesktop
{
    public static class SecureClipboard
    {
        private static DispatcherTimer? _clearTimer;
        private static string? _lastCopied;

        // Copies sensitive text and clears it again after the given delay (unless the user
        // copied something else meanwhile). The extra formats keep it out of Windows
        // clipboard history and cloud clipboard sync, per Microsoft's clipboard guidance.
        // Returns false when another program is holding the clipboard.
        public static bool SetText(string text, TimeSpan clearAfter)
        {
            var data = new DataObject();
            data.SetText(text);
            data.SetData("ExcludeClipboardContentFromMonitorProcessing", new MemoryStream(new byte[4]));
            data.SetData("CanIncludeInClipboardHistory", new MemoryStream(BitConverter.GetBytes(0)));
            data.SetData("CanUploadToCloudClipboard", new MemoryStream(BitConverter.GetBytes(0)));

            try
            {
                Clipboard.SetDataObject(data, copy: true);
            }
            catch (System.Runtime.InteropServices.ExternalException)
            {
                return false;
            }

            _lastCopied = text;
            _clearTimer?.Stop();
            _clearTimer = new DispatcherTimer { Interval = clearAfter };
            _clearTimer.Tick += (_, _) => ClearIfUnchanged();
            _clearTimer.Start();
            return true;
        }

        // Clears the clipboard if it still holds what we copied. Call on lock and exit too.
        public static void ClearIfUnchanged()
        {
            _clearTimer?.Stop();
            if (_lastCopied == null) return;

            try
            {
                if (Clipboard.ContainsText() && Clipboard.GetText() == _lastCopied)
                {
                    Clipboard.Clear();
                }
            }
            catch (System.Runtime.InteropServices.ExternalException)
            {
                // Clipboard busy; nothing else we can safely do.
            }
            _lastCopied = null;
        }
    }
}
