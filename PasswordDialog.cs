using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;

namespace AuthenticatorDesktop
{
    // Masked password prompt. Replaces Microsoft.VisualBasic InputBox, which shows the
    // password in clear text on screen.
    public sealed class PasswordDialog : Window
    {
        private readonly PasswordBox _password;
        private readonly PasswordBox? _confirm;
        private readonly TextBlock _error;
        private readonly int _minLength;

        private PasswordDialog(Window owner, string title, string message, bool requireConfirm, int minLength)
        {
            _minLength = minLength;

            Owner = owner;
            Title = title;
            Width = 420;
            SizeToContent = SizeToContent.Height;
            ResizeMode = ResizeMode.NoResize;
            WindowStartupLocation = WindowStartupLocation.CenterOwner;
            ShowInTaskbar = false;

            Brush background = (owner.TryFindResource("ModalBg") as Brush) ?? Brushes.White;
            Brush primary = (owner.TryFindResource("TextPrimary") as Brush) ?? Brushes.Black;
            Brush secondary = (owner.TryFindResource("TextSecondary") as Brush) ?? Brushes.DimGray;
            Brush danger = (owner.TryFindResource("DangerRed") as Brush) ?? Brushes.Red;
            Background = background;

            var panel = new StackPanel { Margin = new Thickness(20) };
            panel.Children.Add(new TextBlock
            {
                Text = message,
                TextWrapping = TextWrapping.Wrap,
                Foreground = primary,
                Margin = new Thickness(0, 0, 0, 12)
            });

            _password = CreatePasswordBox(title);
            panel.Children.Add(_password);

            if (requireConfirm)
            {
                panel.Children.Add(new TextBlock
                {
                    Text = Loc.T("Pwd_Retype"),
                    Foreground = secondary,
                    FontSize = 12,
                    Margin = new Thickness(0, 10, 0, 4)
                });
                _confirm = CreatePasswordBox(Loc.T("Pwd_Retype"));
                panel.Children.Add(_confirm);
            }

            _error = new TextBlock
            {
                Foreground = danger,
                FontSize = 12,
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 8, 0, 0),
                Visibility = Visibility.Collapsed
            };
            panel.Children.Add(_error);

            var buttons = new StackPanel
            {
                Orientation = Orientation.Horizontal,
                HorizontalAlignment = HorizontalAlignment.Right,
                Margin = new Thickness(0, 16, 0, 0)
            };
            var ok = new Button { Content = Loc.T("Pwd_Ok"), IsDefault = true, MinWidth = 90, Padding = new Thickness(10, 6, 10, 6), Margin = new Thickness(0, 0, 8, 0) };
            var cancel = new Button { Content = Loc.T("Pwd_Cancel"), IsCancel = true, MinWidth = 90, Padding = new Thickness(10, 6, 10, 6) };
            ok.Click += (_, _) => Submit();
            buttons.Children.Add(ok);
            buttons.Children.Add(cancel);
            panel.Children.Add(buttons);

            Content = panel;
            Loaded += (_, _) => Keyboard.Focus(_password);
        }

        private static PasswordBox CreatePasswordBox(string automationName)
        {
            var box = new PasswordBox { PasswordChar = '●', Padding = new Thickness(8, 6, 8, 6) };
            System.Windows.Automation.AutomationProperties.SetName(box, automationName);
            return box;
        }

        private void Submit()
        {
            string password = _password.Password;

            if (password.Length < _minLength)
            {
                ShowError(_minLength > 1
                    ? Loc.F("Pwd_MinLength", _minLength)
                    : Loc.T("Pwd_Empty"));
                return;
            }

            if (_confirm != null && _confirm.Password != password)
            {
                ShowError(Loc.T("Pwd_Mismatch"));
                return;
            }

            DialogResult = true;
        }

        private void ShowError(string message)
        {
            _error.Text = message;
            _error.Visibility = Visibility.Visible;
        }

        // Returns the entered password, or null when the user cancelled.
        public static string? Prompt(Window owner, string title, string message, bool requireConfirm = false, int minLength = 1)
        {
            var dialog = new PasswordDialog(owner, title, message, requireConfirm, minLength);
            return dialog.ShowDialog() == true ? dialog._password.Password : null;
        }
    }
}
