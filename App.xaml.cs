using System.Windows;
using System.Windows.Threading;

namespace AuthenticatorDesktop
{
    public partial class App : Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            // Pick the UI language before the main window loads its text.
            Loc.Initialize(AppSettings.Load(AppSettings.DefaultPath).Language);

            base.OnStartup(e);

            // Show unexpected errors instead of letting the app crash and lose the user's work.
            DispatcherUnhandledException += OnDispatcherUnhandledException;
        }

        private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            MessageBox.Show(Loc.T("App_UnexpectedError") + e.Exception.Message, "Ghost Authenticator", MessageBoxButton.OK, MessageBoxImage.Error);
            e.Handled = true;
        }
    }
}
