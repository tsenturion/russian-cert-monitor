using System.Runtime.InteropServices;

namespace RussianCertMonitor.UI;

internal static class WindowVisibility
{
    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern int ShowWindow(nint windowHandle, int command);

    [DllImport("user32.dll", ExactSpelling = true)]
    private static extern int IsWindowVisible(nint windowHandle);

    public static void EnsureVisible(Form window)
    {
        // Первый показ может наследовать SW_HIDE от запускающей программы.
        // Повторная команда явно показывает окно после скрытого старта из Startup.
        _ = ShowWindow(window.Handle, 5);
        if (IsWindowVisible(window.Handle) == 0)
            throw new InvalidOperationException("Windows не показала окно справочника.");
    }
}
