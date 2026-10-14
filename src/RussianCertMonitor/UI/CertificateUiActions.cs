using RussianCertMonitor.Inventory;

namespace RussianCertMonitor.UI;

internal sealed record CertificateUiActions(
    Action<InventoryCertificate> ShowProperties,
    Action<InventoryCertificate> Export,
    Func<InventoryCertificate, Task> AddToDisallowed,
    Func<InventoryCertificate, Task> RemoveFromDisallowed,
    Func<Task> ImportToDisallowed)
{
    public static CertificateUiActions Disabled { get; } = new(_ => { }, _ => { },
        _ => Task.CompletedTask, _ => Task.CompletedTask, () => Task.CompletedTask);
}
