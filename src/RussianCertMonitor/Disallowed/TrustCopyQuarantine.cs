using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RussianCertMonitor.Infrastructure;

namespace RussianCertMonitor.Disallowed;

internal sealed record TrustCopyChange(StoreLocation Scope, string[] ChangedStores, string[] Issues);

internal sealed class TrustCopyQuarantine(ITrustCopyStore stores, ITrustCopyVault vault)
{
    public static TrustCopyQuarantine Windows() => new(new WindowsTrustCopyStore(), new RegistryTrustCopyVault());

    public bool HasBackup(StoreLocation scope, string id) => vault.Read(scope, id).Count > 0;

    public TrustCopyChange Isolate(StoreLocation scope, string id)
    {
        Dictionary<string, TrustCopyBackup> backups = vault.Read(scope, id)
            .ToDictionary(item => item.Store, StringComparer.OrdinalIgnoreCase);
        List<TrustCopyBackup> remove = [];
        List<string> affected = [];
        List<string> issues = [];
        bool backupChanged = false;
        foreach (string name in WindowsTrustCopyStore.Stores)
        {
            try
            {
                byte[]? current = stores.Read(scope, name, id);
                if (current is null)
                    continue;
                if (backups.TryGetValue(name, out TrustCopyBackup? saved))
                {
                    if (!stores.AreEquivalent(current, saved.Serialized))
                    {
                        issues.Add($"{name}: обнаружена изменённая копия. Она осталась под запретом Windows.");
                        continue;
                    }
                }
                else
                {
                    saved = new(name, current);
                    backups.Add(name, saved);
                    backupChanged = true;
                }
                remove.Add(saved);
            }
            catch (Exception error) when (IsAccessError(error))
            {
                issues.Add($"{name}: {ErrorText.Describe(error)}");
            }
        }

        // Сначала записываем все новые копии. При ошибке записи ничего не удаляем.
        if (backupChanged)
            vault.Save(scope, id, backups.Values.ToArray());
        foreach (TrustCopyBackup copy in remove)
        {
            try
            {
                stores.Remove(scope, copy.Store, id, copy.Serialized);
                if (stores.Read(scope, copy.Store, id) is not null)
                    throw new InvalidOperationException("Копия всё ещё присутствует.");
                affected.Add(copy.Store);
            }
            catch (Exception error) when (IsAccessError(error))
            {
                issues.Add($"{copy.Store}: {ErrorText.Describe(error)}");
            }
        }
        return new(scope, affected.ToArray(), issues.ToArray());
    }

    public TrustCopyChange Restore(StoreLocation scope, string id)
    {
        IReadOnlyList<TrustCopyBackup> saved = vault.Read(scope, id);
        List<string> affected = [];
        List<string> issues = [];
        foreach (TrustCopyBackup copy in saved)
        {
            try
            {
                stores.Restore(scope, copy.Store, id, copy.Serialized);
                if (stores.Read(scope, copy.Store, id) is null)
                    throw new InvalidOperationException("Восстановленную запись не удалось прочитать.");
                affected.Add(copy.Store);
            }
            catch (Exception error) when (IsAccessError(error))
            {
                issues.Add($"{copy.Store}: {ErrorText.Describe(error)}");
            }
        }
        if (saved.Count > 0 && issues.Count == 0)
            vault.Clear(scope, id);
        return new(scope, affected.ToArray(), issues.ToArray());
    }

    internal static bool IsAccessError(Exception error) => error is CryptographicException or Win32Exception
        or IOException or UnauthorizedAccessException or InvalidOperationException or InvalidDataException
        or System.Security.SecurityException;
}
