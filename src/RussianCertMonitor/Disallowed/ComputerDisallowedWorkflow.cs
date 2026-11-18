using System.ComponentModel;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RussianCertMonitor.Certificates;
using RussianCertMonitor.Infrastructure;

namespace RussianCertMonitor.Disallowed;

internal sealed record ComputerDisallowedChange(DisallowedResult Computer, DisallowedResult? UserCleanup,
    string? UserCleanupError, WindowsTrustAssessment Trust,
    TrustCopyChange? ComputerCopies = null, TrustCopyChange? UserCopies = null)
{
    public bool IsConfirmed => Computer.Operation == DisallowedOperation.Add
        ? Computer.OwnPresentAfter && UserCleanupError is null && Trust.CurrentUser.IsExplicitlyDistrusted
            && Trust.LocalMachine.IsExplicitlyDistrusted
        : !Computer.OwnPresentAfter && !Computer.LogicalPresentAfter && UserCleanupError is null
            && UserCleanup?.LogicalPresentAfter != true
            && Trust.CurrentUser.ErrorStatus.HasValue && Trust.LocalMachine.ErrorStatus.HasValue
            && !Trust.CurrentUser.IsExplicitlyDistrusted && !Trust.LocalMachine.IsExplicitlyDistrusted;
}

internal sealed class ComputerDisallowedWorkflow(DisallowedManager manager,
    Func<DisallowedJob, CancellationToken, Func<Task>?, Task<DisallowedReply>> executeOnComputer,
    DiagnosticLog? log = null, Func<byte[], WindowsTrustAssessment>? verify = null,
    TrustCopyQuarantine? quarantine = null)
{
    private const string MachineStore = "LocalMachine\\Disallowed";

    public async Task<ComputerDisallowedChange?> ChangeAsync(DisallowedOperation operation,
        PublicCertificateData certificate, CancellationToken token)
    {
        token.ThrowIfCancellationRequested();
        string id = certificate.Metadata.CertificateId;
        DisallowedJob job = new(1, operation, StoreLocation.LocalMachine, id, certificate.Metadata.RawData);
        log?.TryWrite("disallowed.elevation-requested",
            $"Запрошено изменение чёрного списка компьютера: {operation}; ID={id}.",
            context: new(id, MachineStore, operation.ToString()));
        TrustCopyChange? userCopies = null;
        Func<Task>? beforeApply = operation == DisallowedOperation.Remove && quarantine is not null
            ? () => Task.Run(() => userCopies = RestoreUserCopies(certificate), token) : null;
        DisallowedReply reply = await executeOnComputer(job, token, beforeApply).ConfigureAwait(false);
        RecordCopies(id, operation, reply.TrustCopies);
        if (reply.Cancelled)
        {
            log?.TryWrite("disallowed.cancelled", "Операция отменена в UAC или окне подтверждения.",
                context: new(id, MachineStore, "cancelled"));
            return null;
        }
        if (reply.Error is not null)
            throw new InvalidOperationException(reply.Error);

        if (reply.Result is not { } computer
            || computer.Location != StoreLocation.LocalMachine || computer.Operation != operation
            || !string.Equals(computer.CertificateId, id, StringComparison.OrdinalIgnoreCase)
            || computer.OwnPresentAfter != (operation == DisallowedOperation.Add))
            throw new InvalidDataException("Результат изменения списка компьютера не подтверждён.");

        log?.TryWrite("disallowed.completed",
            $"Операция={operation}; область=LocalMachine; ID={id}; изменено={computer.Changed}; " +
            $"своё={computer.OwnPresentAfter}; логическое={computer.LogicalPresentAfter}.",
            context: new(id, MachineStore, $"{operation}; changed={computer.Changed}; ownPresent={computer.OwnPresentAfter}; logicalPresent={computer.LogicalPresentAfter}"));
        return await Task.Run(() => Complete(computer, certificate, reply.TrustCopies, userCopies)).ConfigureAwait(false);
    }

    private TrustCopyChange? RestoreUserCopies(PublicCertificateData certificate)
    {
        string id = certificate.Metadata.CertificateId;
        if (quarantine?.HasBackup(StoreLocation.CurrentUser, id) != true)
            return null;
        EnsureComputerBlock(certificate);
        TrustCopyChange restored = quarantine.Restore(StoreLocation.CurrentUser, id);
        RecordCopies(id, DisallowedOperation.Remove, restored);
        if (restored.Issues.Length > 0)
            throw new InvalidOperationException("Копии пользователя восстановлены не полностью. Запрет остаётся в силе. "
                + string.Join("; ", restored.Issues));
        return restored;
    }

    private void EnsureComputerBlock(PublicCertificateData certificate)
    {
        DisallowedPreview machine = manager.Preview(DisallowedOperation.Remove, StoreLocation.LocalMachine, certificate);
        if (!machine.OwnPresent || !machine.Certificate.Metadata.RawData.AsSpan().SequenceEqual(certificate.Metadata.RawData)
            || !CheckTrust(certificate).LocalMachine.IsExplicitlyDistrusted)
            throw new InvalidOperationException("Подтверждённый запрет компьютера отсутствует. Сначала снова добавьте сертификат в чёрный список.");
    }

    private ComputerDisallowedChange Complete(DisallowedResult computer, PublicCertificateData certificate,
        TrustCopyChange? machineCopies, TrustCopyChange? userCopies)
    {
        WindowsTrustAssessment trust = CheckTrust(certificate);
        DisallowedResult? user = null;
        string? cleanupError = null;

        if (computer.Operation == DisallowedOperation.Add && quarantine is not null
            && trust.CurrentUser.IsExplicitlyDistrusted && trust.LocalMachine.IsExplicitlyDistrusted)
        {
            try
            {
                EnsureComputerBlock(certificate);
                userCopies = quarantine.Isolate(StoreLocation.CurrentUser, computer.CertificateId);
            }
            catch (Exception error) when (TrustCopyQuarantine.IsAccessError(error))
            {
                userCopies = new(StoreLocation.CurrentUser, [], [ErrorText.Describe(error)]);
            }
            RecordCopies(computer.CertificateId, computer.Operation, userCopies);
        }

        // Прежний запрет пользователя можно убрать лишь после подтверждения запрета компьютера.
        if (computer.Operation == DisallowedOperation.Remove
            || (trust.CurrentUser.IsExplicitlyDistrusted && trust.LocalMachine.IsExplicitlyDistrusted))
        {
            try
            {
                DisallowedPreview preview = manager.Preview(DisallowedOperation.Remove,
                    StoreLocation.CurrentUser, certificate);
                if (preview.OwnPresent)
                {
                    if (!preview.Certificate.Metadata.RawData.AsSpan().SequenceEqual(certificate.Metadata.RawData))
                        throw new CryptographicException("Пользовательская запись отличается от выбранного сертификата.");
                    user = manager.Execute(preview);
                }
            }
            catch (Exception error) when (error is CryptographicException or Win32Exception or IOException
                or UnauthorizedAccessException or InvalidOperationException)
            {
                cleanupError = ErrorText.Describe(error);
                log?.TryWrite("disallowed.user-cleanup-error",
                    "Не удалось завершить обработку прежней пользовательской записи.",
                    error, new(computer.CertificateId, "CurrentUser\\Disallowed", "warning"));
            }
        }

        if (user is not null || cleanupError is not null || userCopies is not null)
            trust = CheckTrust(certificate);
        ComputerDisallowedChange change = new(computer, user, cleanupError, trust, machineCopies, userCopies);
        log?.TryWrite("disallowed.trust-verified",
            $"Операция={computer.Operation}; ID={computer.CertificateId}; подтверждено={change.IsConfirmed}; " +
            $"пользователь={trust.CurrentUser.Details}; компьютер={trust.LocalMachine.Details}.",
            context: new(computer.CertificateId, MachineStore, change.IsConfirmed ? "confirmed" : "warning"));
        return change;
    }

    private void RecordCopies(string id, DisallowedOperation operation, TrustCopyChange? copies)
    {
        if (copies is null || (copies.ChangedStores.Length == 0 && copies.Issues.Length == 0))
            return;
        string action = operation == DisallowedOperation.Add ? "Сохранены и убраны копии" : "Восстановлены копии";
        log?.TryWrite(copies.Issues.Length == 0 ? "disallowed.copies" : "disallowed.copies-error",
            $"{action}: {copies.Scope}, ID={id}, хранилища: {string.Join(", ", copies.ChangedStores)}. " +
            string.Join("; ", copies.Issues),
            context: new(id, copies.Scope.ToString(), operation.ToString()));
    }

    private WindowsTrustAssessment CheckTrust(PublicCertificateData certificate)
    {
        try
        {
            byte[] der = certificate.Metadata.RawData;
            if (verify is not null)
                return verify(der);
            using WindowsTrustVerifier verifier = new();
            return verifier.Verify(der);
        }
        catch (Exception error) when (error is CryptographicException or Win32Exception or IOException
            or UnauthorizedAccessException or InvalidOperationException)
        {
            WindowsChainResult failure = new(null, ErrorText.Describe(error));
            return new(failure, failure);
        }
    }
}
