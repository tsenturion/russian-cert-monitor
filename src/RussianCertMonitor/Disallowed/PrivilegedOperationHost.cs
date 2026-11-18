using System.IO.Pipes;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;
using RussianCertMonitor.Certificates;
using RussianCertMonitor.UI;

namespace RussianCertMonitor.Disallowed;

internal static class PrivilegedOperationHost
{
    public static int Run(string[] args)
    {
        if (!OperationProtocol.TryParseArguments(args, out string token, out int parentId))
            return 2;
        using WindowsIdentity identity = WindowsIdentity.GetCurrent();
        if (!new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator))
            return 3;
        using NamedPipeClientStream pipe = new(".", OperationProtocol.PipeName(token), PipeDirection.InOut,
            PipeOptions.Asynchronous);
        try
        {
            pipe.Connect(10_000);
            if (!OperationProtocol.HasExpectedPeer(pipe, parentId, server: false))
                return 4;
            DisallowedPreview preview;
            DisallowedManager manager = new(new WindowsDisallowedStoreBackend());
            try
            {
                DisallowedJob job = OperationProtocol.ReadAsync<DisallowedJob>(pipe).GetAwaiter().GetResult();
                PublicCertificateData certificate = OperationProtocol.ValidateMachineJob(job);
                preview = manager.Preview(job.Operation, job.Location, certificate);
            }
            catch (Exception error)
            {
                OperationProtocol.WriteAsync(pipe, new DisallowedHandshake(false, error.Message)).GetAwaiter().GetResult();
                return 5;
            }

            bool confirmed = DisallowedDialogs.Confirm(null, preview);
            OperationProtocol.WriteAsync(pipe, new DisallowedHandshake(confirmed, null)).GetAwaiter().GetResult();
            if (!confirmed)
                return 0;
            DisallowedAuthorization authorization = OperationProtocol.ReadAsync<DisallowedAuthorization>(pipe)
                .GetAwaiter().GetResult();
            if (!authorization.Apply || !OperationProtocol.HasExpectedPeer(pipe, parentId, server: false))
                return 6;

            DisallowedReply reply;
            try
            {
                reply = ApplyMachineChange(manager, preview);
            }
            catch (Exception error)
            {
                reply = new DisallowedReply(false, null, error.Message);
            }
            OperationProtocol.WriteAsync(pipe, reply).GetAwaiter().GetResult();
            return reply.Error is null ? 0 : 1;
        }
        catch (Exception error) when (error is IOException or InvalidDataException or TimeoutException
            or UnauthorizedAccessException or System.Text.Json.JsonException)
        {
            // В привилегированном режиме нет записи в пользовательские файлы; диагностику ведёт основной процесс.
            System.Diagnostics.Debug.WriteLine(error.Message);
            return 7;
        }
    }

    private static DisallowedReply ApplyMachineChange(DisallowedManager manager, DisallowedPreview preview)
    {
        WindowsDisallowedStoreBackend backend = new();
        TrustCopyQuarantine quarantine = TrustCopyQuarantine.Windows();
        string id = preview.Certificate.Metadata.CertificateId;
        StoreLocation scope = StoreLocation.LocalMachine;
        TrustCopyChange? copies = null;
        // Разные учётные записи могут одновременно открыть приложение.
        using Mutex gate = new(false, $"Global\\RussianCertMonitor.TrustCopies.{id.ToUpperInvariant()}");
        try
        {
            if (!gate.WaitOne(TimeSpan.FromSeconds(15)))
                throw new InvalidOperationException("Этот сертификат уже изменяется в другой операции.");
        }
        catch (AbandonedMutexException)
        {
            // Повторная операция проверяет состояние хранилища и сохранённый журнал.
        }
        try
        {
            if (preview.Operation == DisallowedOperation.Remove && quarantine.HasBackup(scope, id))
            {
                using WindowsTrustVerifier verifier = new();
                if (!backend.Contains(scope, id)
                    || !verifier.Verify(preview.Certificate.Metadata.RawData).LocalMachine.IsExplicitlyDistrusted)
                    return new(false, null, "Машинный запрет отсутствует. Сначала снова добавьте сертификат в чёрный список.");
                copies = quarantine.Restore(scope, id);
                if (copies.Issues.Length > 0)
                    return new(false, null, "Не все копии восстановлены. Машинный запрет остаётся в силе.", copies);
            }

            DisallowedResult result = manager.Execute(preview);
            if (preview.Operation == DisallowedOperation.Add)
            {
                try
                {
                    using WindowsTrustVerifier verifier = new();
                    if (verifier.Verify(preview.Certificate.Metadata.RawData).LocalMachine.IsExplicitlyDistrusted)
                        copies = quarantine.Isolate(scope, id);
                    else
                        copies = new(scope, [], ["Windows не подтвердила машинный запрет. Копии сохранены в исходных хранилищах."]);
                }
                catch (Exception error) when (TrustCopyQuarantine.IsAccessError(error))
                {
                    copies = new(scope, [], [error.Message]);
                }
            }
            return new(false, result, null, copies);
        }
        finally
        {
            gate.ReleaseMutex();
        }
    }
}
