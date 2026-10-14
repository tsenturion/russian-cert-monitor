using System.IO.Pipes;
using System.Security.Principal;
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
                reply = new DisallowedReply(false, manager.Execute(preview), null);
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
}
