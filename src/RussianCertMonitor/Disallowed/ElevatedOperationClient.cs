using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;

namespace RussianCertMonitor.Disallowed;

internal interface IPrivilegedProcessLauncher
{
    Process Start(string token, int parentId);
}

internal sealed class PrivilegedProcessLauncher : IPrivilegedProcessLauncher
{
    public Process Start(string token, int parentId)
    {
        string exe = Environment.ProcessPath ?? throw new InvalidOperationException("Путь приложения недоступен.");
        if (!Path.GetFileName(exe).Equals("RussianCertMonitor.exe", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("Операцию с компьютером нужно запускать из EXE RussianCertMonitor.");
        ProcessStartInfo start = new(exe) { UseShellExecute = true, Verb = "runas", WorkingDirectory = AppContext.BaseDirectory };
        start.ArgumentList.Add(OperationProtocol.HelperArgument);
        start.ArgumentList.Add(token);
        start.ArgumentList.Add(parentId.ToString(System.Globalization.CultureInfo.InvariantCulture));
        return Process.Start(start) ?? throw new InvalidOperationException("Привилегированный процесс не запущен.");
    }
}

internal sealed class ElevatedOperationClient(IPrivilegedProcessLauncher launcher)
{
    public async Task<DisallowedReply> ExecuteAsync(DisallowedJob job, CancellationToken cancellationToken = default)
        => await ExecuteAsync(job, cancellationToken, beforeApply: null);

    public async Task<DisallowedReply> ExecuteAsync(DisallowedJob job, CancellationToken cancellationToken,
        Func<Task>? beforeApply)
    {
        OperationProtocol.ValidateMachineJob(job);
        string nonce = Guid.NewGuid().ToString("N");
        using NamedPipeServerStream pipe = new(OperationProtocol.PipeName(nonce), PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        Process helper;
        try
        {
            helper = launcher.Start(nonce, Environment.ProcessId);
        }
        catch (Win32Exception error) when (error.NativeErrorCode == 1223)
        {
            return new DisallowedReply(true, null, null);
        }
        using (helper)
        {
            using CancellationTokenSource connectionTimeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            connectionTimeout.CancelAfter(TimeSpan.FromSeconds(15));
            try
            {
                while (true)
                {
                    await pipe.WaitForConnectionAsync(connectionTimeout.Token);
                    if (OperationProtocol.HasExpectedPeer(pipe, helper.Id, server: true))
                        break;
                    pipe.Disconnect();
                }
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                throw new IOException("Привилегированный процесс не подключился к приложению.");
            }
            await OperationProtocol.WriteAsync(pipe, job, cancellationToken);
            DisallowedHandshake handshake = await OperationProtocol.ReadAsync<DisallowedHandshake>(pipe, cancellationToken);
            if (handshake.Error is not null)
                return new DisallowedReply(false, null, handshake.Error);
            if (!handshake.Confirmed)
                return new DisallowedReply(true, null, null);
            cancellationToken.ThrowIfCancellationRequested();
            // Перед снятием общего запрета клиент может восстановить копии в своей учётной записи.
            if (beforeApply is not null)
                await beforeApply();
            cancellationToken.ThrowIfCancellationRequested();
            await OperationProtocol.WriteAsync(pipe, new DisallowedAuthorization(true), cancellationToken);
            DisallowedReply reply = await OperationProtocol.ReadAsync<DisallowedReply>(pipe, cancellationToken);
            if (reply.Result is { } result && (result.Location != job.Location || result.Operation != job.Operation
                || !result.CertificateId.Equals(job.CertificateId, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidDataException("Ответ операции не соответствует выбранному объекту.");
            if (reply.TrustCopies is { Scope: not System.Security.Cryptography.X509Certificates.StoreLocation.LocalMachine })
                throw new InvalidDataException("Ответ о копиях относится к другой области.");
            return reply;
        }
    }
}
