using System.ComponentModel;
using System.Diagnostics;
using System.IO.Pipes;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RussianCertMonitor.Certificates;
using RussianCertMonitor.Disallowed;

namespace RussianCertMonitor.Tests;

internal static class OperationProtocolChecks
{
    public static void Run()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new("CN=Operation-Test, C=US", key, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        using X509Certificate2 native = request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
        PublicCertificateData certificate = PublicCertificateData.FromDer(native.Export(X509ContentType.Cert));
        DisallowedJob job = new(1, DisallowedOperation.Add, StoreLocation.LocalMachine,
            certificate.Metadata.CertificateId, certificate.Metadata.RawData);
        Require(OperationProtocol.ValidateMachineJob(job).Metadata.CertificateId == job.CertificateId,
            "Привилегированный режим должен принимать один публичный сертификат.");
        Reject(() => OperationProtocol.ValidateMachineJob(job with { Location = StoreLocation.CurrentUser }));
        Reject(() => OperationProtocol.ValidateMachineJob(job with { Operation = (DisallowedOperation)100 }));
        Reject(() => OperationProtocol.ValidateMachineJob(job with { SchemaVersion = 2 }));
        Reject(() => OperationProtocol.ValidateMachineJob(job with { CertificateId = new string('0', 40) }));
        Reject(() => OperationProtocol.ValidateMachineJob(job with { CertificateData = native.Export(X509ContentType.Pfx) }));
        Require(OperationProtocol.TryParseArguments([OperationProtocol.HelperArgument, Guid.NewGuid().ToString("N"), "123"], out _, out _),
            "Аргументы должны содержать только имя режима, токен и PID родителя.");
        Require(!OperationProtocol.TryParseArguments([OperationProtocol.HelperArgument, "path", "123"], out _, out _)
            && !OperationProtocol.TryParseArguments([OperationProtocol.HelperArgument, Guid.NewGuid().ToString("N"), "0"], out _, out _),
            "Произвольные пути и отсутствующий родитель не должны приниматься.");

        using MemoryStream buffer = new();
        OperationProtocol.WriteAsync(buffer, job).GetAwaiter().GetResult();
        buffer.Position = 0;
        DisallowedJob read = OperationProtocol.ReadAsync<DisallowedJob>(buffer).GetAwaiter().GetResult();
        Require(read.CertificateData.SequenceEqual(job.CertificateData), "Протокол не должен менять публичный DER.");
        using MemoryStream invalid = new(new byte[] { 255, 255, 255, 127 });
        Reject(() => OperationProtocol.ReadAsync<DisallowedJob>(invalid).GetAwaiter().GetResult());
        using MemoryStream truncated = new(new byte[] { 1, 0 });
        Reject(() => OperationProtocol.ReadAsync<DisallowedJob>(truncated).GetAwaiter().GetResult());

        DisallowedReply cancelled = new ElevatedOperationClient(new CancelledLauncher()).ExecuteAsync(job).GetAwaiter().GetResult();
        Require(cancelled is { Cancelled: true, Result: null, Error: null },
            "Отмена UAC должна завершаться без результата изменения.");
        VerifyPipePeer();
        VerifyHandshakeAsync(job, confirmed: false).GetAwaiter().GetResult();
        VerifyHandshakeAsync(job, confirmed: true).GetAwaiter().GetResult();
        VerifyFailedRestoreAsync(job with { Operation = DisallowedOperation.Remove }).GetAwaiter().GetResult();
    }

    private static void VerifyPipePeer()
    {
        string token = Guid.NewGuid().ToString("N");
        using NamedPipeServerStream server = new(OperationProtocol.PipeName(token), PipeDirection.InOut, 1,
            PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
        using NamedPipeClientStream client = new(".", OperationProtocol.PipeName(token), PipeDirection.InOut, PipeOptions.Asynchronous);
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(3));
        Task connect = server.WaitForConnectionAsync(timeout.Token);
        client.Connect(2000);
        connect.GetAwaiter().GetResult();
        Require(OperationProtocol.HasExpectedPeer(server, Environment.ProcessId, true)
            && OperationProtocol.HasExpectedPeer(client, Environment.ProcessId, false)
            && !OperationProtocol.HasExpectedPeer(server, Environment.ProcessId + 1, true),
            "Обе стороны должны подтверждать конкретный PID, а не только имя канала.");
    }

    private static Task VerifyHandshakeAsync(DisallowedJob job, bool confirmed) => Task.Run(async () =>
    {
        SimulatedLauncher launcher = new(confirmed);
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        DisallowedReply reply = await new ElevatedOperationClient(launcher).ExecuteAsync(job, timeout.Token);
        await launcher.Completion!;
        Require(confirmed ? reply.Result is { Location: StoreLocation.LocalMachine }
            && !reply.Cancelled && launcher.Authorized : reply.Cancelled && !launcher.Authorized,
            "Изменение должно разрешаться только после подтверждения и ответа основного процесса.");
    });

    private static Task VerifyFailedRestoreAsync(DisallowedJob job) => Task.Run(async () =>
    {
        SimulatedLauncher launcher = new(confirmed: true, clientWillAbort: true);
        using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(5));
        bool failed = false;
        try
        {
            await new ElevatedOperationClient(launcher).ExecuteAsync(job, timeout.Token,
                () => Task.FromException(new IOException("Резервная копия не восстановлена.")));
        }
        catch (IOException)
        {
            failed = true;
        }
        await launcher.Completion!.WaitAsync(timeout.Token);
        Require(failed && !launcher.Authorized,
            "Сбой восстановления копий пользователя должен оставить машинный запрет без изменений.");
    });

    private static void Reject(Action action)
    {
        try { action(); }
        catch (Exception error) when (error is ArgumentException or IOException or InvalidDataException or CryptographicException) { return; }
        throw new InvalidOperationException("Недопустимый запрос принят.");
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed class CancelledLauncher : IPrivilegedProcessLauncher
    {
        public Process Start(string token, int parentId) => throw new Win32Exception(1223);
    }

    private sealed class SimulatedLauncher(bool confirmed, bool clientWillAbort = false) : IPrivilegedProcessLauncher
    {
        public Task? Completion { get; private set; }
        public bool Authorized { get; private set; }
        public Process Start(string token, int parentId)
        {
            Completion = Task.Run(async () =>
            {
                using NamedPipeClientStream pipe = new(".", OperationProtocol.PipeName(token), PipeDirection.InOut, PipeOptions.Asynchronous);
                await pipe.ConnectAsync(2000);
                Require(OperationProtocol.HasExpectedPeer(pipe, parentId, false), "Не подтверждён родитель операции.");
                DisallowedJob received = await OperationProtocol.ReadAsync<DisallowedJob>(pipe);
                OperationProtocol.ValidateMachineJob(received);
                await OperationProtocol.WriteAsync(pipe, new DisallowedHandshake(confirmed, null));
                if (!confirmed) return;
                DisallowedAuthorization authorization;
                try { authorization = await OperationProtocol.ReadAsync<DisallowedAuthorization>(pipe); }
                catch (IOException) when (clientWillAbort) { return; }
                Authorized = authorization.Apply;
                Require(Authorized, "Разрешение на применение не получено.");
                await OperationProtocol.WriteAsync(pipe, new DisallowedReply(false,
                    new DisallowedResult(received.Operation, received.Location, received.CertificateId, true, true, true), null));
            });
            return Process.GetCurrentProcess();
        }
    }
}
