using System.Buffers.Binary;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using RussianCertMonitor.Certificates;

namespace RussianCertMonitor.Disallowed;

internal sealed record DisallowedJob(int SchemaVersion, DisallowedOperation Operation,
    StoreLocation Location, string CertificateId, byte[] CertificateData);
internal sealed record DisallowedHandshake(bool Confirmed, string? Error);
internal sealed record DisallowedAuthorization(bool Apply);
internal sealed record DisallowedReply(bool Cancelled, DisallowedResult? Result, string? Error,
    TrustCopyChange? TrustCopies = null);

internal static class OperationProtocol
{
    private const int MaxFrameBytes = 2 * 1024 * 1024;
    public const string HelperArgument = "--disallowed-helper";
    public static string PipeName(string token) => "RussianCertMonitor.Operation." + token;

    public static bool TryParseArguments(string[] args, out string token, out int parentId)
    {
        token = "";
        parentId = 0;
        if (args.Length != 3 || args[0] != HelperArgument
            || !Guid.TryParseExact(args[1], "N", out _) || !int.TryParse(args[2], out parentId) || parentId <= 0)
            return false;
        token = args[1];
        return true;
    }

    public static PublicCertificateData ValidateMachineJob(DisallowedJob job)
    {
        if (job.SchemaVersion != 1 || job.Location != StoreLocation.LocalMachine
            || job.Operation is not (DisallowedOperation.Add or DisallowedOperation.Remove)
            || job.CertificateData is null)
            throw new InvalidDataException("Недопустимая операция с чёрным списком компьютера.");
        PublicCertificateData certificate = PublicCertificateData.FromDer(job.CertificateData);
        if (!string.Equals(certificate.Metadata.CertificateId, job.CertificateId, StringComparison.OrdinalIgnoreCase))
            throw new CryptographicException("Полученные данные не соответствуют выбранному сертификату.");
        return certificate;
    }

    public static async Task WriteAsync<T>(Stream stream, T value, CancellationToken token = default)
    {
        byte[] bytes = JsonSerializer.SerializeToUtf8Bytes(value);
        if (bytes.Length == 0 || bytes.Length > MaxFrameBytes)
            throw new InvalidDataException("Недопустимый размер сообщения операции.");
        byte[] header = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(header, bytes.Length);
        await stream.WriteAsync(header, token).ConfigureAwait(false);
        await stream.WriteAsync(bytes, token).ConfigureAwait(false);
        await stream.FlushAsync(token).ConfigureAwait(false);
    }

    public static async Task<T> ReadAsync<T>(Stream stream, CancellationToken token = default)
    {
        byte[] header = new byte[4];
        await stream.ReadExactlyAsync(header, token).ConfigureAwait(false);
        int length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length <= 0 || length > MaxFrameBytes)
            throw new InvalidDataException("Недопустимый размер сообщения операции.");
        byte[] bytes = new byte[length];
        await stream.ReadExactlyAsync(bytes, token).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(bytes)
            ?? throw new InvalidDataException("Пустое сообщение операции.");
    }

    public static bool HasExpectedPeer(PipeStream pipe, int expectedId, bool server)
    {
        bool success = server
            ? GetNamedPipeClientProcessId(pipe.SafePipeHandle, out uint peer)
            : GetNamedPipeServerProcessId(pipe.SafePipeHandle, out peer);
        return success && expectedId > 0 && peer == (uint)expectedId;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeClientProcessId(SafePipeHandle pipe, out uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetNamedPipeServerProcessId(SafePipeHandle pipe, out uint processId);
}
