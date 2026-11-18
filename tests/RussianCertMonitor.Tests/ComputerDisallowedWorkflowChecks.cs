using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using RussianCertMonitor.Certificates;
using RussianCertMonitor.Disallowed;

namespace RussianCertMonitor.Tests;

internal static class ComputerDisallowedWorkflowChecks
{
    private static readonly WindowsTrustAssessment Explicit = new(new(0x04000000), new(0x04000000));
    private static readonly WindowsTrustAssessment UserOnly = new(new(0x04000000), new(0x00000020));
    private static readonly WindowsTrustAssessment Neither = new(new(0x00000020), new(0x00000020));

    public static void Run()
    {
        using X509Certificate2 certificate = CreateCertificate();
        using X509Certificate2 otherCertificate = CreateCertificate();
        PublicCertificateData data = PublicCertificateData.FromDer(certificate.Export(X509ContentType.Cert));
        PublicCertificateData other = PublicCertificateData.FromDer(otherCertificate.Export(X509ContentType.Cert));
        CheckAddAndRepeatedImport(data);
        CheckRemove(data, other);
        CheckRejectedMachineReplies(data);
        CheckCleanupFailure(data);
    }

    private static void CheckAddAndRepeatedImport(PublicCertificateData data)
    {
        FakeBackend backend = new();
        backend.Add(StoreLocation.CurrentUser, data.Metadata.RawData);
        WindowsTrustAssessment trust = UserOnly;
        List<DisallowedJob> jobs = [];
        ComputerDisallowedWorkflow workflow = CreateWorkflow(backend, jobs, () => trust);

        ComputerDisallowedChange? partial = workflow.ChangeAsync(DisallowedOperation.Add, data,
            CancellationToken.None).GetAwaiter().GetResult();
        Require(partial is not null && !partial.IsConfirmed && partial.Computer.OwnPresentAfter
            && partial.UserCleanup is null && backend.Contains(StoreLocation.CurrentUser, data.Metadata.CertificateId),
            "Пользовательская запись должна сохраниться, пока Windows не подтвердит обе области.");
        Require(backend.Contains(StoreLocation.LocalMachine, data.Metadata.CertificateId),
            "Запись компьютера должна быть добавлена.");
        CheckJob(jobs.Single(), DisallowedOperation.Add, data);

        trust = Explicit;
        ComputerDisallowedChange? completed = workflow.ChangeAsync(DisallowedOperation.Add, data,
            CancellationToken.None).GetAwaiter().GetResult();
        Require(completed is not null && completed.IsConfirmed && completed.UserCleanup is not null
            && !completed.UserCleanup.OwnPresentAfter && !backend.Contains(StoreLocation.CurrentUser, data.Metadata.CertificateId),
            "После подтверждения Windows устаревшая пользовательская запись должна удаляться.");

        // Повторный импорт тем же внешним установщиком не должен оставлять лишний запрет пользователя.
        backend.Add(StoreLocation.CurrentUser, data.Metadata.RawData);
        ComputerDisallowedChange? repeated = workflow.ChangeAsync(DisallowedOperation.Add, data,
            CancellationToken.None).GetAwaiter().GetResult();
        Require(repeated is not null && repeated.IsConfirmed && repeated.UserCleanup is not null
            && !backend.Contains(StoreLocation.CurrentUser, data.Metadata.CertificateId),
            "Повторный импорт пользовательской записи должен очищаться для того же сертификата.");
        Require(jobs.Count == 3 && jobs.All(job => job.Operation == DisallowedOperation.Add),
            "Каждое добавление должно выполняться в области компьютера.");
    }

    private static void CheckRemove(PublicCertificateData data, PublicCertificateData other)
    {
        FakeBackend backend = new();
        foreach (StoreLocation scope in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
        {
            backend.Add(scope, data.Metadata.RawData);
            backend.Add(scope, other.Metadata.RawData);
        }
        List<DisallowedJob> jobs = [];
        ComputerDisallowedWorkflow workflow = CreateWorkflow(backend, jobs, () => Neither);
        ComputerDisallowedChange? removed = workflow.ChangeAsync(DisallowedOperation.Remove, data,
            CancellationToken.None).GetAwaiter().GetResult();
        Require(removed is not null && removed.IsConfirmed && removed.UserCleanup is not null
            && !removed.Computer.OwnPresentAfter && !removed.UserCleanup.OwnPresentAfter,
            "Удаление должно подтвердить обе собственные записи и отсутствие явного запрета Windows.");
        CheckJob(jobs.Single(), DisallowedOperation.Remove, data);
        foreach (StoreLocation scope in new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine })
            Require(!backend.Contains(scope, data.Metadata.CertificateId)
                && backend.Contains(scope, other.Metadata.CertificateId),
                "Удаляться должен только точный ID выбранного сертификата.");

        backend.InheritedUser = true;
        workflow = CreateWorkflow(backend, jobs, () => backend.InheritedUser ? UserOnly : Neither);
        ComputerDisallowedChange? inherited = workflow.ChangeAsync(DisallowedOperation.Remove, data,
            CancellationToken.None).GetAwaiter().GetResult();
        Require(inherited is not null && !inherited.IsConfirmed && inherited.UserCleanup is null
            && !backend.Contains(StoreLocation.CurrentUser, data.Metadata.CertificateId),
            "Унаследованная запись должна оставаться видимой, но не удаляться как собственная.");
        Require(backend.RemovedIds.All(item => item.Id == data.Metadata.CertificateId),
            "Унаследованная запись и другие сертификаты не должны удаляться.");
    }

    private static void CheckRejectedMachineReplies(PublicCertificateData data)
    {
        foreach (Func<DisallowedJob, DisallowedReply> reply in new Func<DisallowedJob, DisallowedReply>[]
        {
            _ => new(true, null, null),
            _ => new(false, null, "Ошибка помощника"),
            job => new(false, new DisallowedResult(job.Operation, StoreLocation.CurrentUser,
                job.CertificateId, true, false, false), null),
            job => new(false, new DisallowedResult(job.Operation, StoreLocation.LocalMachine,
                "НЕВЕРНЫЙ-ID", true, false, false), null)
        })
        {
            FakeBackend backend = new();
            backend.Add(StoreLocation.CurrentUser, data.Metadata.RawData);
            DisallowedManager manager = new(backend);
            ComputerDisallowedWorkflow workflow = new(manager,
                (job, _) => Task.FromResult(reply(job)), verify: _ => Neither);
            ComputerDisallowedChange? result = null;
            try
            {
                result = workflow.ChangeAsync(DisallowedOperation.Remove, data,
                    CancellationToken.None).GetAwaiter().GetResult();
            }
            catch (Exception error) when (error is InvalidOperationException or CryptographicException
                or InvalidDataException or IOException or UnauthorizedAccessException) { }
            Require(result is null || !result.IsConfirmed,
                "Отменённый или ошибочный ответ не должен подтверждать удаление.");
            Require(backend.Contains(StoreLocation.CurrentUser, data.Metadata.CertificateId)
                && backend.RemovedIds.Count == 0,
                "Ошибка помощника не должна менять пользовательский Disallowed.");
        }
    }

    private static void CheckCleanupFailure(PublicCertificateData data)
    {
        FakeBackend backend = new();
        backend.Add(StoreLocation.CurrentUser, data.Metadata.RawData);
        backend.ThrowOnUserRemove = true;
        ComputerDisallowedWorkflow workflow = CreateWorkflow(backend, [], () => Neither);
        ComputerDisallowedChange? change = workflow.ChangeAsync(DisallowedOperation.Remove, data,
            CancellationToken.None).GetAwaiter().GetResult();
        Require(change is not null && !change.IsConfirmed && change.Computer.OwnPresentAfter == false
            && change.UserCleanup is null && !string.IsNullOrWhiteSpace(change.UserCleanupError)
            && backend.Contains(StoreLocation.CurrentUser, data.Metadata.CertificateId),
            "Сбой очистки пользователя должен возвращать частичный результат без подтверждения удаления.");

        ComputerDisallowedWorkflow addWorkflow = CreateWorkflow(backend, [], () => Explicit);
        ComputerDisallowedChange? added = addWorkflow.ChangeAsync(DisallowedOperation.Add, data,
            CancellationToken.None).GetAwaiter().GetResult();
        Require(added is not null && !added.IsConfirmed && added.UserCleanup is null
            && !string.IsNullOrWhiteSpace(added.UserCleanupError)
            && backend.Contains(StoreLocation.CurrentUser, data.Metadata.CertificateId),
            "Сбой очистки после добавления должен оставаться частичным результатом.");
    }

    private static ComputerDisallowedWorkflow CreateWorkflow(FakeBackend backend, List<DisallowedJob> jobs,
        Func<WindowsTrustAssessment> trust)
    {
        DisallowedManager manager = new(backend);
        return new(manager, (job, _) =>
        {
            jobs.Add(job);
            DisallowedResult result = manager.Execute(manager.Preview(job.Operation, job.Location,
                PublicCertificateData.FromDer(job.CertificateData)));
            return Task.FromResult(new DisallowedReply(false, result, null));
        }, verify: _ => trust());
    }

    private static void CheckJob(DisallowedJob job, DisallowedOperation operation, PublicCertificateData data)
    {
        Require(job.SchemaVersion == 1 && job.Operation == operation
            && job.Location == StoreLocation.LocalMachine
            && job.CertificateId == data.Metadata.CertificateId
            && job.CertificateData.SequenceEqual(data.Metadata.RawData),
            "Задание помощнику должно содержать исходный DER и точный ID для области компьютера.");
    }

    private static X509Certificate2 CreateCertificate()
    {
        using RSA key = RSA.Create(2048);
        CertificateRequest request = new($"CN=Workflow-{Guid.NewGuid():N}, C=US", key,
            HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(1));
    }

    private static void Require(bool condition, string message)
    {
        if (!condition) throw new InvalidOperationException(message);
    }

    private sealed class FakeBackend : IDisallowedStoreBackend
    {
        private readonly Dictionary<(StoreLocation Location, string Id), byte[]> entries = [];
        public bool InheritedUser { get; set; }
        public bool ThrowOnUserRemove { get; set; }
        public List<(StoreLocation Location, string Id)> RemovedIds { get; } = [];

        public bool Contains(StoreLocation location, string id) => entries.ContainsKey((location, id));
        public byte[]? Find(StoreLocation location, string id) => entries.GetValueOrDefault((location, id));
        public void Add(StoreLocation location, byte[] der)
        {
            entries[(location, PublicCertificateData.FromDer(der).Metadata.CertificateId)] = der;
        }
        public void Remove(StoreLocation location, string id)
        {
            if (location == StoreLocation.CurrentUser && ThrowOnUserRemove)
                throw new UnauthorizedAccessException("Очистка пользователя запрещена.");
            RemovedIds.Add((location, id));
            entries.Remove((location, id));
        }
        public bool ContainsLogical(StoreLocation location, string id) =>
            Contains(location, id) || (location == StoreLocation.CurrentUser && InheritedUser);
    }
}
