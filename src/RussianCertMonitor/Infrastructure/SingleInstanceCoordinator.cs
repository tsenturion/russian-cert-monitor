namespace RussianCertMonitor.Infrastructure;

internal sealed class SingleInstanceCoordinator : IDisposable
{
    private readonly Mutex mutex;
    private bool disposed;

    public bool IsPrimaryInstance { get; }
    public EventWaitHandle ActivationEvent { get; }

    public SingleInstanceCoordinator(string instanceId)
    {
        mutex = new Mutex(true, $@"Local\{instanceId}.Instance", out bool createdNew);
        IsPrimaryInstance = createdNew;
        try
        {
            ActivationEvent = new EventWaitHandle(
                false, EventResetMode.AutoReset, $@"Local\{instanceId}.Activate");
        }
        catch
        {
            if (IsPrimaryInstance)
                mutex.ReleaseMutex();
            mutex.Dispose();
            throw;
        }
    }

    public void RequestActivation() => ActivationEvent.Set();

    public void Dispose()
    {
        if (disposed)
            return;

        disposed = true;
        ActivationEvent.Dispose();
        if (IsPrimaryInstance)
            mutex.ReleaseMutex();
        mutex.Dispose();
    }
}
