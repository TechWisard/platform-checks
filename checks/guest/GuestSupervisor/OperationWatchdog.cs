using System.Diagnostics;

namespace SessionContractExperiment;

// A dedicated OS thread covers synchronous process creation and reader setup,
// which an async timeout registered afterwards cannot cover. This is not a
// substitute for the host's independent deadline if the whole VM stops running.
internal sealed class OperationWatchdog
{
    private readonly ManualResetEvent disarmed = new(false);
    private readonly Thread worker;
    private int state; // 0 armed, 1 disarmed, 2 deadline claimed

    internal OperationWatchdog(TimeSpan limit, Action expired)
    {
        ArgumentNullException.ThrowIfNull(expired);
        if (limit <= TimeSpan.Zero || limit > TimeSpan.FromMinutes(10))
            throw new ArgumentOutOfRangeException(nameof(limit));
        Stopwatch elapsed = Stopwatch.StartNew();
        worker = new Thread(() =>
        {
            TimeSpan remaining = limit - elapsed.Elapsed;
            bool cancelled = remaining > TimeSpan.Zero && disarmed.WaitOne(remaining);
            if (!cancelled && Interlocked.CompareExchange(ref state, 2, 0) == 0) expired();
        }) { IsBackground = true, Name = "owned-operation-deadline" };
        try { worker.Start(); }
        catch { disarmed.Dispose(); throw; }
    }

    internal bool TryDisarm()
    {
        int previous = Interlocked.CompareExchange(ref state, 1, 0);
        if (previous == 0) disarmed.Set();
        return previous is 0 or 1;
    }

    internal bool JoinAndRelease(TimeSpan limit)
    {
        // Never close a handle while the worker may still wait on it. On an
        // unverified join the production caller exits only its own process.
        if (!worker.Join(limit)) return false;
        disarmed.Dispose();
        return true;
    }
}
