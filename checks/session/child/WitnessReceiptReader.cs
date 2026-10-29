namespace SessionContractExperiment;

// The identity producer closes its temporary file before publishing it. A
// published immutable receipt can still be briefly locked by another handle.
// Retry only the two Windows sharing/lock errors; parsing and identity gates
// remain outside this retry. The caller supplies its existing total deadline.
internal static class WitnessReceiptReader
{
    private const string Operation = "witness_identity_read";
    private const int MaximumAttempts = 21;
    private const int TimeoutHresult = unchecked((int)0x800705B4);
    private static readonly TimeSpan RetryDelay = TimeSpan.FromMilliseconds(100);

    internal static bool IsSharingViolation(IOException error) =>
        unchecked((uint)error.HResult) is 0x80070020U or 0x80070021U;

    internal static async Task<string> ReadIdentityAsync(string path, Func<TimeSpan> remaining, Action verify)
    {
        int lastSharingHresult = 0;
        for (int attempt = 1; ; attempt++)
        {
            // Task.Delay deliberately captures the calling UI context. No COM
            // or session ownership query is moved to a worker thread.
            verify();
            if (remaining() <= TimeSpan.Zero)
                throw new ExperimentFailure(Operation, lastSharingHresult != 0 ? lastSharingHresult : TimeoutHresult);
            string text;
            try { text = File.ReadAllText(path); }
            catch (IOException error)
            {
                TimeSpan left = remaining();
                if (!IsSharingViolation(error) || attempt >= MaximumAttempts || left <= TimeSpan.Zero)
                    throw new ExperimentFailure(Operation, error.HResult);
                lastSharingHresult = error.HResult;
                await Task.Delay(left < RetryDelay ? left : RetryDelay);
                continue;
            }
            catch (UnauthorizedAccessException error)
            {
                throw new ExperimentFailure(Operation, error.HResult);
            }
            verify();
            if (remaining() <= TimeSpan.Zero) throw new ExperimentFailure(Operation, TimeoutHresult);
            return text;
        }
    }
}
