using System.Diagnostics;

namespace RuntimeProbe;

internal sealed class CleanupResult
{
    // Last failed operation: 0 none, 1 inspect directory, 2 inspect file,
    // 3 delete file, 4 delete empty directory, 5 verify absence.
    // File index: 0 directory, 1 console, 2 window. No paths or text are logged.
    public int operation { get; set; }
    public int file_index { get; set; }
    public int hresult { get; set; }
    public int attempts { get; set; }
    public int retries { get; set; }
    public int image_hresult { get; set; }
    public int image_retries { get; set; }
}

internal static class PayloadCleanup
{
    private const int BudgetMilliseconds = 5000;
    private const int MaximumRetries = 50;

    internal static bool CasesReleased(IReadOnlyList<CaseResult> cases) => cases.Count == 4
        && cases.Select((item, index) => item.index == index + 1 && item.passed && item.process_started && item.exit_observed
            && item.job_empty && item.cleanup_verified && !item.forced_termination && item.error == 0).All(value => value);

    internal static bool TryRemove(string directory, CleanupResult evidence, bool casesReleased = false, IReadOnlyList<OwnedImageIdentity?>? identities = null)
    {
        var budget = Stopwatch.StartNew();
        try
        {
            RunOperation(1, 0, () => Wire.Need((File.GetAttributes(directory) & FileAttributes.ReparsePoint) == 0, 320), evidence, budget);
            string[] names = ["console.exe", "window.exe"];
            for (int index = 0; index < names.Length; index++)
            {
                string path = Path.Combine(directory, names[index]);
                bool present = true;
                RunOperation(2, index + 1, () =>
                {
                    try { Wire.Need((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0, 320); }
                    catch (FileNotFoundException) { present = false; }
                }, evidence, budget);
                if (present)
                {
                    OwnedImageIdentity? expected = identities is { Count: 2 } ? identities[index] : null;
                    bool recheckIdentity = false;
                    bool Guard()
                    {
                        bool valid = casesReleased && expected.HasValue && ImageIdentity.Matches(path, expected.Value);
                        if (valid) recheckIdentity = true;
                        return valid;
                    }
                    RunOperation(3, index + 1, () =>
                    {
                        if (recheckIdentity && !Guard()) throw new UnauthorizedAccessException("image_identity");
                        File.Delete(path);
                    }, evidence, budget, Guard);
                }
            }
            RunOperation(4, 0, () => Directory.Delete(directory, false), evidence, budget);
            RunOperation(5, 0, () =>
            {
                RequireMissing(directory);
                RequireMissing(Path.Combine(directory, names[0]));
                RequireMissing(Path.Combine(directory, names[1]));
            }, evidence, budget);
            return true;
        }
        catch { return false; }
    }

    private static void RequireMissing(string path)
    {
        try { _ = File.GetAttributes(path); }
        catch (FileNotFoundException) { return; }
        catch (DirectoryNotFoundException) { return; }
        // Query/access errors propagate; File.Exists/Directory.Exists would
        // incorrectly turn those errors into apparently successful absence.
        throw new ProbeFailure(322);
    }

    internal static void RunOperation(int operation, int fileIndex, Action action, CleanupResult evidence, Stopwatch budget, Func<bool>? imageGuard = null)
    {
        while (true)
        {
            evidence.attempts++;
            try { action(); return; }
            catch (Exception failure)
            {
                evidence.operation = operation; evidence.file_index = fileIndex; evidence.hresult = failure.HResult;
                bool imageDenial = operation == 3 && fileIndex is 1 or 2 && failure.HResult == unchecked((int)0x80070005)
                    && (failure is IOException || failure is UnauthorizedAccessException);
                if (imageDenial) evidence.image_hresult = failure.HResult;
                // A code 5 retry is limited to a known image whose identity and
                // regular/non-readonly attributes were rechecked after all cases
                // released their processes/jobs. No permissions are changed.
                bool transient = failure is IOException && (failure.HResult == unchecked((int)0x80070020) || failure.HResult == unchecked((int)0x80070021));
                if (imageDenial && imageGuard?.Invoke() == true) transient = true;
                long remaining = BudgetMilliseconds - budget.ElapsedMilliseconds;
                if (!transient || evidence.retries >= MaximumRetries || remaining <= 0) throw;
                Thread.Sleep((int)Math.Min(100, remaining));
                if (budget.ElapsedMilliseconds >= BudgetMilliseconds) throw;
                evidence.retries++;
                if (imageDenial) evidence.image_retries++;
            }
        }
    }
}

internal static class CleanupSelfTests
{
    internal static void Run(Action<bool> check, Action<Action> reject)
    {
        check(System.Runtime.InteropServices.Marshal.SizeOf<ImageIdentity.FileIdRecord>() == 24);
        check(System.Runtime.InteropServices.Marshal.SizeOf<ImageIdentity.AttributeRecord>() == 8);
        check(ImageIdentity.Regular(0x80, 0));
        check(!ImageIdentity.Regular((uint)FileAttributes.ReadOnly, 0));
        check(!ImageIdentity.Regular((uint)FileAttributes.Directory, 0));
        check(!ImageIdentity.Regular((uint)FileAttributes.ReparsePoint, 0));
        check(!ImageIdentity.Regular(0x80, 1));
        var released = Enumerable.Range(1, 4).Select(index => new CaseResult { index = index, passed = true, process_started = true, exit_observed = true, job_empty = true, cleanup_verified = true }).ToArray();
        check(PayloadCleanup.CasesReleased(released));
        released[3].cleanup_verified = false; check(!PayloadCleanup.CasesReleased(released)); released[3].cleanup_verified = true;
        released[2].forced_termination = true; check(!PayloadCleanup.CasesReleased(released)); released[2].forced_termination = false;
        check(!PayloadCleanup.CasesReleased(released.Take(3).ToArray()));
        int calls = 0;
        var evidence = new CleanupResult();
        PayloadCleanup.RunOperation(3, 1, () => { if (++calls == 1) throw new IOException("fixture", unchecked((int)0x80070020)); }, evidence, Stopwatch.StartNew());
        check(calls == 2 && evidence.retries == 1 && evidence.operation == 3 && evidence.file_index == 1 && evidence.hresult == unchecked((int)0x80070020));
        calls = 0; evidence = new CleanupResult();
        PayloadCleanup.RunOperation(3, 2, () => { if (++calls == 1) throw new IOException("fixture", unchecked((int)0x80070021)); }, evidence, Stopwatch.StartNew());
        check(calls == 2 && evidence.retries == 1 && evidence.hresult == unchecked((int)0x80070021));
        calls = 0; evidence = new CleanupResult();
        PayloadCleanup.RunOperation(3, 2, () => { if (++calls == 1) throw new UnauthorizedAccessException("fixture"); }, evidence, Stopwatch.StartNew(), () => true);
        check(calls == 2 && evidence.image_retries == 1 && evidence.image_hresult == unchecked((int)0x80070005));
        calls = 0; evidence = new CleanupResult();
        reject(() => PayloadCleanup.RunOperation(3, 2, () => { calls++; throw new UnauthorizedAccessException("fixture"); }, evidence, Stopwatch.StartNew(), () => false));
        check(calls == 1 && evidence.image_retries == 0 && evidence.retries == 0);
        calls = 0; evidence = new CleanupResult();
        reject(() => PayloadCleanup.RunOperation(3, 2, () => { calls++; throw new UnauthorizedAccessException("fixture"); }, evidence, Stopwatch.StartNew(), () => calls == 1));
        check(calls == 2 && evidence.image_retries == 1 && evidence.retries == 1);
        calls = 0; evidence = new CleanupResult();
        reject(() => PayloadCleanup.RunOperation(4, 0, () => { calls++; throw new UnauthorizedAccessException("fixture"); }, evidence, Stopwatch.StartNew(), () => true));
        check(calls == 1 && evidence.image_retries == 0);
        calls = 0; evidence = new CleanupResult();
        PayloadCleanup.RunOperation(3, 2, () =>
        {
            calls++;
            if (calls == 1) throw new UnauthorizedAccessException("fixture");
            if (calls == 2) throw new IOException("fixture", unchecked((int)0x80070020));
        }, evidence, Stopwatch.StartNew(), () => true);
        check(calls == 3 && evidence.image_retries == 1 && evidence.image_hresult == unchecked((int)0x80070005) && evidence.hresult == unchecked((int)0x80070020));
        foreach (int hresult in new[] { unchecked((int)0x80070005), unchecked((int)0x80070091), unchecked((int)0x80131620) })
        {
            calls = 0; evidence = new CleanupResult();
            reject(() => PayloadCleanup.RunOperation(4, 0, () => { calls++; throw new IOException("fixture", hresult); }, evidence, Stopwatch.StartNew()));
            check(calls == 1 && evidence.retries == 0 && evidence.hresult == hresult);
        }
        calls = 0; evidence = new CleanupResult();
        var deadline = Stopwatch.StartNew();
        reject(() => PayloadCleanup.RunOperation(3, 1, () => { calls++; throw new IOException("fixture", unchecked((int)0x80070020)); }, evidence, deadline));
        check(calls == evidence.retries + 1 && evidence.retries is > 0 and <= 50 && deadline.ElapsedMilliseconds >= 4900);

        string directory = Path.Combine(Path.GetTempPath(), "runtime-cleanup-test-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        string console = Path.Combine(directory, "console.exe"), window = Path.Combine(directory, "window.exe"), extra = Path.Combine(directory, "extra");
        FileStream? held = null;
        try
        {
            File.WriteAllText(console, "synthetic"); File.WriteAllText(window, "synthetic");
            evidence = new CleanupResult();
            check(PayloadCleanup.TryRemove(directory, evidence) && !Directory.Exists(directory) && evidence.hresult == 0 && evidence.retries == 0);
            Directory.CreateDirectory(directory);
            File.WriteAllText(console, "synthetic"); File.WriteAllText(window, "synthetic"); File.WriteAllText(extra, "synthetic");
            evidence = new CleanupResult();
            check(!PayloadCleanup.TryRemove(directory, evidence) && File.Exists(extra) && evidence.operation == 4 && evidence.file_index == 0 && evidence.hresult != 0);
            File.Delete(extra); Directory.Delete(directory, false);
            if (OperatingSystem.IsWindows())
            {
                Directory.CreateDirectory(directory);
                File.WriteAllText(console, "synthetic"); File.WriteAllText(window, "synthetic");
                held = new FileStream(console, FileMode.Open, FileAccess.Read, FileShare.Read);
                evidence = new CleanupResult();
                using var observed = new ManualResetEventSlim();
                Task remove = Task.Run(() => PayloadCleanup.RunOperation(3, 1, () =>
                {
                    try { File.Delete(console); }
                    catch (IOException failure) when (failure.HResult == unchecked((int)0x80070020)) { observed.Set(); throw; }
                }, evidence, Stopwatch.StartNew()));
                bool sawSharing = observed.Wait(3000);
                held.Dispose(); held = null;
                remove.GetAwaiter().GetResult();
                check(sawSharing && evidence.retries > 0 && evidence.file_index == 1 && evidence.hresult == unchecked((int)0x80070020));
                check(PayloadCleanup.TryRemove(directory, new CleanupResult()) && !Directory.Exists(directory));
                Directory.CreateDirectory(directory);
                OwnedImageIdentity original;
                using (var created = new FileStream(window, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.None))
                { created.WriteByte(1); original = ImageIdentity.Capture(created.SafeFileHandle); }
                check(ImageIdentity.Matches(window, original));
                File.Move(window, console);
                check(!ImageIdentity.Matches(window, original));
                File.WriteAllText(window, "replacement");
                check(!ImageIdentity.Matches(window, original) && ImageIdentity.Matches(console, original));
                check(!ImageIdentity.Matches(directory, original));
                check(PayloadCleanup.TryRemove(directory, new CleanupResult()));
            }
        }
        finally
        {
            held?.Dispose();
            foreach (string path in new[] { console, window, extra }) if (File.Exists(path)) File.Delete(path);
            if (Directory.Exists(directory)) Directory.Delete(directory, false);
        }
    }
}
