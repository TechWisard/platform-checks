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
}

internal static class PayloadCleanup
{
    private const int BudgetMilliseconds = 5000;
    private const int MaximumRetries = 50;

    internal static bool TryRemove(string directory, CleanupResult evidence)
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
                if (present) RunOperation(3, index + 1, () => File.Delete(path), evidence, budget);
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

    internal static void RunOperation(int operation, int fileIndex, Action action, CleanupResult evidence, Stopwatch budget)
    {
        while (true)
        {
            evidence.attempts++;
            try { action(); return; }
            catch (Exception failure)
            {
                evidence.operation = operation; evidence.file_index = fileIndex; evidence.hresult = failure.HResult;
                // Retry only the two documented Windows sharing/lock HRESULTs.
                // Access denied, a nonempty directory, unknown I/O failures,
                // reparse points and all other exceptions remain failures.
                bool transient = failure is IOException && (failure.HResult == unchecked((int)0x80070020) || failure.HResult == unchecked((int)0x80070021));
                long remaining = BudgetMilliseconds - budget.ElapsedMilliseconds;
                if (!transient || evidence.retries >= MaximumRetries || remaining <= 0) throw;
                Thread.Sleep((int)Math.Min(100, remaining));
                if (budget.ElapsedMilliseconds >= BudgetMilliseconds) throw;
                evidence.retries++;
            }
        }
    }
}

internal static class CleanupSelfTests
{
    internal static void Run(Action<bool> check, Action<Action> reject)
    {
        int calls = 0;
        var evidence = new CleanupResult();
        PayloadCleanup.RunOperation(3, 1, () => { if (++calls == 1) throw new IOException("fixture", unchecked((int)0x80070020)); }, evidence, Stopwatch.StartNew());
        check(calls == 2 && evidence.retries == 1 && evidence.operation == 3 && evidence.file_index == 1 && evidence.hresult == unchecked((int)0x80070020));
        calls = 0; evidence = new CleanupResult();
        PayloadCleanup.RunOperation(3, 2, () => { if (++calls == 1) throw new IOException("fixture", unchecked((int)0x80070021)); }, evidence, Stopwatch.StartNew());
        check(calls == 2 && evidence.retries == 1 && evidence.hresult == unchecked((int)0x80070021));
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
