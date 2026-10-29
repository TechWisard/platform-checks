using System.Collections.Concurrent;
using System.Diagnostics;
using System.Reflection;
using System.Text.Json;

// Load the actual built fixture. The reader has no Windows Forms dependency,
// so the same test executable can run on Linux and on the native ARM runner.
Assembly fixture = Assembly.LoadFrom(Path.GetFullPath(args.Single()));
const BindingFlags Hidden = BindingFlags.Static | BindingFlags.NonPublic;
Type reader = fixture.GetType("SessionContractExperiment.WitnessReceiptReader", true)!;
MethodInfo read = reader.GetMethod("ReadIdentityAsync", Hidden)!;
MethodInfo retryable = reader.GetMethod("IsSharingViolation", Hidden)!;
int checks = 0;
void Need(bool ok, string name) { if (!ok) throw new InvalidOperationException(name); checks++; }
Task<string> Read(string path, Func<TimeSpan> remaining, Action verify) =>
    (Task<string>)read.Invoke(null, new object[] { path, remaining, verify })!;
async Task Failure(Task<string> task, int code)
{
    try { _ = await task; }
    catch (Exception error) when (error.GetType().FullName == "SessionContractExperiment.ExperimentFailure")
    {
        const BindingFlags props = BindingFlags.Instance | BindingFlags.NonPublic;
        Need((string)error.GetType().GetProperty("Stage", props)!.GetValue(error)! == "witness_identity_read", "safe operation");
        Need((int)error.GetType().GetProperty("Code", props)!.GetValue(error)! == code, "original HRESULT retained");
        return;
    }
    throw new InvalidOperationException("reader must fail closed");
}
Func<TimeSpan> LongBudget = () => TimeSpan.FromMinutes(1);
string directory = Path.Combine(Path.GetTempPath(), "receipt-reader-test-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(directory);
bool nativeLocks = false;
try
{
    foreach (uint code in new uint[] { 0x80070020, 0x80070021 })
        Need((bool)retryable.Invoke(null, new object[] { new IOException("synthetic", unchecked((int)code)) })!, "retry exact Windows lock code");
    foreach (uint code in new uint[] { 32, 33, 0x80130020, 0x80070005, 0x80070002, 0x8007001e, 0x80070070 })
        Need(!(bool)retryable.Invoke(null, new object[] { new IOException("synthetic", unchecked((int)code)) })!, "do not retry other HRESULT");

    string path = Path.Combine(directory, "receipt.json");
    const string receipt = "{\"nonce\":\"independent-test-value\",\"session_id\":1}";
    File.WriteAllText(path, receipt);
    int verifies = 0;
    Need(await Read(path, LongBudget, () => verifies++) == receipt, "complete receipt unchanged");
    Need(verifies == 2, "ownership checked before and after successful read");

    verifies = 0;
    Task<string> missing = Read(Path.Combine(directory, "absent"), LongBudget, () => verifies++);
    Need(missing.IsCompleted, "nonsharing IO failure has no delay");
    await Failure(missing, unchecked((int)0x80070002));
    Need(verifies == 1, "nonsharing IO failure is not retried");

    verifies = 0;
    Task<string> denied = Read(directory, LongBudget, () => verifies++);
    Need(denied.IsCompleted, "access denied has no delay");
    await Failure(denied, unchecked((int)0x80070005));
    Need(verifies == 1, "access denied is not retried");

    verifies = 0;
    await Failure(Read(Path.Combine(directory, "absent"), () => TimeSpan.Zero, () => verifies++), unchecked((int)0x800705B4));
    Need(verifies == 1, "expired caller budget prevents read");

    TimeSpan left = TimeSpan.FromSeconds(1);
    verifies = 0;
    await Failure(Read(path, () => left, () => { if (++verifies == 2) left = TimeSpan.Zero; }), unchecked((int)0x800705B4));
    Need(verifies == 2, "receipt completing beyond total budget is rejected");

    InvalidOperationException lostOwner = new("ownership changed");
    verifies = 0;
    bool ownerRejected = false;
    try { _ = await Read(path, LongBudget, () => { if (++verifies == 2) throw lostOwner; }); }
    catch (InvalidOperationException error) when (ReferenceEquals(error, lostOwner)) { ownerRejected = true; }
    Need(ownerRejected && verifies == 2, "post-read ownership failure is not retried");

    File.WriteAllText(path, "{malformed stable receipt");
    verifies = 0;
    string malformed = await Read(path, LongBudget, () => verifies++);
    bool rejected = false;
    try { using JsonDocument ignored = JsonDocument.Parse(malformed); }
    catch (JsonException) { rejected = true; }
    Need(rejected && verifies == 2, "malformed stable JSON is rejected outside retry");
    File.WriteAllText(path, receipt);

    // Verify the runtime's actual FileShare.None behavior before testing the
    // retry. Windows is required to support it; other runtimes may skip only
    // these native file-sharing cases, never report a simulated lock as native.
    using (FileStream held = new(path, FileMode.Open, FileAccess.Read, FileShare.None))
    {
        try { _ = File.ReadAllText(path); }
        catch (IOException error) { nativeLocks = unchecked((uint)error.HResult) == 0x80070020U; }
    }
    Need(nativeLocks || !OperatingSystem.IsWindows(), "Windows must expose actual sharing violation");
    if (nativeLocks)
    {
        // Release only on the second validation, proving that the real first
        // File.ReadAllText failed under a held lock and yielded asynchronously.
        using (FileStream held = new(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            verifies = 0;
            SynchronizationContext? previous = SynchronizationContext.Current;
            using QueuedContext context = new();
            SynchronizationContext.SetSynchronizationContext(context);
            try
            {
                int owner = Environment.CurrentManagedThreadId;
                Task<string> released = Read(path, LongBudget, () =>
                {
                    Need(Environment.CurrentManagedThreadId == owner, "ownership guard stays on UI context thread");
                    if (++verifies == 2) held.Dispose();
                });
                // The continuation cannot run until this test pumps it. This
                // assertion is independent of scheduler preemption and delay.
                Need(!released.IsCompleted, "locked read yields to caller");
                context.RunOne();
                Need(released.IsCompleted, "one retry finishes after releasing lock");
                Need(released.GetAwaiter().GetResult() == receipt, "released lock returns complete actual file");
                Need(verifies == 3, "released lock rechecks owner after yield and after read");
            }
            finally { SynchronizationContext.SetSynchronizationContext(previous); }
        }

        using (FileStream held = new(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            Stopwatch watch = Stopwatch.StartNew();
            verifies = 0;
            await Failure(Read(path, () => TimeSpan.FromMilliseconds(180) - watch.Elapsed, () => verifies++), unchecked((int)0x80070020));
            Need(verifies >= 2 && verifies <= 22, "persistent lock remains bounded by attempts");
            Need(watch.Elapsed >= TimeSpan.FromMilliseconds(100) && watch.Elapsed < TimeSpan.FromSeconds(4), "persistent lock respects caller budget");
        }

        using (FileStream held = new(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            verifies = 0;
            await Failure(Read(path, LongBudget, () => verifies++), unchecked((int)0x80070020));
            Need(verifies == 21, "fixed retry cap prevents indefinite waiting");
        }

        using (FileStream held = new(path, FileMode.Open, FileAccess.Read, FileShare.None))
        {
            verifies = 0;
            bool failed = false;
            try { _ = await Read(path, LongBudget, () => { if (++verifies == 2) throw lostOwner; }); }
            catch (InvalidOperationException error) when (ReferenceEquals(error, lostOwner)) { failed = true; }
            Need(failed && verifies == 2, "ownership failure after retry yield stops immediately");
        }
    }
    Console.WriteLine(JsonSerializer.Serialize(new { schema = "witness-receipt-reader-tests/v1", status = "passed", checks,
        native_file_sharing = nativeLocks, runtime_windows = OperatingSystem.IsWindows() }));
}
catch (Exception error)
{
    // Neither exception messages nor fixture paths contain useful public test
    // evidence. Report only the exception category and numeric HRESULT.
    Console.WriteLine(JsonSerializer.Serialize(new { schema = "witness-receipt-reader-tests/v1", status = "failed", checks,
        native_file_sharing = nativeLocks, runtime_windows = OperatingSystem.IsWindows(),
        error_type = error.GetType().Name, error_hresult = error.HResult }));
    Environment.ExitCode = 1;
}
finally { Directory.Delete(directory, recursive: true); }

sealed class QueuedContext : SynchronizationContext, IDisposable
{
    private readonly BlockingCollection<(SendOrPostCallback Callback, object? State)> pending = new();
    public override void Post(SendOrPostCallback callback, object? state) => pending.Add((callback, state));
    internal void RunOne()
    {
        if (!pending.TryTake(out var work, TimeSpan.FromSeconds(5)))
            throw new InvalidOperationException("reader continuation was not posted to its calling context");
        work.Callback(work.State);
    }
    public void Dispose() => pending.Dispose();
}
