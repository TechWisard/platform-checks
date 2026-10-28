using System.Text.Json;
using SessionContractExperiment;

// Pure managed contracts only. No PowerShell, licensing query, Win32 call,
// account, VM, serial device, screenshot, or product code is executed here.
int passed = 0;
void Check(bool value) { if (!value) throw new InvalidOperationException("contract_test_failed"); }
void Reject(Action action)
{
    bool rejected = false;
    try { action(); } catch (Exception) { rejected = true; }
    Check(rejected);
}

using (ManualResetEvent fired = new(false))
{
    OperationWatchdog watch = new(TimeSpan.FromMilliseconds(40), () => fired.Set());
    // Deliberately block the operation thread before registering any async
    // wait: the dedicated deadline must still claim this operation.
    Thread.Sleep(120);
    Check(fired.WaitOne(TimeSpan.FromSeconds(2)));
    Check(!watch.TryDisarm());
    Check(watch.JoinAndRelease(TimeSpan.FromSeconds(2)));
    passed++;
}
{
    int expired = 0;
    OperationWatchdog watch = new(TimeSpan.FromSeconds(2), () => Interlocked.Increment(ref expired));
    Check(watch.TryDisarm());
    Check(watch.JoinAndRelease(TimeSpan.FromSeconds(2)));
    Check(expired == 0);
    passed++;
}
using (ManualResetEvent entered = new(false))
using (ManualResetEvent release = new(false))
{
    OperationWatchdog watch = new(TimeSpan.FromMilliseconds(20), () => { entered.Set(); release.WaitOne(TimeSpan.FromSeconds(2)); });
    Check(entered.WaitOne(TimeSpan.FromSeconds(2)));
    Check(!watch.TryDisarm());
    // A failed join must leave the synchronization object alive for its worker.
    Check(!watch.JoinAndRelease(TimeSpan.FromMilliseconds(20)));
    release.Set();
    Check(watch.JoinAndRelease(TimeSpan.FromSeconds(2)));
    passed++;
}
for (int index = 0; index < 16; index++)
{
    int expired = 0;
    OperationWatchdog watch = new(TimeSpan.FromMilliseconds(2), () => Interlocked.Increment(ref expired));
    if ((index & 1) == 0) Thread.Sleep(3);
    bool disarmed = watch.TryDisarm();
    Check(watch.JoinAndRelease(TimeSpan.FromSeconds(2)));
    Check(disarmed ? expired == 0 : expired == 1);
}
passed++;

for (int status = 0; status <= 6; status++)
{
    ActivationSample value = ActivationSample.Parse($"{{\"candidate_count\":1,\"license_status\":{status},\"license_status_reason\":0}}");
    Check(value.Licensed == (status == 1));
}
passed++;
foreach (int count in new[] { 0, 2, 512 })
    Check(!ActivationSample.Parse($"{{\"candidate_count\":{count},\"license_status\":null,\"license_status_reason\":null}}").Licensed);
passed++;
foreach (string text in new[] {
    "{\"candidate_count\":true,\"license_status\":1,\"license_status_reason\":0}",
    "{\"candidate_count\":1,\"license_status\":null,\"license_status_reason\":0}",
    "{\"candidate_count\":1,\"license_status\":7,\"license_status_reason\":0}",
    "{\"candidate_count\":1,\"license_status\":1,\"license_status_reason\":4294967296}",
    "{\"candidate_count\":2,\"license_status\":1,\"license_status_reason\":0}",
    "{\"candidate_count\":1,\"license_status\":1,\"license_status\":2,\"license_status_reason\":0}",
    new string('x', 4097), "true" }) Reject(() => ActivationSample.Parse(text));
passed++;
Console.WriteLine(JsonSerializer.Serialize(new { schema = "managed-contract-tests/v1", passed, failed = 0,
    windows_executed = false, activation_queried = false, guest_executed = false }));
