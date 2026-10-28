using System.Text.Json;
using System.Security.Cryptography;
using System.Text;
using SessionContractExperiment;

// Pure managed contracts only. No PowerShell, licensing query, Win32 call,
// account, VM, serial device, screenshot, or product code is executed here.
if (args.Length == 2 && args[0] == "--export-scripts")
{
    Directory.CreateDirectory(args[1]);
    File.WriteAllText(Path.Combine(args[1], "query.ps1"), ActivationScripts.Query);
    string syntheticDigest = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes("00000000-0000-0000-0000-000000000001")));
    File.WriteAllText(Path.Combine(args[1], "activate.ps1"), ActivationScripts.Activate(syntheticDigest));
    Console.WriteLine("exported_exact_compiled_scripts=2");
    return;
}
if (args.Length != 0) throw new ArgumentException("unexpected_test_arguments");
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
string Snapshot(int status = 5, int count = 1, string? end = "null", string? trusted = "null", string? digest = null) =>
    JsonSerializer.Serialize(new Dictionary<string, object?>
    {
        ["candidate_count"] = count, ["license_status"] = count == 1 ? status : null,
        ["license_status_reason"] = count == 1 ? 3221549065U : null,
        ["grace_period_remaining"] = count == 1 ? 0U : null,
        ["evaluation_end_utc"] = count == 1 && end != "null" ? long.Parse(end!) : null,
        ["trusted_time_utc"] = count == 1 && trusted != "null" ? long.Parse(trusted!) : null,
        ["guest_utc"] = 1793232000L, ["identity_digest"] = count == 1 ? digest ?? new string('A', 64) : null
    });
// Notification plus 0xC004F009 is not proof of an expired evaluation.
LicensingSnapshot notification = LicensingSnapshot.Parse(Snapshot());
Check(!notification.Licensed && notification.Evidence.EvaluationExpired is null && notification.Evidence.LicenseStatusReason == 3221549065L);
Check(LicensingSnapshot.Parse(Snapshot(1)).Licensed);
Check(!LicensingSnapshot.Parse(Snapshot(1, 0)).Licensed);
Check(!LicensingSnapshot.Parse(Snapshot(1, 2)).Licensed);
passed++;
// Known expiration is distinct from missing date, future date, and trusted time.
Check(LicensingSnapshot.Parse(Snapshot(1, end: "1793231999")).Evidence.EvaluationExpired == true);
Check(!LicensingSnapshot.Parse(Snapshot(1, end: "1793231999")).Licensed);
Check(LicensingSnapshot.Parse(Snapshot(1, end: "1793232100")).Evidence.EvaluationExpired == false);
Check(LicensingSnapshot.Parse(Snapshot(1, end: "1793232100", trusted: "1793232101")).Evidence.EvaluationExpired == true);
passed++;
Check(notification.SameProduct(LicensingSnapshot.Parse(Snapshot(1))));
Check(!notification.SameProduct(LicensingSnapshot.Parse(Snapshot(1, digest: new string('B', 64)))));
Check(!notification.SameProduct(LicensingSnapshot.Parse(Snapshot(1, 0))));
// Only the fixed evidence projection is public; digest is absent.
string projected = JsonSerializer.Serialize(notification.Evidence);
Check(!projected.Contains(new string('A', 64), StringComparison.Ordinal) && !projected.Contains("Identity", StringComparison.Ordinal));
passed++;
foreach (string text in new[] {
    Snapshot().Replace("\"candidate_count\":1", "\"candidate_count\":true", StringComparison.Ordinal),
    Snapshot().Replace("\"guest_utc\":1793232000", "\"guest_utc\":null", StringComparison.Ordinal),
    Snapshot().Replace("\"guest_utc\":1793232000", "\"guest_utc\":0", StringComparison.Ordinal),
    Snapshot().Replace("\"trusted_time_utc\":null", "\"trusted_time_utc\":true", StringComparison.Ordinal),
    Snapshot().Replace("\"evaluation_end_utc\":null", "\"evaluation_end_utc\":-1", StringComparison.Ordinal),
    Snapshot().Replace("\"license_status\":5", "\"license_status\":1,\"license_status\":5", StringComparison.Ordinal),
    Snapshot(digest: "not-a-digest"), Snapshot(7), Snapshot().Replace("3221549065", "4294967296", StringComparison.Ordinal),
    Snapshot().Replace("\"grace_period_remaining\":0", "\"grace_period_remaining\":false", StringComparison.Ordinal),
    new string('x', 8193), "[]" }) Reject(() => LicensingSnapshot.Parse(text));
passed++;
string Reply(bool started, bool returned, uint? rv, int? error, int guard, bool same, int? shape = null, int? resultError = null) =>
    JsonSerializer.Serialize(new { invocation_started = started, invocation_returned = returned, return_value = rv,
        error_hresult = error, guard_code = guard, same_product_verified = same,
        result_shape = shape ?? (returned ? (rv.HasValue ? 3 : 2) : 0), result_error_hresult = resultError });
Check(ActivationMethodReply.Parse(Reply(true, true, 0, null, 0, true)).ReturnValue == 0);
Check(ActivationMethodReply.Parse(Reply(true, false, null, -1, 0, true)).InvocationReturned == false);
Check(!ActivationMethodReply.Parse(Reply(false, false, null, null, 1, true)).InvocationStarted);
Check(!ActivationMethodReply.Parse(Reply(false, false, null, null, 2, true)).InvocationStarted);
Check(!ActivationMethodReply.Parse(Reply(false, false, null, null, 3, false)).InvocationStarted);
Check(!ActivationMethodReply.Parse(Reply(false, false, null, -1, 4, false)).InvocationStarted);
passed++;
// A normal invocation with unavailable output is explicit, not a fabricated
// zero and not an invocation error. The public host still needs fresh status.
foreach (int shape in new[] { 1, 2, 4, 5, 6 })
{
    int? resultError = shape == 6 ? unchecked((int)0x80131501) : null;
    ActivationMethodReply reply = ActivationMethodReply.Parse(Reply(true, true, null, null, 0, true, shape, resultError));
    Check(reply.InvocationStarted && reply.InvocationReturned && reply.ReturnValue is null && reply.ErrorHresult is null &&
        reply.ResultShape == shape && reply.ResultErrorHresult == resultError && reply.SameProductVerified);
    Check(!notification.Licensed && LicensingSnapshot.Parse(Snapshot(1)).Licensed);
}
passed++;
foreach (string text in new[] {
    Reply(true, true, 0, null, 0, false), Reply(true, false, 0, -1, 0, true),
    Reply(false, true, 0, null, 1, true), Reply(true, false, null, null, 0, true),
    Reply(false, false, null, null, 0, true), Reply(false, false, null, null, 4, false),
    Reply(false, false, null, null, 2, false), Reply(false, false, null, null, 3, true),
    Reply(true, true, 0, -1, 0, true), Reply(true, true, null, null, 0, true, 0),
    Reply(true, true, null, null, 0, true, 3), Reply(true, true, 0, null, 0, true, 2),
    Reply(true, true, null, null, 0, true, 6), Reply(true, true, null, null, 0, true, 2, -1),
    Reply(true, false, null, -1, 0, true, 6, -1), Reply(false, false, null, null, 1, true, 2),
    Reply(true, true, null, null, 0, true, 7),
    Reply(true, true, 0, null, 0, true).Replace("\"guard_code\":0", "\"guard_code\":true", StringComparison.Ordinal),
    Reply(true, true, 0, null, 0, true).Replace("\"result_shape\":3", "\"result_shape\":true", StringComparison.Ordinal),
    Reply(true, true, 0, null, 0, true).Replace("\"result_error_hresult\":null", "\"result_error_hresult\":4294967296", StringComparison.Ordinal),
    Reply(true, true, 0, null, 0, true).Replace("\"result_shape\":3", "\"result_shape\":3,\"result_shape\":2", StringComparison.Ordinal) })
    Reject(() => ActivationMethodReply.Parse(text));
passed++;
Reject(() => ActivationScripts.Activate("';unexpected-command"));
Check(ActivationScripts.Activate(new string('A', 64)).Split("Invoke-CimMethod", StringSplitOptions.None).Length == 2);
// A method reply carries no Licensed property; only an independently parsed
// same-product snapshot can satisfy the supervisor's final gate.
Check(!notification.Licensed);
passed++;
Console.WriteLine(JsonSerializer.Serialize(new { schema = "managed-contract-tests/v1", passed, failed = 0,
    windows_executed = false, activation_queried = false, guest_executed = false }));
