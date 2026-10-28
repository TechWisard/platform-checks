using System.Text.Json;

namespace SessionContractExperiment;

// Only this public, fixed-shape projection is eligible for serial output.
// The internal identity digest is never included in diagnostic evidence.
internal sealed record LicensingEvidence(int CandidateCount, int LicenseStatus, long LicenseStatusReason,
    uint? GracePeriodRemaining, long? EvaluationEndUtc, long? TrustedTimeUtc, long GuestUtc, bool? EvaluationExpired);

internal sealed record LicensingSnapshot(LicensingEvidence Evidence, string? IdentityDigest)
{
    internal bool Licensed => Evidence.CandidateCount == 1 && Evidence.LicenseStatus == 1 && Evidence.EvaluationExpired != true;
    internal bool SameProduct(LicensingSnapshot other) => Evidence.CandidateCount == 1 && other.Evidence.CandidateCount == 1 &&
        IdentityDigest is not null && string.Equals(IdentityDigest, other.IdentityDigest, StringComparison.Ordinal);

    internal static LicensingSnapshot Parse(string text)
    {
        using JsonDocument document = StrictJson.Parse(text, 8192);
        JsonElement value = document.RootElement;
        StrictJson.Keys(value, "candidate_count", "license_status", "license_status_reason", "grace_period_remaining",
            "evaluation_end_utc", "trusted_time_utc", "guest_utc", "identity_digest");
        int count = StrictJson.Int(value, "candidate_count", 0, 512);
        long guest = StrictJson.Long(value, "guest_utc", 946684800, 4102444800); // 2000..2100, not a clock correction
        if (count != 1)
        {
            foreach (string key in new[] { "license_status", "license_status_reason", "grace_period_remaining",
                "evaluation_end_utc", "trusted_time_utc", "identity_digest" })
                if (value.GetProperty(key).ValueKind != JsonValueKind.Null) throw new InvalidDataException("license_ambiguous_values");
            return new(new(count, -1, -1, null, null, null, guest, null), null);
        }
        int status = StrictJson.Int(value, "license_status", 0, 6);
        uint reason = StrictJson.UInt(value, "license_status_reason");
        uint? grace = StrictJson.NullableUInt(value, "grace_period_remaining");
        long? end = StrictJson.NullableTime(value, "evaluation_end_utc");
        long? trusted = StrictJson.NullableTime(value, "trusted_time_utc");
        JsonElement identity = value.GetProperty("identity_digest");
        string? digest = identity.ValueKind == JsonValueKind.String ? identity.GetString() : null;
        if (digest is null || digest.Length != 64 || !digest.All(char.IsAsciiHexDigit))
            throw new InvalidDataException("license_identity_digest_invalid");
        bool? expired = end is null ? null : end <= guest || (trusted.HasValue && end <= trusted.Value);
        return new(new(count, status, reason, grace, end, trusted, guest, expired), digest.ToUpperInvariant());
    }
}

internal sealed record ActivationMethodReply(bool InvocationStarted, bool InvocationReturned, uint? ReturnValue,
    int? ErrorHresult, int GuardCode, bool SameProductVerified)
{
    internal static ActivationMethodReply Parse(string text)
    {
        using JsonDocument document = StrictJson.Parse(text, 4096);
        JsonElement value = document.RootElement;
        StrictJson.Keys(value, "invocation_started", "invocation_returned", "return_value", "error_hresult", "guard_code", "same_product_verified");
        bool started = value.GetProperty("invocation_started").GetBoolean();
        bool returned = value.GetProperty("invocation_returned").GetBoolean();
        uint? result = StrictJson.NullableUInt(value, "return_value");
        JsonElement errorElement = value.GetProperty("error_hresult");
        int? error = errorElement.ValueKind == JsonValueKind.Null ? null : errorElement.GetInt32();
        int guard = StrictJson.Int(value, "guard_code", 0, 4);
        bool same = value.GetProperty("same_product_verified").GetBoolean();
        if ((started && (guard != 0 || !same)) || (!started && returned) || (result.HasValue && !returned) ||
            (!started && result.HasValue) || (started && !returned && !error.HasValue) ||
            (returned && !result.HasValue && !error.HasValue) || (guard == 4 && !error.HasValue) ||
            (guard is 1 or 2 && (!same || started || error.HasValue)) || (guard == 3 && (same || started || error.HasValue)) ||
            (guard == 0 && !started))
            throw new InvalidDataException("activation_method_reply_inconsistent");
        return new(started, returned, result, error, guard, same);
    }
}

internal sealed record ActivationAudit
{
    public LicensingEvidence? Before { get; init; }
    public LicensingEvidence? After { get; init; }
    public ActivationNetwork.Observation[]? Network { get; init; }
    public int AttemptCount { get; init; }
    public bool MethodProcessStarted { get; init; }
    public bool MethodProcessCompleted { get; init; }
    public int? MethodProcessExitCode { get; init; }
    // Null means the reply was not observed; a killed client does not establish
    // that the licensing provider never started, stopped, or completed its work.
    public ActivationMethodReply? MethodReply { get; init; }
    public bool SameProductVerified { get; init; }
    public bool LicensedStatusConfirmed { get; init; }
}

internal static class StrictJson
{
    internal static JsonDocument Parse(string text, int cap)
    {
        if (text.Length is <= 0 || text.Length > cap) throw new InvalidDataException("license_json_size_invalid");
        return JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 4 });
    }
    internal static void Keys(JsonElement value, params string[] keys)
    {
        if (value.ValueKind != JsonValueKind.Object) throw new InvalidDataException("license_json_not_object");
        string[] actual = value.EnumerateObject().Select(item => item.Name).ToArray();
        if (actual.Length != keys.Length || actual.Distinct(StringComparer.Ordinal).Count() != keys.Length ||
            actual.Any(key => !keys.Contains(key, StringComparer.Ordinal))) throw new InvalidDataException("license_json_keys_invalid");
    }
    internal static int Int(JsonElement value, string key, int minimum, int maximum)
    {
        if (!value.GetProperty(key).TryGetInt32(out int number) || number < minimum || number > maximum)
            throw new InvalidDataException("license_integer_invalid");
        return number;
    }
    internal static long Long(JsonElement value, string key, long minimum, long maximum)
    {
        if (!value.GetProperty(key).TryGetInt64(out long number) || number < minimum || number > maximum)
            throw new InvalidDataException("license_integer_invalid");
        return number;
    }
    internal static uint UInt(JsonElement value, string key) => value.GetProperty(key).TryGetUInt32(out uint number)
        ? number : throw new InvalidDataException("license_unsigned_invalid");
    internal static uint? NullableUInt(JsonElement value, string key) => value.GetProperty(key).ValueKind == JsonValueKind.Null ? null : UInt(value, key);
    internal static long? NullableTime(JsonElement value, string key) => value.GetProperty(key).ValueKind == JsonValueKind.Null
        ? null : Long(value, key, 1, 253402300799);
}
