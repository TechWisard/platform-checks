using System.Text.Json;

namespace SessionContractExperiment;

internal sealed record ActivationObservation(int Iteration, int Step, int Code, int CandidateCount, int LicenseStatus, long LicenseStatusReason);

internal readonly record struct ActivationSample(int CandidateCount, int LicenseStatus, long LicenseStatusReason)
{
    internal bool Licensed => CandidateCount == 1 && LicenseStatus == 1;

    internal static ActivationSample Parse(string text)
    {
        if (text.Length is <= 0 or > 4096) throw new InvalidDataException("activation_status_size_invalid");
        using JsonDocument document = JsonDocument.Parse(text, new JsonDocumentOptions { MaxDepth = 4 });
        JsonElement value = document.RootElement;
        if (value.ValueKind != JsonValueKind.Object || value.EnumerateObject().Count() != 3 ||
            !value.TryGetProperty("candidate_count", out JsonElement countElement) || !countElement.TryGetInt32(out int count) || count is < 0 or > 512 ||
            !value.TryGetProperty("license_status", out JsonElement statusElement) ||
            !value.TryGetProperty("license_status_reason", out JsonElement reasonElement))
            throw new InvalidDataException("activation_status_format_invalid");
        if (count != 1)
        {
            if (statusElement.ValueKind != JsonValueKind.Null || reasonElement.ValueKind != JsonValueKind.Null)
                throw new InvalidDataException("activation_status_ambiguous_values");
            return new(count, -1, -1);
        }
        if (!statusElement.TryGetInt32(out int status) || status is < 0 or > 6 || !reasonElement.TryGetUInt32(out uint reason))
            throw new InvalidDataException("activation_status_value_invalid");
        return new(count, status, reason);
    }
}
