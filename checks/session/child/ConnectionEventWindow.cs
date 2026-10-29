using System.Globalization;
using System.Text.Json;

namespace SessionContractExperiment;

// Pure eligibility check for one supplemental read. The original time window,
// recent records, and shared collection budget remain authoritative.
internal static class ConnectionEventWindow
{
    internal static DateTimeOffset? EarlierWarningErrorCutoff(JsonElement channel,
        DateTimeOffset started, DateTimeOffset ended)
    {
        bool Number(JsonElement value, string name, int expected) =>
            value.TryGetProperty(name, out JsonElement item) && item.ValueKind == JsonValueKind.Number &&
            item.TryGetInt32(out int number) && number == expected;
        if (started.Offset != TimeSpan.Zero || ended.Offset != TimeSpan.Zero || started > ended ||
            channel.ValueKind != JsonValueKind.Object || !Number(channel, "id", 4) || !Number(channel, "availability", 0) ||
            !channel.TryGetProperty("limit_reached", out JsonElement limited) || limited.ValueKind != JsonValueKind.True ||
            !channel.TryGetProperty("events", out JsonElement events) || events.ValueKind != JsonValueKind.Array ||
            events.GetArrayLength() != 8) return null;
        DateTimeOffset oldest = ended;
        foreach (JsonElement item in events.EnumerateArray())
        {
            if (item.ValueKind != JsonValueKind.Object || !Number(item, "level", 4) ||
                !item.TryGetProperty("utc", out JsonElement time) || time.ValueKind != JsonValueKind.String ||
                time.GetString() is not string text || text.Length > 33 ||
                !DateTimeOffset.TryParseExact(text, new[] { "O", "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'" },
                    CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset stamp) ||
                stamp.Offset != TimeSpan.Zero || stamp < started || stamp > ended) return null;
            if (stamp < oldest) oldest = stamp;
        }
        return oldest;
    }
}
