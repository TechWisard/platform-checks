using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SessionContractExperiment;

internal static class SessionRuntimeEvidence
{
    internal static JsonObject? Snapshot(JsonElement input)
    {
        JsonObject result = new();
        foreach ((string field, long max) in new[] { ("process_session", (long)int.MaxValue), ("console_session", (long)uint.MaxValue),
            ("wts_state", 9L), ("os_build", (long)uint.MaxValue), ("os_ubr", (long)uint.MaxValue), ("os_product_type", (long)uint.MaxValue) })
            if (!Number(input, result, field, 0, max, true)) return null;
        foreach (string field in new[] { "child_enabled", "input_desktop_matches_thread" })
            if (!Boolean(input, result, field, true)) return null;
        foreach (string field in new[] { "process_session", "console_session", "wts_state", "os_build", "os_ubr", "os_product_type",
            "child_enabled", "input_desktop_matches_thread", "mstscax_version" })
            if (input.TryGetProperty(field + "_error", out _) && !Number(input, result, field + "_error", int.MinValue, int.MaxValue)) return null;
        if (!input.TryGetProperty("mstscax_version", out JsonElement version)) return null;
        if (version.ValueKind == JsonValueKind.Null) result["mstscax_version"] = null;
        else if (version.ValueKind == JsonValueKind.Array && version.GetArrayLength() == 4)
        {
            JsonArray parts = new();
            foreach (JsonElement item in version.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Number || !item.TryGetInt32(out int number) || number is < 0 or > 65535) return null;
                parts.Add(number);
            }
            result["mstscax_version"] = parts;
        }
        else return null;
        if (!Array(input, "registry", 13, out JsonElement registry) || registry.GetArrayLength() != 13) return null;
        JsonArray entries = new();
        int index = 0;
        foreach (JsonElement item in registry.EnumerateArray())
        {
            JsonObject entry = new(); index++;
            if (item.ValueKind != JsonValueKind.Object || !Number(item, entry, "id", index, index) ||
                !Number(item, entry, "availability", 0, 3) || !Number(item, entry, "value", 0, uint.MaxValue, true) ||
                !Number(item, entry, "error", int.MinValue, int.MaxValue, true)) return null;
            long availability = entry["availability"]!.GetValue<long>();
            if ((availability == 0) != (entry["value"] is not null) || (availability == 2) != (entry["error"] is not null)) return null;
            entries.Add(entry);
        }
        result["registry"] = entries;
        JsonObject? serviceSnapshot = Services(input);
        if (serviceSnapshot is null) return null;
        result["services"] = serviceSnapshot["services"]!.DeepClone();
        return result;
    }

    internal static JsonObject? Services(JsonElement input)
    {
        JsonObject result = new();
        if (!Array(input, "services", 2, out JsonElement services) || services.GetArrayLength() != 2) return null;
        JsonArray serviceEntries = new(); int index = 0;
        foreach (JsonElement item in services.EnumerateArray())
        {
            JsonObject entry = new(); index++;
            if (item.ValueKind != JsonValueKind.Object || !Number(item, entry, "id", index, index) ||
                !Number(item, entry, "state", 1, 7, true) || !Number(item, entry, "win32_exit_code", 0, uint.MaxValue, true) ||
                !Number(item, entry, "service_exit_code", 0, uint.MaxValue, true) || !Number(item, entry, "error", int.MinValue, int.MaxValue, true)) return null;
            bool success = entry["error"] is null;
            if (success != (entry["state"] is not null) || success != (entry["win32_exit_code"] is not null) ||
                success != (entry["service_exit_code"] is not null)) return null;
            serviceEntries.Add(entry);
        }
        result["services"] = serviceEntries;
        return result;
    }

    internal static JsonObject? Events(JsonElement input)
    {
        if (!input.TryGetProperty("attribution", out JsonElement attribution) || attribution.ValueKind != JsonValueKind.String ||
            attribution.GetString() != "time_window_only" || !Array(input, "channels", 5, out JsonElement channels) ||
            channels.GetArrayLength() != 5) return null;
        JsonObject result = new() { ["attribution"] = "time_window_only" };
        if (!Number(input, result, "events_per_channel_limit", 8, 8)) return null;
        JsonArray selected = new(); int index = 0;
        foreach (JsonElement channel in channels.EnumerateArray())
        {
            JsonObject output = new(); index++;
            if (channel.ValueKind != JsonValueKind.Object || !Number(channel, output, "id", index, index) ||
                !Number(channel, output, "availability", 0, 3) || !Number(channel, output, "error", int.MinValue, int.MaxValue, true) ||
                !Boolean(channel, output, "limit_reached") || !Array(channel, "events", 8, out JsonElement events)) return null;
            if ((output["availability"]!.GetValue<long>() == 2) != (output["error"] is not null)) return null;
            JsonArray records = new();
            foreach (JsonElement item in events.EnumerateArray())
            {
                JsonObject? record = Event(item);
                if (record is null) return null;
                records.Add(record);
            }
            output["events"] = records; selected.Add(output);
        }
        result["channels"] = selected;
        if (input.TryGetProperty("earlier_warning_error", out JsonElement earlier))
        {
            JsonObject? extra = EarlierWarningError(earlier, selected[3]!.AsObject());
            if (extra is null) result["earlier_warning_error_rejected"] = true;
            else result["earlier_warning_error"] = extra;
        }
        return result;
    }

    private static JsonObject? EarlierWarningError(JsonElement earlier, JsonObject recent)
    {
        JsonArray recentEvents = recent["events"]!.AsArray();
        if (recent["availability"]!.GetValue<long>() != 0 || !recent["limit_reached"]!.GetValue<bool>() ||
            recentEvents.Count != 8 || recentEvents.Any(x => x?["level"]?.GetValue<long>() != 4 || x?["utc"] is null)) return null;
        DateTimeOffset oldest = recentEvents.Min(x => DateTimeOffset.ParseExact(x!["utc"]!.GetValue<string>(), "O", CultureInfo.InvariantCulture));
        JsonObject extra = new();
        if (earlier.ValueKind != JsonValueKind.Object || !Number(earlier, extra, "id", 4, 4) ||
            !Number(earlier, extra, "availability", 0, 3) || !Number(earlier, extra, "error", int.MinValue, int.MaxValue, true) ||
            !Boolean(earlier, extra, "limit_reached") || !Array(earlier, "events", 8, out JsonElement extraEvents) ||
            !Utc(earlier, "through_utc", out DateTimeOffset through) || through != oldest ||
            extra["availability"]!.GetValue<long>() == 1 ||
            (extra["availability"]!.GetValue<long>() == 2) != (extra["error"] is not null)) return null;
        extra["through_utc"] = through.ToString("O", CultureInfo.InvariantCulture);
        JsonArray selectedEarlier = new();
        foreach (JsonElement item in extraEvents.EnumerateArray())
        {
            JsonObject? record = Event(item);
            if (record is null || record["level"]?.GetValue<long>() is not (>= 1 and <= 3) ||
                !Utc(item, "utc", out DateTimeOffset stamp) || stamp > through) return null;
            selectedEarlier.Add(record);
        }
        extra["events"] = selectedEarlier;
        return extra;
    }

    private static JsonObject? Event(JsonElement item)
    {
        string[] names = { "error_code", "hresult", "status", "substatus", "reason", "reason_code", "previous_state", "new_state", "state_event", "logon_type" };
        JsonObject record = new();
        if (item.ValueKind != JsonValueKind.Object || !Number(item, record, "event_id", 0, 65535) ||
            !Number(item, record, "version", 0, 255, true) || !Number(item, record, "level", 0, 255, true) ||
            !item.TryGetProperty("codes", out JsonElement codes) || codes.ValueKind != JsonValueKind.Object) return null;
        JsonObject codeValues = new();
        foreach (JsonProperty code in codes.EnumerateObject())
            if (!names.Contains(code.Name, StringComparer.Ordinal) || !Number(codes, codeValues, code.Name, 0, uint.MaxValue)) return null;
        record["codes"] = codeValues;
        if (item.TryGetProperty("utc", out _))
        {
            if (!Utc(item, "utc", out DateTimeOffset stamp)) return null;
            record["utc"] = stamp.ToString("O", CultureInfo.InvariantCulture);
        }
        return record;
    }

    private static bool Utc(JsonElement input, string name, out DateTimeOffset stamp)
    {
        stamp = default;
        return input.TryGetProperty(name, out JsonElement utc) && utc.ValueKind == JsonValueKind.String &&
            utc.GetString() is string text && text.Length <= 33 &&
            DateTimeOffset.TryParseExact(text, new[] { "O", "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'" }, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal, out stamp) && stamp.Offset == TimeSpan.Zero;
    }

    private static bool Array(JsonElement input, string field, int max, out JsonElement value) =>
        input.TryGetProperty(field, out value) && value.ValueKind == JsonValueKind.Array && value.GetArrayLength() <= max;
    private static bool Number(JsonElement input, JsonObject output, string field, long min, long max, bool nullable = false)
    {
        if (!input.TryGetProperty(field, out JsonElement value)) return false;
        if (nullable && value.ValueKind == JsonValueKind.Null) { output[field] = null; return true; }
        if (value.ValueKind != JsonValueKind.Number || !value.TryGetInt64(out long number) || number < min || number > max) return false;
        output[field] = number; return true;
    }
    private static bool Boolean(JsonElement input, JsonObject output, string field, bool nullable = false)
    {
        if (!input.TryGetProperty(field, out JsonElement value)) return false;
        if (nullable && value.ValueKind == JsonValueKind.Null) { output[field] = null; return true; }
        if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return false;
        output[field] = value.GetBoolean(); return true;
    }
}
