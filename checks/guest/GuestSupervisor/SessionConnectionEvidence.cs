using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace SessionContractExperiment;

// Diagnostic projection only. These values never participate in acceptance or
// cleanup decisions. In particular, a null RDP event code is not a failed parse:
// OnConnecting/OnConnected/OnLoginComplete have no numeric argument.
internal static class SessionConnectionEvidence
{
    private const int MaximumEvents = 32;
    private static readonly string[] SessionFields = {
        "parent_session_id", "child_session_id", "console_session_before", "console_session_after" };
    private static readonly string[] BooleanFields = {
        "interactive", "initially_enabled", "enable_changed", "connect_called", "child_created",
        "test_account_remote_desktop_users_membership" };
    private static readonly Dictionary<string, (int Id, bool Numeric)> EventSignatures = new(StringComparer.Ordinal) {
        ["OnConnecting"] = (1, false), ["OnConnected"] = (2, false), ["OnLoginComplete"] = (3, false),
        ["OnDisconnected"] = (4, true), ["OnFatalError"] = (10, true), ["OnWarning"] = (11, true),
        ["OnLogonError"] = (22, true), ["OnAuthenticationWarningDisplayed"] = (18, false),
        ["OnAuthenticationWarningDismissed"] = (19, false) };
    private static readonly HashSet<string> Stages = new(StringComparer.Ordinal) {
        "extended_settings_typelib_verified", "connection_credssp", "server_authentication_required",
        "credential_prompt_disabled", "shared_framebuffer_requested", "optional_shared_framebuffer_request_failed",
        "owned_test_credentials_applied", "connect_invocation_started", "connect_called", "rdp_connection_event",
        "rdp_extended_disconnect", "rdp_extended_disconnect_query_failed", "experiment_failed",
        "connection_preconnect_snapshot", "connection_postfailure_services", "connection_services_unavailable",
        "connection_failure_events", "connection_snapshot_unavailable", "connection_events_unavailable" };

    internal static JsonObject Project(JsonElement value)
    {
        JsonObject result = new() { ["schema"] = "session-connection-observation/v1" };
        foreach (string name in SessionFields)
            if (value.TryGetProperty(name, out JsonElement item))
            {
                if (item.ValueKind == JsonValueKind.Null) result[name] = null;
                else if (item.ValueKind == JsonValueKind.Number && item.TryGetUInt32(out uint number)) result[name] = number;
            }
        foreach (string name in BooleanFields)
            if (value.TryGetProperty(name, out JsonElement item) &&
                item.ValueKind is JsonValueKind.True or JsonValueKind.False or JsonValueKind.Null)
                result[name] = JsonNode.Parse(item.GetRawText());

        JsonArray selected = new();
        bool truncated = false;
        int rejected = 0;
        int remainingEventBytes = 24 * 1024;
        HashSet<string> runtimeStages = new(StringComparer.Ordinal);
        if (value.TryGetProperty("events", out JsonElement events) && events.ValueKind == JsonValueKind.Array)
            foreach (JsonElement item in events.EnumerateArray())
            {
                if (item.ValueKind != JsonValueKind.Object || !Text(item, "stage", out string stage) || !Stages.Contains(stage)) continue;
                JsonObject? details = Details(stage, item);
                if (details is null) { rejected = Math.Min(rejected + 1, 1048576); continue; }
                if (stage is "connection_preconnect_snapshot" or "connection_postfailure_services" or "connection_failure_events" && !runtimeStages.Add(stage))
                { rejected = Math.Min(rejected + 1, 1048576); continue; }
                if (selected.Count == MaximumEvents) { truncated = true; continue; }
                JsonObject observation = new() { ["stage"] = stage, ["details"] = details };
                if (Text(item, "utc", out string utc) && utc.Length <= 33 &&
                    DateTimeOffset.TryParseExact(utc, new[] { "O", "yyyy-MM-dd'T'HH:mm:ss.fffffff'Z'" },
                        CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out DateTimeOffset stamp) && stamp.Offset == TimeSpan.Zero)
                    observation["observed_utc"] = stamp.ToString("O", CultureInfo.InvariantCulture);
                int bytes = Encoding.UTF8.GetByteCount(observation.ToJsonString()) + 1;
                if (bytes > remainingEventBytes) { truncated = true; continue; }
                remainingEventBytes -= bytes;
                selected.Add(observation);
            }
        result["events"] = selected;
        result["events_truncated"] = truncated;
        result["rejected_event_count"] = rejected;
        // Evidence.Event stamps a drained queued event. Do not label it as
        // the callback time or derive transport latency from this timestamp.
        result["rdp_event_time_is_drain_time"] = true;
        return result;
    }

    private static JsonObject? Details(string stage, JsonElement item)
    {
        bool hasDetails = item.TryGetProperty("details", out JsonElement input);
        JsonObject result = new();
        if (stage is "shared_framebuffer_requested" or "owned_test_credentials_applied" or
            "connect_invocation_started" or "connect_called")
            return !hasDetails || input.ValueKind == JsonValueKind.Null ? result : null;
        if (!hasDetails || input.ValueKind != JsonValueKind.Object) return null;
        switch (stage)
        {
            case "connection_preconnect_snapshot": return SessionRuntimeEvidence.Snapshot(input);
            case "connection_postfailure_services": return SessionRuntimeEvidence.Services(input);
            case "connection_failure_events": return SessionRuntimeEvidence.Events(input);
            case "extended_settings_typelib_verified":
                return Number(input, result, "put_slot", 0, 64) && Number(input, result, "get_slot", 0, 64) ? result : null;
            case "connection_credssp":
            case "credential_prompt_disabled":
                return Boolean(input, result, "before") && Boolean(input, result, "after") ? result : null;
            case "server_authentication_required":
                return Number(input, result, "before", 0, 2) && Number(input, result, "after", 0, 2) ? result : null;
            case "rdp_connection_event":
                if (!Text(input, "stage", out string name) || !EventSignatures.TryGetValue(name, out var signature) ||
                    !Number(input, result, "dispid", signature.Id, signature.Id) || !Boolean(input, result, "cleanup") ||
                    !input.TryGetProperty("code", out JsonElement code)) return null;
                if (signature.Numeric)
                {
                    if (!Number(input, result, "code", int.MinValue, int.MaxValue)) return null;
                }
                else if (code.ValueKind == JsonValueKind.Null) result["code"] = null;
                else return null;
                result["stage"] = name;
                return result;
            default:
                // Keep the original failure in SelectEvidence.failures. No
                // free-form operation/exception/provider text is added here.
                return Number(input, result, "code", int.MinValue, int.MaxValue) ? result : null;
        }
    }

    private static bool Text(JsonElement input, string name, out string text)
    {
        text = "";
        if (!input.TryGetProperty(name, out JsonElement value) || value.ValueKind != JsonValueKind.String) return false;
        text = value.GetString()!;
        return true;
    }

    private static bool Boolean(JsonElement input, JsonObject result, string name)
    {
        if (!input.TryGetProperty(name, out JsonElement value) || value.ValueKind is not (JsonValueKind.True or JsonValueKind.False)) return false;
        result[name] = value.GetBoolean();
        return true;
    }

    private static bool Number(JsonElement input, JsonObject result, string name, int min, int max)
    {
        if (!input.TryGetProperty(name, out JsonElement value) || value.ValueKind != JsonValueKind.Number ||
            !value.TryGetInt32(out int number) || number < min || number > max) return false;
        result[name] = number;
        return true;
    }
}
