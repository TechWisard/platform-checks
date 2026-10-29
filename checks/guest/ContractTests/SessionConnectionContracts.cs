using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;
using SessionContractExperiment;

internal static class SessionConnectionContracts
{
    internal static void Run(Func<JsonNode?, JsonObject> project, Action<bool> check)
    {
        JsonObject Event(string name, JsonObject? details) => new() { ["stage"] = name,
            ["utc"] = "2026-10-29T11:06:57.0000000+00:00", ["details"] = details };
        JsonObject Input(params JsonNode?[] events) => new() { ["schema"] = "session-contract-experiment/v1", ["status"] = "failed",
            ["parent_session_id"] = 2, ["console_session_before"] = 2, ["console_session_after"] = 2, ["child_session_id"] = null,
            ["interactive"] = true, ["initially_enabled"] = false, ["enable_changed"] = true,
            ["connect_called"] = true, ["child_created"] = false, ["test_account_remote_desktop_users_membership"] = false,
            ["window_input_cleanup_verified"] = null, ["events"] = new JsonArray(events) };
        JsonObject Rdp(string stage, int dispid, int? code) => Event("rdp_connection_event", new() {
            ["stage"] = stage, ["dispid"] = dispid, ["code"] = code, ["cleanup"] = false, ["private_text"] = "discard_me" });
        JsonObject failure = Event("experiment_failed", new() { ["code"] = 4, ["operation"] = "rdp_disconnected_before_acceptance" });
        JsonObject input = Input(Event("connect_invocation_started", null), Event("connect_called", null),
            Rdp("OnConnecting", 1, null), Rdp("OnDisconnected", 4, 4), Event("rdp_extended_disconnect", new() { ["code"] = 0 }), failure);
        JsonObject projected = project(input);
        JsonObject connection = projected["connection"]!.AsObject();
        check(projected["status"]!.GetValue<string>() == "failed" && projected["window_input_cleanup_verified"] is null);
        check(connection["parent_session_id"]!.GetValue<uint>() == 2 && connection["initially_enabled"]!.GetValue<bool>() == false);
        check(connection["child_session_id"] is null && connection["test_account_remote_desktop_users_membership"]!.GetValue<bool>() == false);
        check(connection["events"]!.AsArray().Count == 6 && connection["events"]![2]!["details"]!["code"] is null);
        check(connection["events"]![3]!["details"]!["stage"]!.GetValue<string>() == "OnDisconnected");
        check(connection["events"]![4]!["details"]!["code"]!.GetValue<int>() == 0);
        check(connection["rdp_event_time_is_drain_time"]!.GetValue<bool>() && !connection["events_truncated"]!.GetValue<bool>());
        check(!connection.ToJsonString().Contains("discard_me", StringComparison.Ordinal));
        check(projected["failures"]!.AsArray().Any(x => x?["operation"]?.GetValue<string>() == "rdp_disconnected_before_acceptance"));
        foreach (JsonNode? bad in new JsonNode?[] { JsonValue.Create(true), JsonValue.Create("2"), new JsonArray(2),
            JsonValue.Create(-1), JsonValue.Create(4294967296L), JsonValue.Create(1.5) })
        {
            JsonObject malformed = Input(); malformed["parent_session_id"] = bad;
            check(!project(malformed)["connection"]!.AsObject().ContainsKey("parent_session_id"));
        }
        foreach (JsonNode? bad in new JsonNode?[] { JsonValue.Create(1), JsonValue.Create("true"), new JsonArray(true), new JsonObject() })
        {
            JsonObject malformed = Input(); malformed["initially_enabled"] = bad;
            check(!project(malformed)["connection"]!.AsObject().ContainsKey("initially_enabled"));
        }
        foreach (JsonObject badEvent in new[] { Rdp("OnConnecting", 4, null), Rdp("OnConnecting", 1, 0),
            Rdp("OnDisconnected", 4, null), Rdp("Unknown", 1, null) })
        {
            connection = project(Input(badEvent))["connection"]!.AsObject();
            check(connection["events"]!.AsArray().Count == 0 && connection["rejected_event_count"]!.GetValue<int>() == 1);
        }
        JsonArray many = new();
        for (int i = 0; i < 40; i++) many.Add(Rdp("OnConnecting", 1, null));
        many.Add(failure.DeepClone());
        input = Input(); input["events"] = many;
        projected = project(input); connection = projected["connection"]!.AsObject();
        check(connection["events"]!.AsArray().Count == 32 && connection["events_truncated"]!.GetValue<bool>());
        check(projected["failures"]!.AsArray().Count == 1 && projected["failures"]![0]!["code"]!.GetValue<int>() == 4);

        JsonObject snapshot = new() { ["process_session"] = 2, ["console_session"] = 2, ["wts_state"] = 0,
            ["child_enabled"] = true, ["input_desktop_matches_thread"] = true, ["os_build"] = 26100, ["os_ubr"] = 1,
            ["os_product_type"] = 125, ["mstscax_version"] = new JsonArray(10, 0, 26100, 1) };
        JsonArray registry = new(), services = new();
        for (int i = 1; i <= 13; i++) registry.Add(new JsonObject { ["id"] = i, ["availability"] = 1, ["value"] = null, ["error"] = null });
        for (int i = 1; i <= 2; i++) services.Add(new JsonObject { ["id"] = i, ["state"] = 4, ["win32_exit_code"] = 0, ["service_exit_code"] = 0, ["error"] = null });
        snapshot["registry"] = registry; snapshot["services"] = services;
        JsonObject Snap(JsonObject value) => project(Input(Event("connection_preconnect_snapshot", value)))["connection"]!.AsObject();
        check(Snap(snapshot.DeepClone().AsObject())["events"]!.AsArray().Count == 1);
        foreach (Action<JsonObject> corrupt in new Action<JsonObject>[] {
            x => x["child_enabled"] = 1, x => x["mstscax_version"] = new JsonArray(10, 0, 26100),
            x => x["registry"]![0]!["value"] = "private", x => x["registry"]![0]!["value"] = 1,
            x => x["registry"]![0]!["id"] = 13, x => x["services"]![0]!["error"] = 5 })
        { JsonObject bad = snapshot.DeepClone().AsObject(); corrupt(bad); check(Snap(bad)["events"]!.AsArray().Count == 0); }

        JsonArray channels = new();
        for (int i = 1; i <= 5; i++) channels.Add(new JsonObject { ["id"] = i, ["availability"] = 0, ["error"] = null,
            ["limit_reached"] = false, ["events"] = new JsonArray() });
        channels[4]!["events"]!.AsArray().Add(new JsonObject { ["event_id"] = 4625, ["version"] = 0, ["level"] = 0,
            ["codes"] = new JsonObject { ["status"] = 3221225581L, ["substatus"] = 3221225578L, ["logon_type"] = 3 },
            ["utc"] = "2026-10-29T11:06:57.0000000Z" });
        JsonObject logs = new() { ["attribution"] = "time_window_only", ["events_per_channel_limit"] = 8, ["channels"] = channels };
        JsonObject Logs(JsonObject value) => project(Input(Event("connection_failure_events", value)))["connection"]!.AsObject();
        check(Logs(logs.DeepClone().AsObject())["events"]!.AsArray().Count == 1);
        JsonObject duplicates = project(Input(Event("connection_failure_events", logs.DeepClone().AsObject()),
            Event("connection_failure_events", logs.DeepClone().AsObject())))["connection"]!.AsObject();
        check(duplicates["events"]!.AsArray().Count == 1 && duplicates["rejected_event_count"]!.GetValue<int>() == 1);
        foreach (Action<JsonObject> corrupt in new Action<JsonObject>[] {
            x => x["channels"]![4]!["events"]![0]!["codes"]!["user_name"] = "private",
            x => x["channels"]![4]!["events"]![0]!["codes"]!["status"] = true,
            x => x["channels"]![4]!["events"]![0]!["utc"] = "private",
            x => x["channels"]![0]!["availability"] = 2,
            x => { for (int i = 0; i < 9; i++) x["channels"]![0]!["events"]!.AsArray().Add(new JsonObject()); } })
        { JsonObject bad = logs.DeepClone().AsObject(); corrupt(bad); check(Logs(bad)["events"]!.AsArray().Count == 0); }

        // Preserve the strict nullable pre-input cleanup receipt while adding
        // a separate services-only observation after the failed attempt.
        JsonObject serviceDetails = new() { ["services"] = services.DeepClone(), ["private_text"] = "must_not_leave" };
        JsonObject serviceEvent = Event("connection_postfailure_services", serviceDetails);
        projected = project(Input(serviceEvent.DeepClone(), serviceEvent.DeepClone()));
        connection = projected["connection"]!.AsObject();
        check(connection["events"]!.AsArray().Count == 1 && connection["rejected_event_count"]!.GetValue<int>() == 1);
        check(projected["window_input_cleanup_verified"] is null && !connection.ToJsonString().Contains("must_not_leave", StringComparison.Ordinal));
        JsonObject failedService = serviceDetails.DeepClone().AsObject();
        foreach (string field in new[] { "state", "win32_exit_code", "service_exit_code" }) failedService["services"]![0]![field] = null;
        failedService["services"]![0]!["error"] = 5;
        check(project(Input(Event("connection_postfailure_services", failedService)))["connection"]!["events"]!.AsArray().Count == 1);
        foreach (Action<JsonObject> corrupt in new Action<JsonObject>[] {
            x => x["services"]![0]!["id"] = 2, x => x["services"]![0]!["state"] = 0,
            x => x["services"]![0]!["win32_exit_code"] = "private", x => x["services"]![0]!["error"] = 5,
            x => x["services"]!.AsArray().Add(new JsonObject()) })
        {
            JsonObject bad = serviceDetails.DeepClone().AsObject(); corrupt(bad);
            check(project(Input(Event("connection_postfailure_services", bad)))["connection"]!["events"]!.AsArray().Count == 0);
        }
        check(project(Input(Event("connection_services_unavailable", new() { ["code"] = -2147467259,
            ["message"] = "must_not_leave" })))["connection"]!["events"]!.AsArray().Count == 1);

        // Guest10-shaped informational flood: the oldest retained timestamp,
        // not array position or an expanded interval, bounds the extra read.
        DateTimeOffset began = DateTimeOffset.Parse("2026-10-29T16:03:18.8781423+00:00", CultureInfo.InvariantCulture);
        DateTimeOffset oldest = DateTimeOffset.Parse("2026-10-29T16:03:21.2249748+00:00", CultureInfo.InvariantCulture);
        DateTimeOffset ended = DateTimeOffset.Parse("2026-10-29T16:03:23.2325485+00:00", CultureInfo.InvariantCulture);
        JsonObject saturated = logs.DeepClone().AsObject();
        JsonObject channel4 = saturated["channels"]![3]!.AsObject();
        channel4["limit_reached"] = true;
        JsonArray flood = new();
        for (int i = 7; i >= 0; i--) flood.Add(new JsonObject { ["event_id"] = 20523, ["version"] = 0,
            ["level"] = 4, ["codes"] = new JsonObject(), ["utc"] = oldest.AddMilliseconds(i).ToString("O") });
        channel4["events"] = flood;
        DateTimeOffset? Cutoff(JsonObject value) => ConnectionEventWindow.EarlierWarningErrorCutoff(JsonSerializer.SerializeToElement(value), began, ended);
        check(Cutoff(channel4) == oldest);
        foreach (Action<JsonObject> corrupt in new Action<JsonObject>[] {
            x => x["id"] = 3, x => x["availability"] = 3, x => x["limit_reached"] = false,
            x => x["events"]!.AsArray().RemoveAt(0), x => x["events"]!.AsArray().Add(new JsonObject()),
            x => x["events"]![0]!["level"] = 2, x => x["events"]![0]!["level"] = null,
            x => x["events"]![0]!.AsObject().Remove("utc"), x => x["events"]![0]!["utc"] = "private",
            x => x["events"]![0]!["utc"] = began.AddTicks(-1).ToString("O"),
            x => x["events"]![0]!["utc"] = ended.AddTicks(1).ToString("O"),
            x => x["events"]![0]!["utc"] = oldest.ToOffset(TimeSpan.FromHours(1)).ToString("O") })
        { JsonObject bad = channel4.DeepClone().AsObject(); corrupt(bad); check(Cutoff(bad) is null); }
        check(ConnectionEventWindow.EarlierWarningErrorCutoff(JsonSerializer.SerializeToElement(channel4), ended, began) is null);

        JsonObject earlier = new() { ["id"] = 4, ["through_utc"] = oldest.ToString("O"), ["availability"] = 0,
            ["error"] = null, ["limit_reached"] = false, ["private_text"] = "must_not_leave",
            ["events"] = new JsonArray(new JsonObject { ["event_id"] = 1041, ["version"] = 0, ["level"] = 2,
                ["codes"] = new JsonObject { ["error_code"] = 2147942405L }, ["utc"] = began.AddSeconds(1).ToString("O"),
                ["event_text"] = "must_not_leave" }) };
        saturated["earlier_warning_error"] = earlier;
        JsonObject details = Logs(saturated.DeepClone().AsObject())["events"]![0]!["details"]!.AsObject();
        check(details["channels"]![3]!["events"]!.AsArray().Count == 8 && details["channels"]![4]!["events"]!.AsArray().Count == 1);
        check(details["earlier_warning_error"]!["events"]![0]!["codes"]!["error_code"]!.GetValue<long>() == 2147942405L);
        check(!details.ToJsonString().Contains("must_not_leave", StringComparison.Ordinal));
        string originalChannels = details["channels"]!.ToJsonString();
        foreach (Action<JsonObject> corrupt in new Action<JsonObject>[] {
            x => x["id"] = 1, x => x["through_utc"] = oldest.AddTicks(1).ToString("O"),
            x => x["events"]![0]!["level"] = 4, x => x["events"]![0]!["level"] = 0,
            x => x["events"]![0]!["utc"] = oldest.AddTicks(1).ToString("O"),
            x => x["events"]![0]!.AsObject().Remove("utc"),
            x => x["events"]![0]!["codes"]!["user_name"] = "must_not_leave",
            x => x["events"]![0]!["codes"]!["error_code"] = "must_not_leave",
            x => x["availability"] = 2, x => x["availability"] = 1,
            x => { for (int i = 0; i < 8; i++) x["events"]!.AsArray().Add(x["events"]![0]!.DeepClone()); } })
        {
            JsonObject bad = saturated.DeepClone().AsObject(); corrupt(bad["earlier_warning_error"]!.AsObject());
            JsonObject kept = Logs(bad)["events"]![0]!["details"]!.AsObject();
            check(kept["earlier_warning_error"] is null && kept["earlier_warning_error_rejected"]!.GetValue<bool>());
            check(kept["channels"]!.ToJsonString() == originalChannels && !kept.ToJsonString().Contains("must_not_leave", StringComparison.Ordinal));
        }
        foreach (int unavailable in new[] { 2, 3 })
        {
            JsonObject skipped = saturated.DeepClone().AsObject(); JsonObject extra = skipped["earlier_warning_error"]!.AsObject();
            extra["availability"] = unavailable; extra["error"] = unavailable == 2 ? 5 : null; extra["events"] = new JsonArray();
            JsonObject kept = Logs(skipped)["events"]![0]!["details"]!.AsObject();
            check(kept["earlier_warning_error"]!["availability"]!.GetValue<long>() == unavailable && kept["channels"]!.ToJsonString() == originalChannels);
        }
    }
}
