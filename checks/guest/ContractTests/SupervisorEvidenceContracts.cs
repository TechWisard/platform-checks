using System.Reflection;
using System.Text.Json;
using System.Text.Json.Nodes;

internal static class SupervisorEvidenceContracts
{
    internal static void Run(string supervisorPath, bool requireWindows)
    {
        if (requireWindows && !OperatingSystem.IsWindows()) throw new InvalidOperationException("windows_contract_host_required");
        Assembly assembly = Assembly.LoadFile(Path.GetFullPath(supervisorPath));
        Type type = assembly.GetType("SessionContractExperiment.GuestSupervisor", throwOnError: true)!;
        MethodInfo Method(string name) => type.GetMethod(name, BindingFlags.NonPublic | BindingFlags.Static) ??
            throw new InvalidOperationException("compiled_contract_method_missing");
        MethodInfo project = Method("SelectEvidence"), cleanup = Method("SessionCleanupVerified"),
            contract = Method("SessionContractPassed"), copy = Method("CopyVerifiedFile"), remove = Method("RemoveOwnedDirectory");
        int checks = 0;
        void Check(bool value)
        { if (!value) throw new InvalidOperationException("supervisor_contract_failed_" + checks); checks++; }
        JsonObject Project(JsonNode? input)
        {
            using JsonDocument doc = JsonDocument.Parse(input?.ToJsonString() ?? "null");
            return (JsonObject)project.Invoke(null, new object[] { doc.RootElement })!;
        }
        bool Gate(MethodInfo method, JsonNode? input)
        {
            using JsonDocument doc = JsonDocument.Parse(input?.ToJsonString() ?? "null");
            return (bool)method.Invoke(null, new object[] { doc.RootElement })!;
        }
        JsonObject Event(JsonNode? code) => new() { ["stage"] = "experiment_failed", ["details"] = new JsonObject
            { ["code"] = code, ["operation"] = "rdp_disconnected_before_acceptance", ["private_text"] = "do_not_forward" } };
        JsonObject Failed(params JsonNode?[] events) => new() { ["schema"] = "session-contract-experiment/v1", ["status"] = "failed",
            ["window_input_cleanup_verified"] = false, ["events"] = new JsonArray(events), ["private_text"] = "do_not_forward" };
        JsonObject actualShape = Failed(new JsonObject { ["stage"] = "rdp_event", ["details"] = new JsonObject
            { ["stage"] = "OnConnecting", ["code"] = null } }, Event(JsonValue.Create(4)));
        JsonObject selected = Project(actualShape);
        Check(selected["status"]!.GetValue<string>() == "failed");
        Check(selected["window_input_cleanup_verified"]!.GetValue<bool>() == false);
        Check(selected["failures"]!.AsArray().Count == 1);
        Check(selected["failures"]![0]!["code"]!.GetValue<int>() == 4);
        Check(selected["failures"]![0]!["operation"]!.GetValue<string>() == "rdp_disconnected_before_acceptance");
        Check(!selected.ToJsonString().Contains("do_not_forward", StringComparison.Ordinal));
        Check(!Gate(contract, selected) && !Gate(cleanup, selected));
        foreach (JsonNode? malformed in new JsonNode?[] { null, JsonValue.Create(true), JsonValue.Create("4"),
            new JsonArray(), new JsonObject(), JsonValue.Create(2147483648L), JsonValue.Create(-2147483649L), JsonValue.Create(1.5) })
        {
            selected = Project(Failed(Event(malformed)));
            Check(selected["failures"]!.AsArray().Count == 0);
            Check(selected["status"]!.GetValue<string>() == "failed");
            Check(!Gate(contract, selected) && !Gate(cleanup, selected));
        }
        foreach (JsonNode? malformed in new JsonNode?[] { null, JsonValue.Create(4), JsonValue.Create(true),
            new JsonArray(), new JsonObject(), new JsonObject { ["stage"] = 2 }, new JsonObject { ["stage"] = "has space" } })
            Check(Project(Failed(malformed))["failures"]!.AsArray().Count == 0);
        foreach (JsonNode? malformed in new JsonNode?[] { null, new JsonObject(), JsonValue.Create("raw_text"), JsonValue.Create(true) })
        {
            JsonObject input = Failed(); input["events"] = malformed;
            selected = Project(input);
            Check(selected["failures"]!.AsArray().Count == 0);
            Check(!Gate(contract, selected));
        }
        foreach (JsonNode? malformed in new JsonNode?[] { null, new JsonArray(), JsonValue.Create(true), JsonValue.Create("raw_text") })
            Check(Project(malformed).Count == 0);
        foreach (JsonNode? malformed in new JsonNode?[] { null, JsonValue.Create(1), JsonValue.Create(true), new JsonObject(),
            new JsonArray(), JsonValue.Create("raw text"), JsonValue.Create("") })
        {
            JsonObject item = Event(JsonValue.Create(int.MinValue)); item["details"]!["operation"] = malformed;
            selected = Project(Failed(item));
            Check(selected["failures"]!.AsArray().Count == 1);
            Check(!selected["failures"]![0]!.AsObject().ContainsKey("operation"));
        }
        JsonArray many = new();
        for (int i = 0; i < 20; i++) many.Add(Event(JsonValue.Create(i)));
        JsonObject capped = Failed(); capped["events"] = many;
        Check(Project(capped)["failures"]!.AsArray().Count == 16);

        SessionConnectionContracts.Run(Project, Check);

        string fixture = Path.Combine(Path.GetTempPath(), "guest-file-contract-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(fixture);
        JsonObject? lockedObservation = null;
        int cleared = 0;
        bool windowsFiles = OperatingSystem.IsWindows();
        JsonObject Remove(int area, bool owned, string path)
        {
            object observation = remove.Invoke(null, new object?[] { area, owned, path })!;
            return JsonSerializer.SerializeToNode(observation, new JsonSerializerOptions
                { PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower })!.AsObject();
        }
        try
        {
            string source = Path.Combine(fixture, "source.bin"), targetRoot = Path.Combine(fixture, "target");
            Directory.CreateDirectory(targetRoot);
            string target = Path.Combine(targetRoot, "copy.bin");
            byte[] bytes = { 1, 4, 9, 16, 25, 36 };
            File.WriteAllBytes(source, bytes);
            File.SetAttributes(source, File.GetAttributes(source) | FileAttributes.ReadOnly);
            FileAttributes before = File.GetAttributes(source);
            Check((before & FileAttributes.ReadOnly) != 0);
            copy.Invoke(null, new object?[] { source, target, (Action)(() => cleared++) });
            Check(File.ReadAllBytes(target).SequenceEqual(bytes));
            Check(File.GetAttributes(source) == before);
            Check((File.GetAttributes(target) & FileAttributes.ReadOnly) == 0);
            Check(cleared == 1);
            bool collisionRejected = false;
            try { copy.Invoke(null, new object?[] { source, target, null }); }
            catch (TargetInvocationException error) when (error.InnerException is IOException) { collisionRejected = true; }
            Check(collisionRejected && File.ReadAllBytes(target).SequenceEqual(bytes));
            JsonObject unowned = Remove(1, false, targetRoot);
            Check(unowned["removal_verified"]!.GetValue<bool>() && Directory.Exists(targetRoot));
            if (windowsFiles)
            {
                using (FileStream locked = new(target, FileMode.Open, FileAccess.Read, FileShare.None))
                {
                    lockedObservation = Remove(1, true, targetRoot);
                    Check(!lockedObservation["removal_verified"]!.GetValue<bool>());
                    Check(lockedObservation["present_before"]!.GetValue<bool>());
                    Check(lockedObservation["error_stage"]!.GetValue<int>() == 2);
                    Check(lockedObservation["error_kind"]!.GetValue<int>() is 1 or 2);
                    Check(lockedObservation["error_hresult"]!.GetValue<int>() < 0);
                    Check(Directory.Exists(targetRoot) && File.Exists(target));
                }
            }
            JsonObject removed = Remove(1, true, targetRoot);
            Check(removed["removal_verified"]!.GetValue<bool>() && removed["present_before"]!.GetValue<bool>());
            Check(removed["error_stage"]!.GetValue<int>() == 0 && removed["error_kind"] is null && removed["error_hresult"] is null);
            Check(!Directory.Exists(targetRoot));
            JsonObject absent = Remove(1, true, targetRoot);
            Check(absent["removal_verified"]!.GetValue<bool>() && !absent["present_before"]!.GetValue<bool>());
            Check(File.GetAttributes(source) == before && File.ReadAllBytes(source).SequenceEqual(bytes));
        }
        finally
        {
            // These are exclusively synthetic files created by this contract.
            foreach (string file in Directory.EnumerateFiles(fixture, "*", SearchOption.AllDirectories))
                File.SetAttributes(file, File.GetAttributes(file) & ~FileAttributes.ReadOnly);
            Directory.Delete(fixture, true);
        }
        Check(!Directory.Exists(fixture));
        Console.WriteLine(JsonSerializer.Serialize(new { schema = "compiled-supervisor-evidence-contracts/v1", passed = checks, failed = 0,
            exact_compiled_supervisor = true, synthetic_owned_file_contracts_executed = true,
            windows_owned_file_contracts_executed = windowsFiles, inherited_read_only_cleared = cleared,
            locked_file_cleanup_observation = lockedObservation, supervisor_entry_point_executed = false,
            native_provider_invoked = false, input_injected = false }));
    }
}
