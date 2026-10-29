using System.Buffers.Binary;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace RuntimeProbe;

internal sealed class ProbeFailure(int code) : Exception
{
    internal int Code { get; } = code;
}

internal static class Wire
{
    internal const string Repository = "TechWisard/platform-checks";
    internal const string Workflow = Repository + "/.github/workflows/runtime-probe.yml@refs/heads/main";
    internal const int FileLimit = 3 * 1024 * 1024;
    internal const int PlainLimit = 10 * 1024 * 1024;
    internal const int EnvelopeLimit = 14 * 1024 * 1024;
    internal const int WaitSeconds = 1500;
    internal static string Hash(ReadOnlySpan<byte> value) => Convert.ToHexString(SHA256.HashData(value)).ToLowerInvariant();
    internal static void Need(bool condition, int code) { if (!condition) throw new ProbeFailure(code); }
    internal static bool Hex(string value, int length) => value.Length == length && value.All(c => c is >= '0' and <= '9' or >= 'a' and <= 'f');
    internal static bool Decimal(string value) => value.Length is > 0 and <= 20 && value.All(c => c is >= '0' and <= '9') && value[0] != '0';
    internal static string Text(JsonElement value, string name)
    {
        Need(value.TryGetProperty(name, out var result) && result.ValueKind == JsonValueKind.String, 101);
        return result.GetString()!;
    }
    internal static void Fields(JsonElement value, params string[] expected)
    {
        Need(value.ValueKind == JsonValueKind.Object, 102);
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var property in value.EnumerateObject()) Need(names.Add(property.Name), 103);
        Need(names.SetEquals(expected), 104);
    }
    internal static byte[] Decode(string value, int maximum)
    {
        Need(value.Length > 0 && value.Length <= ((long)maximum + 2) / 3 * 4 && value.Length % 4 == 0, 105);
        // Require canonical RFC 4648 text: no whitespace or alternative encodings.
        var bytes = Convert.FromBase64String(value);
        Need(bytes.Length <= maximum && Convert.ToBase64String(bytes) == value, 106);
        return bytes;
    }
    internal static JsonDocument Json(byte[] value) => JsonDocument.Parse(value, new JsonDocumentOptions { MaxDepth = 8, CommentHandling = JsonCommentHandling.Disallow });
    internal static byte[] Aad(string challengeHash) => Encoding.ASCII.GetBytes("runtime-envelope/v1\n" + challengeHash);

    internal static byte[] Decrypt(byte[] envelopeBytes, string challengeHash, RSA key)
    {
        Need(envelopeBytes.Length <= EnvelopeLimit, 110);
        using var document = Json(envelopeBytes);
        var envelope = document.RootElement;
        Fields(envelope, "schema", "challengeSha256", "wrappedKey", "nonce", "ciphertext", "tag");
        Need(Text(envelope, "schema") == "runtime-envelope/v1" && Text(envelope, "challengeSha256") == challengeHash, 111);
        var wrapped = Decode(Text(envelope, "wrappedKey"), 384);
        var nonce = Decode(Text(envelope, "nonce"), 12);
        var tag = Decode(Text(envelope, "tag"), 16);
        var ciphertext = Decode(Text(envelope, "ciphertext"), PlainLimit);
        Need(wrapped.Length == 384 && nonce.Length == 12 && tag.Length == 16 && ciphertext.Length > 0, 112);
        byte[]? aesKey = null;
        byte[]? plain = null;
        try
        {
            aesKey = key.Decrypt(wrapped, RSAEncryptionPadding.OaepSHA256);
            Need(aesKey.Length == 32, 113);
            plain = new byte[ciphertext.Length];
            using var aes = new AesGcm(aesKey, 16);
            aes.Decrypt(nonce, ciphertext, tag, plain, Aad(challengeHash));
            return plain;
        }
        catch { if (plain is not null) CryptographicOperations.ZeroMemory(plain); throw; }
        finally { if (aesKey is not null) CryptographicOperations.ZeroMemory(aesKey); }
    }

    internal static Payload ParsePayload(byte[] bytes)
    {
        Need(bytes.Length <= PlainLimit, 120);
        using var document = Json(bytes);
        var value = document.RootElement;
        Fields(value, "schema", "files", "expectations");
        Need(Text(value, "schema") == "runtime-payload/v1", 121);
        var files = value.GetProperty("files");
        Need(files.ValueKind == JsonValueKind.Array && files.GetArrayLength() == 2, 122);
        var decoded = new List<byte[]>();
        try
        {
            string[] names = ["console.exe", "window.exe"];
            for (var i = 0; i < 2; i++)
            {
                var item = files[i]; Fields(item, "name", "sha256", "data");
                Need(Text(item, "name") == names[i], 123);
                var hash = Text(item, "sha256"); Need(Hex(hash, 64), 124);
                var data = Decode(Text(item, "data"), FileLimit);
                decoded.Add(data);
                Need(Hash(data) == hash, 125);
                ValidatePe(data, i == 0 ? (ushort)3 : (ushort)2);
            }
            var expected = value.GetProperty("expectations");
            string[] fields = ["versionStdoutSha256", "versionStderrSha256", "helpStdoutSha256", "helpStderrSha256", "invalidStdoutSha256", "invalidStderrSha256", "windowClass"];
            Fields(expected, fields);
            var hashes = fields.Take(6).Select(name => Text(expected, name)).ToArray();
            Need(hashes.All(hash => Hex(hash, 64)), 126);
            var windowClass = Text(expected, "windowClass");
            Need(windowClass.Length is > 0 and <= 120 && windowClass.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '.' or '-'), 127);
            return new Payload(decoded[0], decoded[1], hashes, windowClass);
        }
        catch { foreach (var data in decoded) CryptographicOperations.ZeroMemory(data); throw; }
    }

    internal static void ValidatePe(byte[] data, ushort subsystem)
    {
        Need(data.Length >= 512 && data[0] == 'M' && data[1] == 'Z', 130);
        int offset = BinaryPrimitives.ReadInt32LittleEndian(data.AsSpan(0x3c, 4));
        Need(offset >= 64 && offset <= data.Length - 264, 131);
        Need(BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset, 4)) == 0x00004550, 132);
        Need(BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset + 4, 2)) == 0x8664, 133);
        ushort sections = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset + 6, 2));
        Need(sections is > 0 and <= 96, 134);
        ushort optionalLength = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset + 20, 2));
        ushort characteristics = BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset + 22, 2));
        Need(optionalLength >= 240 && offset + 24L + optionalLength <= data.Length && (characteristics & 2) != 0 && (characteristics & 0x2000) == 0, 135);
        Need(BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset + 24, 2)) == 0x20b, 136);
        Need(BinaryPrimitives.ReadUInt16LittleEndian(data.AsSpan(offset + 24 + 68, 2)) == subsystem, 137);
        uint directories = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(offset + 24 + 108, 4));
        Need(directories is 15 or 16 && BinaryPrimitives.ReadUInt64LittleEndian(data.AsSpan(offset + 24 + 112 + 14 * 8, 8)) == 0, 138);
    }

    internal static byte[] NormalizeOutput(byte[] bytes)
    {
        using var stream = new MemoryStream(bytes.Length);
        for (int i = 0; i < bytes.Length; i++)
        {
            if (bytes[i] == 13 && i + 1 < bytes.Length && bytes[i + 1] == 10) continue;
            stream.WriteByte(bytes[i]);
        }
        return stream.ToArray();
    }
}

internal sealed class Payload(byte[] console, byte[] window, string[] hashes, string windowClass) : IDisposable
{
    internal byte[] ConsoleBytes { get; } = console;
    internal byte[] WindowBytes { get; } = window;
    internal string[] Hashes { get; } = hashes;
    internal string WindowClass { get; } = windowClass;
    public void Dispose() { CryptographicOperations.ZeroMemory(ConsoleBytes); CryptographicOperations.ZeroMemory(WindowBytes); }
}

internal sealed class GithubReader : IDisposable
{
    private readonly HttpClient client;
    internal GithubReader(string token)
    {
        Wire.Need(token.Length is > 0 and < 2048, 200);
        client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false }) { Timeout = TimeSpan.FromSeconds(15) };
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        client.DefaultRequestHeaders.UserAgent.ParseAdd("bounded-runtime-probe/1");
        client.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
        client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github.object+json");
    }
    private async Task<byte[]?> Read(string suffix, int limit)
    {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        using var reply = await client.GetAsync("https://api.github.com/repos/" + Wire.Repository + suffix, HttpCompletionOption.ResponseHeadersRead, deadline.Token);
        if (reply.StatusCode == HttpStatusCode.NotFound) return null;
        Wire.Need(reply.StatusCode == HttpStatusCode.OK, 201);
        Wire.Need(reply.Content.Headers.ContentLength is null || reply.Content.Headers.ContentLength <= limit, 202);
        await using var source = await reply.Content.ReadAsStreamAsync(deadline.Token);
        using var output = new MemoryStream();
        byte[] buffer = new byte[8192];
        int count;
        while ((count = await source.ReadAsync(buffer, deadline.Token)) != 0)
        {
            Wire.Need(output.Length + count <= limit, 203);
            output.Write(buffer, 0, count);
        }
        return output.ToArray();
    }
    internal async Task<byte[]?> TryEnvelope(string branch)
    {
        byte[]? reference = await Read("/git/ref/heads/" + branch, 16384);
        if (reference is null) return null;
        using var referenceJson = Wire.Json(reference);
        string commit = Wire.Text(referenceJson.RootElement.GetProperty("object"), "sha");
        Wire.Need(Wire.Hex(commit, 40), 204);
        byte[]? metadata = await Read("/contents/runtime/envelope.json?ref=" + commit, 2 * 1024 * 1024);
        if (metadata is null) return null;
        using var metadataJson = Wire.Json(metadata);
        var item = metadataJson.RootElement;
        Wire.Need(Wire.Text(item, "type") == "file" && Wire.Text(item, "path") == "runtime/envelope.json", 205);
        string blob = Wire.Text(item, "sha"); Wire.Need(Wire.Hex(blob, 40), 206);
        Wire.Need(item.GetProperty("size").TryGetInt32(out int length) && length is > 0 and <= Wire.EnvelopeLimit, 207);
        byte[]? body = await Read("/git/blobs/" + blob, Wire.EnvelopeLimit * 2);
        Wire.Need(body is not null, 208);
        using var blobJson = Wire.Json(body!);
        var record = blobJson.RootElement;
        Wire.Need(Wire.Text(record, "sha") == blob && Wire.Text(record, "encoding") == "base64", 209);
        string encoded = Wire.Text(record, "content");
        Wire.Need(encoded.Length <= Wire.EnvelopeLimit * 3 / 2, 210);
        // GitHub's base64 transport is line wrapped. This is not our envelope's canonical encoding.
        byte[] envelope = Convert.FromBase64String(encoded);
        Wire.Need(envelope.Length == length, 211);
        byte[] header = Encoding.ASCII.GetBytes("blob " + length.ToString(CultureInfo.InvariantCulture) + "\0");
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA1);
        hash.AppendData(header); hash.AppendData(envelope);
        Wire.Need(Convert.ToHexString(hash.GetHashAndReset()).ToLowerInvariant() == blob, 212);
        return envelope;
    }
    public void Dispose() => client.Dispose();
}

internal static class Program
{
    internal static string Env(string name) => Environment.GetEnvironmentVariable(name) ?? "";
    private static string stage = "startup";
    private static async Task<int> Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--self-test") return SelfTest.Run();
        if (args.Length == 3 && args[0] == "--launch") return ReceiverLauncher.Run(args[1], args[2]);
        string? root = null;
        var cases = new List<CaseResult>();
        bool filesRemoved = false, executionComplete = false;
        int error = 0;
        try
        {
            Wire.Need(args.Length == 3 && args[0] == "--receive" && OperatingSystem.IsWindows() && Environment.Is64BitProcess, 300);
            root = Path.GetFullPath(args[1]);
            string runnerTemp = Path.GetFullPath(Env("RUNNER_TEMP")).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            Wire.Need(root.StartsWith(runnerTemp, StringComparison.OrdinalIgnoreCase) && Path.GetFileName(root).StartsWith("runtime-probe-", StringComparison.Ordinal), 301);
            Wire.Need(Directory.Exists(root) && (File.GetAttributes(root) & FileAttributes.ReparsePoint) == 0, 302);
            Wire.Need(Wire.Hex(args[2], 64), 303);
            string repositoryId = Env("GITHUB_REPOSITORY_ID"), run = Env("GITHUB_RUN_ID"), attempt = Env("GITHUB_RUN_ATTEMPT"), sha = Env("GITHUB_SHA");
            Wire.Need(Env("GITHUB_ACTIONS") == "true" && Env("GITHUB_REPOSITORY") == Wire.Repository && Env("GITHUB_REF") == "refs/heads/main" && Env("GITHUB_WORKFLOW_REF") == Wire.Workflow, 304);
            Wire.Need(Wire.Decimal(repositoryId) && Wire.Decimal(run) && Wire.Decimal(attempt) && Wire.Hex(sha, 40), 305);
            Wire.Need(Env("GITHUB_EVENT_NAME") == "push", 306);
            Wire.Need(RunnerProcess.InteractiveSessionReady(), 309);
            string token = Env("RUNTIME_CONTENT_TOKEN");
            Environment.SetEnvironmentVariable("RUNTIME_CONTENT_TOKEN", null);
            Environment.SetEnvironmentVariable("ACTIONS_ID_TOKEN_REQUEST_TOKEN", null);
            Environment.SetEnvironmentVariable("ACTIONS_RUNTIME_TOKEN", null);
            using var reader = new GithubReader(token);
            using var key = RSA.Create(3072);
            var spki = key.ExportSubjectPublicKeyInfo();
            var created = DateTimeOffset.UtcNow;
            var challenge = new Dictionary<string, object>
            {
                ["schema"] = "runtime-challenge/v1", ["repository"] = Wire.Repository, ["repositoryId"] = repositoryId,
                ["runId"] = run, ["runAttempt"] = attempt, ["executionSha"] = sha, ["ref"] = "refs/heads/main", ["workflow"] = Wire.Workflow,
                ["requestNonce"] = args[2], ["nonce"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(32)).ToLowerInvariant(),
                ["publicKeySpki"] = Convert.ToBase64String(spki), ["publicKeySha256"] = Wire.Hash(spki),
                ["createdUtc"] = created.ToString("O", CultureInfo.InvariantCulture), ["expiresUtc"] = created.AddSeconds(Wire.WaitSeconds).ToString("O", CultureInfo.InvariantCulture),
                ["casePolicy"] = "fixed-smoke/v1"
            };
            byte[] challengeBytes = JsonSerializer.SerializeToUtf8Bytes(challenge);
            string stagedChallenge = Path.Combine(root, "challenge.pending");
            using (var output = new FileStream(stagedChallenge, FileMode.CreateNew, FileAccess.Write, FileShare.None)) output.Write(challengeBytes);
            File.Move(stagedChallenge, Path.Combine(root, "challenge.json"), false);
            string challengeHash = Wire.Hash(challengeBytes);
            stage = "wait_envelope";
            var deadline = Stopwatch.StartNew();
            byte[]? envelope = null;
            while (deadline.Elapsed < TimeSpan.FromSeconds(Wire.WaitSeconds))
            {
                envelope = await reader.TryEnvelope("runtime-probe/" + run + "-" + attempt);
                if (envelope is not null) break;
                await Task.Delay(5000);
            }
            Wire.Need(envelope is not null && deadline.Elapsed < TimeSpan.FromSeconds(Wire.WaitSeconds) && DateTimeOffset.UtcNow < created.AddSeconds(Wire.WaitSeconds), 307);
            stage = "decrypt";
            byte[] plain = Wire.Decrypt(envelope!, challengeHash, key);
            Payload payload;
            try { payload = Wire.ParsePayload(plain); }
            finally { CryptographicOperations.ZeroMemory(plain); }
            using (payload)
            {
                string directory = Path.Combine(root, "payload");
                Wire.Need(!Directory.Exists(directory) && !File.Exists(directory), 308);
                Directory.CreateDirectory(directory);
                try
                {
                    string console = Path.Combine(directory, "console.exe"), window = Path.Combine(directory, "window.exe");
                    using (var stream = new FileStream(console, FileMode.CreateNew, FileAccess.Write, FileShare.None)) stream.Write(payload.ConsoleBytes);
                    using (var stream = new FileStream(window, FileMode.CreateNew, FileAccess.Write, FileShare.None)) stream.Write(payload.WindowBytes);
                    CryptographicOperations.ZeroMemory(payload.ConsoleBytes); CryptographicOperations.ZeroMemory(payload.WindowBytes);
                    string[] arguments = ["--version", "--help", "--runtime-probe-invalid"];
                    for (int i = 0; i < arguments.Length; i++)
                    {
                        stage = "case_" + (i + 1).ToString(CultureInfo.InvariantCulture);
                        var result = RunnerProcess.ConsoleCase(console, arguments[i], i + 1, i == 2 ? 64 : 0, payload.Hashes[i * 2], payload.Hashes[i * 2 + 1]);
                        cases.Add(result); Wire.Need(result.passed, 310 + i);
                    }
                    stage = "case_4";
                    var windowResult = RunnerProcess.WindowCase(window, payload.WindowClass);
                    cases.Add(windowResult); Wire.Need(windowResult.passed, 314);
                    executionComplete = true;
                }
                finally
                {
                    stage = executionComplete ? "cleanup" : stage;
                    // This exact fresh directory contains only our two files; never traverse another tree.
                    foreach (string name in new[] { "console.exe", "window.exe" })
                    {
                        string path = Path.Combine(directory, name);
                        if (File.Exists(path))
                        {
                            Wire.Need((File.GetAttributes(path) & FileAttributes.ReparsePoint) == 0, 320);
                            File.Delete(path);
                        }
                    }
                    Directory.Delete(directory, false);
                    filesRemoved = !Directory.Exists(directory);
                }
            }
        }
        catch (ProbeFailure failure) { error = failure.Code; }
        catch (CryptographicException) { error = 401; }
        catch (JsonException) { error = 402; }
        catch (FormatException) { error = 403; }
        catch (HttpRequestException) { error = 404; }
        catch (TaskCanceledException) { error = 405; }
        catch (Exception) { error = 499; }
        bool passed = executionComplete && filesRemoved && cases.Count == 4 && cases.All(item => item.passed) && error == 0;
        var report = new { schema = "runtime-result/v1", passed, stage, error, cases, plaintext_files_removed = filesRemoved };
        byte[] reportBytes = JsonSerializer.SerializeToUtf8Bytes(report);
        if (root is not null)
        {
            try { File.WriteAllBytes(Path.Combine(root, "result.json"), reportBytes); }
            catch { passed = false; }
        }
        Console.WriteLine(Encoding.UTF8.GetString(reportBytes));
        return passed ? 0 : 1;
    }
}

internal static class SelfTest
{
    internal static int Run()
    {
        int assertions = 0;
        void Check(bool value) { assertions++; if (!value) throw new Exception(); }
        void Reject(Action action) { assertions++; try { action(); } catch { return; } throw new Exception(); }
        try
        {
            if (IntPtr.Size == 8)
            {
                Check(System.Runtime.InteropServices.Marshal.SizeOf<Native.StartupInfo>() == 104);
                Check(System.Runtime.InteropServices.Marshal.SizeOf<Native.StartupInfoEx>() == 112);
                Check(System.Runtime.InteropServices.Marshal.SizeOf<Native.SecurityAttributes>() == 24);
                Check(System.Runtime.InteropServices.Marshal.SizeOf<Native.ProcessInformation>() == 24);
                Check(System.Runtime.InteropServices.Marshal.SizeOf<Native.JobBasicLimit>() == 64);
                Check(System.Runtime.InteropServices.Marshal.SizeOf<Native.JobExtendedLimit>() == 144);
                Check(System.Runtime.InteropServices.Marshal.SizeOf<Native.JobAccounting>() == 48);
                Check(System.Runtime.InteropServices.Marshal.SizeOf<Native.UserObjectFlags>() == 12);
            }
            Check(Wire.Hex(new string('a', 64), 64)); Check(!Wire.Hex(new string('A', 64), 64));
            Check(!Wire.Decimal("01")); Check(Wire.Decimal("123"));
            Check(Encoding.ASCII.GetString(Wire.NormalizeOutput(Encoding.ASCII.GetBytes("a\r\nb\rc\n"))) == "a\nb\rc\n");
            using (var duplicate = JsonDocument.Parse("{\"schema\":1,\"schema\":2}")) Reject(() => Wire.Fields(duplicate.RootElement, "schema"));
            using (var unknown = JsonDocument.Parse("{\"schema\":1,\"extra\":2}")) Reject(() => Wire.Fields(unknown.RootElement, "schema"));
            Reject(() => Wire.Decode("Z g==", 4)); Reject(() => Wire.Decode("Zg==", 0));
            Reject(() => Wire.ValidatePe(new byte[512], 3));
            byte[] TestPe(ushort subsystem)
            {
                byte[] image = new byte[512]; image[0] = (byte)'M'; image[1] = (byte)'Z';
                BinaryPrimitives.WriteInt32LittleEndian(image.AsSpan(60, 4), 64);
                BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(64, 4), 0x00004550);
                BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(68, 2), 0x8664);
                BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(70, 2), 1);
                BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(84, 2), 240);
                BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(86, 2), 2);
                BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(88, 2), 0x20b);
                BinaryPrimitives.WriteUInt16LittleEndian(image.AsSpan(156, 2), subsystem);
                BinaryPrimitives.WriteUInt32LittleEndian(image.AsSpan(196, 4), 16);
                return image;
            }
            byte[] consolePe = TestPe(3), windowPe = TestPe(2);
            Wire.ValidatePe(consolePe, 3); assertions++; Wire.ValidatePe(windowPe, 2); assertions++;
            Reject(() => Wire.ValidatePe(consolePe, 2));
            var badPe = consolePe.ToArray(); badPe[68] = 0x4c; Reject(() => Wire.ValidatePe(badPe, 3));
            badPe = consolePe.ToArray(); badPe[312] = 1; Reject(() => Wire.ValidatePe(badPe, 3));
            var payloadObject = new Dictionary<string, object>
            {
                ["schema"] = "runtime-payload/v1",
                ["files"] = new[] { new Dictionary<string, string> { ["name"] = "console.exe", ["sha256"] = Wire.Hash(consolePe), ["data"] = Convert.ToBase64String(consolePe) }, new Dictionary<string, string> { ["name"] = "window.exe", ["sha256"] = Wire.Hash(windowPe), ["data"] = Convert.ToBase64String(windowPe) } },
                ["expectations"] = new Dictionary<string, string> { ["versionStdoutSha256"] = Wire.Hash([]), ["versionStderrSha256"] = Wire.Hash([]), ["helpStdoutSha256"] = Wire.Hash([]), ["helpStderrSha256"] = Wire.Hash([]), ["invalidStdoutSha256"] = Wire.Hash([]), ["invalidStderrSha256"] = Wire.Hash([]), ["windowClass"] = "SyntheticWindow" }
            };
            using (var payload = Wire.ParsePayload(JsonSerializer.SerializeToUtf8Bytes(payloadObject))) Check(payload.ConsoleBytes.SequenceEqual(consolePe) && payload.WindowBytes.SequenceEqual(windowPe));
            var fileItems = (Dictionary<string, string>[])payloadObject["files"];
            fileItems[0]["name"] = "../console.exe"; Reject(() => Wire.ParsePayload(JsonSerializer.SerializeToUtf8Bytes(payloadObject)));
            fileItems[0]["name"] = "console.exe"; fileItems[0]["sha256"] = new string('0', 64); Reject(() => Wire.ParsePayload(JsonSerializer.SerializeToUtf8Bytes(payloadObject)));
            fileItems[0]["sha256"] = Wire.Hash(consolePe);
            var expectedFields = (Dictionary<string, string>)payloadObject["expectations"];
            expectedFields["arguments"] = "powershell"; Reject(() => Wire.ParsePayload(JsonSerializer.SerializeToUtf8Bytes(payloadObject)));
            expectedFields.Remove("arguments"); expectedFields["windowClass"] = "../window"; Reject(() => Wire.ParsePayload(JsonSerializer.SerializeToUtf8Bytes(payloadObject)));
            using var rsa = RSA.Create(3072);
            byte[] plain = Encoding.ASCII.GetBytes("synthetic-local-crypto-roundtrip");
            byte[] aesKey = RandomNumberGenerator.GetBytes(32), nonce = RandomNumberGenerator.GetBytes(12), tag = new byte[16], cipher = new byte[plain.Length];
            string challenge = Wire.Hash(Encoding.ASCII.GetBytes("synthetic-challenge"));
            using (var aes = new AesGcm(aesKey, 16)) aes.Encrypt(nonce, plain, cipher, tag, Wire.Aad(challenge));
            var record = new Dictionary<string, string> { ["schema"] = "runtime-envelope/v1", ["challengeSha256"] = challenge, ["wrappedKey"] = Convert.ToBase64String(rsa.Encrypt(aesKey, RSAEncryptionPadding.OaepSHA256)), ["nonce"] = Convert.ToBase64String(nonce), ["ciphertext"] = Convert.ToBase64String(cipher), ["tag"] = Convert.ToBase64String(tag) };
            var bytes = JsonSerializer.SerializeToUtf8Bytes(record);
            Check(Wire.Decrypt(bytes, challenge, rsa).SequenceEqual(plain));
            Reject(() => Wire.Decrypt(bytes, new string('0', 64), rsa));
            tag[0] ^= 1; record["tag"] = Convert.ToBase64String(tag);
            Reject(() => Wire.Decrypt(JsonSerializer.SerializeToUtf8Bytes(record), challenge, rsa));
            tag[0] ^= 1; record["tag"] = Convert.ToBase64String(tag); cipher[0] ^= 1; record["ciphertext"] = Convert.ToBase64String(cipher);
            Reject(() => Wire.Decrypt(JsonSerializer.SerializeToUtf8Bytes(record), challenge, rsa));
            cipher[0] ^= 1; record["ciphertext"] = Convert.ToBase64String(cipher); record["extra"] = "x";
            Reject(() => Wire.Decrypt(JsonSerializer.SerializeToUtf8Bytes(record), challenge, rsa));
            CryptographicOperations.ZeroMemory(aesKey);
            Console.WriteLine(JsonSerializer.Serialize(new { schema = "runtime-local-tests/v1", passed = true, assertions }));
            return 0;
        }
        catch { Console.WriteLine(JsonSerializer.Serialize(new { schema = "runtime-local-tests/v1", passed = false, assertions })); return 1; }
    }
}
