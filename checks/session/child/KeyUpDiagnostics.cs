using System.Text.Json;

namespace SessionContractExperiment;

// Diagnostic observations of this witness's own WndProc only. The buffer is
// fixed; truncation and diagnostic failures never change the input counters.
internal sealed class KeyUpDiagnosticTrace
{
    internal const int Capacity = 32;
    private readonly KeyUpDiagnosticEntry[] entries = new KeyUpDiagnosticEntry[Capacity];
    private int stored, dropped;

    internal static KeyUpDiagnosticTrace? TryCreate()
    {
        try { return new(); }
        catch { return null; }
    }

    internal void Observe(int message, int ordinal, long virtualKey, long packed)
    {
        try
        {
            if (message is not 0x0101 and not 0x0105) return;
            if (stored == Capacity)
            {
                if (dropped < int.MaxValue) dropped++;
                return;
            }
            bool named = KeyUpDiagnosticEntry.NamedKey(virtualKey);
            int scan = (int)((packed >> 16) & 255);
            entries[stored++] = new KeyUpDiagnosticEntry
            {
                Ordinal = ordinal, SystemMessage = message == 0x0105,
                RepeatCount = unchecked((ushort)packed), Extended = (packed & (1L << 24)) != 0,
                ReservedBits = (byte)((packed >> 25) & 15), Context = (packed & (1L << 29)) != 0,
                PreviousState = (packed & (1L << 30)) != 0, Transition = (packed & (1L << 31)) != 0,
                KeyCategory = KeyUpDiagnosticEntry.Category(virtualKey),
                VirtualKey = named ? (int)virtualKey : null,
                ScanCode = named && KeyUpDiagnosticEntry.NamedScan(virtualKey, scan) ? scan : null
            };
        }
        catch { } // A diagnostic cannot throw into the witness's WndProc.
    }

    internal JsonElement? Snapshot()
    {
        try
        {
            KeyUpDiagnosticEntry[] captured = new KeyUpDiagnosticEntry[stored];
            Array.Copy(entries, captured, stored);
            return JsonSerializer.SerializeToElement(new { stored, dropped, entries = captured }, InputReport.Options);
        }
        catch { return null; }
    }
}

internal readonly record struct KeyUpDiagnosticEntry
{
    public int Ordinal { get; init; }
    public bool SystemMessage { get; init; }
    public ushort RepeatCount { get; init; }
    public bool Extended { get; init; }
    public byte ReservedBits { get; init; }
    public bool Context { get; init; }
    public bool PreviousState { get; init; }
    public bool Transition { get; init; }
    // 0 = other/unknown redacted; 1 = digit redacted; 2 = modifier; 3 = lock;
    // 4 = VK_PACKET; 5 = VK_PROCESSKEY; 6 = zero; 7 = 0xFF.
    // The four fixed diagnostic classes never authorize VK/scan output.
    public byte KeyCategory { get; init; }
    public int? VirtualKey { get; init; }
    public int? ScanCode { get; init; }

    internal static bool NamedKey(long key) => key is
        0x10 or 0x11 or 0x12 or 0x5B or 0x5C or >= 0xA0 and <= 0xA5 or 0x14 or 0x90 or 0x91;
    internal static byte Category(long key) => key is 0x14 or 0x90 or 0x91 ? (byte)3 :
        NamedKey(key) ? (byte)2 : key is >= 0x30 and <= 0x39 or >= 0x60 and <= 0x69 ? (byte)1 :
        key == 0xE7 ? (byte)4 : key == 0xE5 ? (byte)5 : key == 0 ? (byte)6 : key == 0xFF ? (byte)7 : (byte)0;

    // A named VK alone cannot authorize an arbitrary scan value. These are
    // the only permitted pairs; every unusual/mismatched scan stays redacted.
    internal static bool NamedScan(long key, int scan) => key switch
    {
        0x10 => scan is 0x2A or 0x36,
        0xA0 => scan == 0x2A,
        0xA1 => scan == 0x36,
        0x11 or 0xA2 or 0xA3 => scan == 0x1D,
        0x12 or 0xA4 or 0xA5 => scan == 0x38,
        0x5B => scan == 0x5B,
        0x5C => scan == 0x5C,
        0x14 => scan == 0x3A,
        0x90 => scan == 0x45,
        0x91 => scan == 0x46,
        _ => false
    };

    internal KeyUpDiagnosticEntry Redacted()
    {
        // Reapply the allowlist when reading the optional JSON. Never trust a
        // serialized category to authorize publishing a key or scan code.
        bool named = VirtualKey is int key && NamedKey(key);
        byte category = VirtualKey is int raw ? Category(raw) :
            KeyCategory is 1 or 4 or 5 or 6 or 7 ? KeyCategory : (byte)0;
        return this with { KeyCategory = category,
            VirtualKey = named ? VirtualKey : null,
            ScanCode = named && ScanCode is int scan && NamedScan(VirtualKey!.Value, scan) ? ScanCode : null,
            ReservedBits = (byte)(ReservedBits & 15) };
    }
}

internal static class SendKeysFailureDiagnostics
{
    internal static void Record(Action<string, object?> record, InputObservation? latest,
        string? expected, long? baselineSequence, int calls)
    {
        try
        {
            bool eligible = latest is not null && expected is not null && baselineSequence is long baseline &&
                latest.Sequence > baseline && calls == 1;
            List<KeyUpDiagnosticEntry> entries = new(KeyUpDiagnosticTrace.Capacity);
            bool available = false, malformed = false, truncated = false;
            int? stored = null, dropped = null;
            if (latest?.KeyUpDiagnostics is JsonElement raw)
            {
                try
                {
                    stored = raw.GetProperty("stored").GetInt32();
                    dropped = raw.GetProperty("dropped").GetInt32();
                    JsonElement array = raw.GetProperty("entries");
                    int length = array.GetArrayLength();
                    if (stored < 0 || stored > KeyUpDiagnosticTrace.Capacity || dropped < 0 || stored != length)
                        malformed = true;
                    truncated = length > KeyUpDiagnosticTrace.Capacity;
                    for (int i = 0; i < Math.Min(length, KeyUpDiagnosticTrace.Capacity); i++)
                    {
                        try { entries.Add(array[i].Deserialize<KeyUpDiagnosticEntry>(InputReport.Options).Redacted()); }
                        catch { malformed = true; }
                    }
                    available = true;
                }
                catch { malformed = true; }
            }
            record("sendkeys_failure_diagnostic", new
            {
                observation_scope = "last_read_own_witness_report_before_cleanup",
                latest_sequence = latest?.Sequence, baseline_sequence = baselineSequence, calls,
                expected_text_comparison_performed = eligible,
                expected_text_equals = eligible ? (bool?)(latest!.ReceivedHex == expected) : null,
                comparison_is_acceptance = false,
                receipt_counters = ReceiptCounters(latest, expected, eligible),
                key_up_metadata_available = available, key_up_metadata_malformed = malformed,
                key_up_metadata_truncated = truncated, key_up_metadata_capacity = KeyUpDiagnosticTrace.Capacity,
                key_up_stored = stored, key_up_dropped = dropped, key_up_entries = entries
            });
        }
        catch { } // Preserve the original experiment failure, including logger failures.
    }

    private static object? ReceiptCounters(InputObservation? latest, string? expected, bool eligible)
    {
        if (latest is null) return null;
        string? received = latest.ReceivedHex;
        // InputReport already bounds the string to 16. Keep this diagnostic
        // independently bounded if called with a malformed in-memory report.
        int inspected = Math.Min(received?.Length ?? 0, 16);
        int decimalDigits = 0, hexLetters = 0, other = 0;
        for (int i = 0; i < inspected; i++)
        {
            char value = received![i];
            if (value is >= '0' and <= '9') decimalDigits++;
            else if (value is >= 'a' and <= 'f' or >= 'A' and <= 'F') hexLetters++;
            else other++;
        }
        string? difference = null;
        int? differences = null;
        if (eligible && received is { Length: <= 16 } && expected is { Length: <= 16 })
        {
            int count = Math.Abs(received.Length - expected.Length);
            for (int i = 0; i < Math.Min(received.Length, expected.Length); i++)
                if (received[i] != expected[i]) count++;
            differences = count;
            difference = count == 0 ? "equal" : received.Length < expected.Length ? "received_shorter" :
                received.Length > expected.Length ? "received_longer" : "same_length_mismatch";
        }
        return new
        {
            characters = latest.CharacterCount, keys_down = latest.KeyDownCount, keys_up = latest.KeyUpCount,
            received_hex_length = received?.Length, inspected_characters = inspected,
            decimal_digit_count = decimalDigits, hex_letter_count = hexLetters, other_stored_character_count = other,
            unexpected_characters = latest.UnexpectedCharacters, repeated_characters = latest.RepeatedCharacters,
            overflow_characters = latest.OverflowCharacters, system_characters = latest.SystemCharacters,
            difference_class = difference, differing_or_missing_positions = differences
        };
    }
}
