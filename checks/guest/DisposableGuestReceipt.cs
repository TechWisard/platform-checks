using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.Json;

namespace SessionContractExperiment;

// Explicit opt-in for a guest created by this harness, not a claim that the
// guest is itself a GitHub Windows runner. Like the existing environment guard,
// this prevents accidental use; it is not cryptographic VM attestation.
internal static class DisposableGuestReceipt
{
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint GetSystemFirmwareTable(uint provider, uint table, IntPtr buffer, uint bytes);
    [DllImport("kernel32.dll")]
    private static extern uint WTSGetActiveConsoleSessionId();

    internal static Guid FirmwareUuid()
    {
        const uint rawSmbios = 0x52534D42; // 'RSMB', documented firmware provider.
        uint needed = GetSystemFirmwareTable(rawSmbios, 0, IntPtr.Zero, 0);
        if (needed is < 8 or > 1048576) throw new InvalidOperationException("smbios_size_invalid");
        IntPtr memory = Marshal.AllocHGlobal(checked((int)needed));
        try
        {
            uint count = GetSystemFirmwareTable(rawSmbios, 0, memory, needed);
            if (count != needed) throw new InvalidOperationException("smbios_query_changed");
            byte[] data = new byte[count];
            Marshal.Copy(memory, data, 0, data.Length);
            // GUID byte order below is defined for SMBIOS 2.6 and later.
            if (data[1] < 2 || (data[1] == 2 && data[2] < 6)) throw new InvalidOperationException("smbios_revision_unsupported");
            uint tableBytes = BitConverter.ToUInt32(data, 4);
            if (tableBytes > data.Length - 8) throw new InvalidOperationException("smbios_length_invalid");
            int end = checked(8 + (int)tableBytes);
            Guid? result = null;
            for (int position = 8; position + 4 <= end;)
            {
                int length = data[position + 1];
                if (length < 4 || position + length > end) throw new InvalidOperationException("smbios_structure_invalid");
                if (data[position] == 1)
                {
                    if (length < 25 || result.HasValue) throw new InvalidOperationException("smbios_uuid_ambiguous");
                    result = new Guid(data.AsSpan(position + 8, 16));
                }
                if (data[position] == 127) break;
                int next = position + length;
                while (next + 1 < end && (data[next] != 0 || data[next + 1] != 0)) next++;
                if (next + 1 >= end) throw new InvalidOperationException("smbios_strings_unterminated");
                position = next + 2;
            }
            if (result is null || result == Guid.Empty || result == new Guid("ffffffff-ffff-ffff-ffff-ffffffffffff"))
                throw new InvalidOperationException("smbios_uuid_missing");
            return result.Value;
        }
        finally { Marshal.FreeHGlobal(memory); }
    }

    internal static string IdentityDigest(string nonce, string sid) =>
        Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(nonce + ":" + sid)));

    internal static bool IsRequested()
    {
        string? path = Environment.GetEnvironmentVariable("SESSION_CONTRACT_GUEST_RECEIPT");
        if (string.IsNullOrEmpty(path)) return false;
        try
        {
            string full = Path.GetFullPath(path);
            string programData = Path.TrimEndingDirectorySeparator(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData));
            string? directory = Path.GetDirectoryName(full);
            if (!full.StartsWith(programData + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase) ||
                Path.GetFileName(full) != "guest-receipt.json" || directory is null ||
                !Path.GetFileName(directory).StartsWith("GuestContract-", StringComparison.Ordinal) ||
                (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0 ||
                (File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0) return false;
            using FileStream stream = new(full, FileMode.Open, FileAccess.Read, FileShare.Read);
            if (stream.Length is <= 0 or > 4096) return false;
            using JsonDocument document = JsonDocument.Parse(stream);
            JsonElement value = document.RootElement;
            string? nonce = value.GetProperty("nonce").GetString();
            if (value.GetProperty("schema").GetString() != "owned-disposable-guest/v1" ||
                nonce is null || nonce.Length != 48 || !nonce.All(Uri.IsHexDigit) ||
                value.GetProperty("firmware_uuid").GetGuid() != FirmwareUuid() ||
                value.GetProperty("expires_utc").GetDateTimeOffset() < DateTimeOffset.UtcNow ||
                value.GetProperty("expires_utc").GetDateTimeOffset() > DateTimeOffset.UtcNow.AddMinutes(31) ||
                !value.GetProperty("secure_boot_verified").GetBoolean() || !value.GetProperty("tpm2_verified").GetBoolean()) return false;
            uint session = checked((uint)Process.GetCurrentProcess().SessionId);
            if (!Environment.UserInteractive || session == 0 || WTSGetActiveConsoleSessionId() != session ||
                value.GetProperty("parent_session_id").GetUInt32() != session) return false;
            using WindowsIdentity identity = WindowsIdentity.GetCurrent();
            string? sid = identity.User?.Value;
            return sid is not null && !identity.IsSystem &&
                value.GetProperty("parent_identity_digest").GetString() == IdentityDigest(nonce, sid);
        }
        catch { return false; }
    }
}
