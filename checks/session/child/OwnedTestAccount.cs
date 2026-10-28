using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Security.Principal;

namespace SessionContractExperiment;

// Opt-in, disposable-VM test fixture. It never adopts an existing name or SID,
// changes group membership, changes policy, or uses another account's password.
internal sealed class OwnedTestAccount : IDisposable
{
    private const uint UserNotFound = 2221;
    private static readonly SecurityIdentifier Administrators = new(WellKnownSidType.BuiltinAdministratorsSid, null);
    private static readonly SecurityIdentifier RemoteDesktopUsers = new(WellKnownSidType.BuiltinRemoteDesktopUsersSid, null);
    private readonly Action<string, object?> record;
    private readonly string name = "scx" + Convert.ToHexString(RandomNumberGenerator.GetBytes(8)).ToLowerInvariant();
    private SecureString? password = NewPassword();
    internal string Name => name;
    internal string Sid { get; private set; } = "";
    internal bool Created { get; private set; }
    internal bool Removed { get; private set; }
    internal bool NonAdministratorVerified { get; private set; }
    internal bool RemoteDesktopUsersMembership { get; private set; }

    internal OwnedTestAccount(Action<string, object?> record) => this.record = record;

    [StructLayout(LayoutKind.Sequential)]
    private struct UserInfo1
    {
        internal IntPtr Name, Password;
        internal uint PasswordAge, Privilege;
        internal IntPtr HomeDirectory, Comment;
        internal uint Flags;
        internal IntPtr ScriptPath;
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct UserInfo23
    {
        internal IntPtr Name, FullName, Comment;
        internal uint Flags;
        internal IntPtr Sid;
    }
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint NetUserAdd(string? server, uint level, ref UserInfo1 user, out uint parameterError);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint NetUserGetInfo(string? server, string name, uint level, out IntPtr buffer);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint NetUserGetLocalGroups(string? server, string name, uint level, uint flags,
        out IntPtr buffer, uint preferredMaximumLength, out uint entriesRead, out uint totalEntries);
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode, ExactSpelling = true)]
    private static extern uint NetUserDel(string? server, string name);
    [DllImport("netapi32.dll", ExactSpelling = true)]
    private static extern uint NetApiBufferFree(IntPtr buffer);

    internal static bool DisposableHostedRunnerRequested() =>
        string.Equals(Environment.GetEnvironmentVariable("GITHUB_ACTIONS"), "true", StringComparison.OrdinalIgnoreCase) &&
        string.Equals(Environment.GetEnvironmentVariable("RUNNER_ENVIRONMENT"), "github-hosted", StringComparison.Ordinal) &&
        string.Equals(Environment.GetEnvironmentVariable("RUNNER_OS"), "Windows", StringComparison.Ordinal);

    internal void Create()
    {
        if (Created || Removed || password is null) throw new ExperimentFailure("test_account_lifecycle_invalid");
        IntPtr nativeName = Marshal.StringToHGlobalUni(name);
        IntPtr nativePassword = IntPtr.Zero;
        try
        {
            nativePassword = Marshal.SecureStringToGlobalAllocUnicode(password);
            UserInfo1 user = new()
            {
                Name = nativeName,
                Password = nativePassword,
                Privilege = 1, // USER_PRIV_USER, required by NetUserAdd.
                Flags = 0x0001 | 0x0200 // UF_SCRIPT | UF_NORMAL_ACCOUNT only.
            };
            uint status = NetUserAdd(null, 1, ref user, out _);
            // A name collision is a failure. Never reuse, update, or delete the
            // colliding account; ownership starts only after this returns zero.
            if (status != 0) throw new ExperimentFailure("NetUserAdd_test_account", checked((int)status));
            Created = true;
        }
        finally
        {
            if (nativePassword != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(nativePassword);
            Marshal.FreeHGlobal(nativeName);
        }
        Sid = ReadCurrentSid() ?? throw new ExperimentFailure("created_test_account_not_found");
        VerifyNoAdministratorMembership();
    }

    internal void RequireOwnership()
    {
        if (!Created || Removed || Sid.Length == 0 || ReadCurrentSid() != Sid)
            throw new ExperimentFailure("test_account_sid_ownership_not_proven");
    }

    internal void VerifyNoAdministratorMembership()
    {
        RequireOwnership();
        uint status = NetUserGetLocalGroups(null, name, 0, 1 /* LG_INCLUDE_INDIRECT */,
            out IntPtr buffer, uint.MaxValue /* MAX_PREFERRED_LENGTH */, out uint read, out uint total);
        try
        {
            if (status != 0) throw new ExperimentFailure("NetUserGetLocalGroups_test_account", checked((int)status));
            if (read != total || read > 16384 || (read != 0 && buffer == IntPtr.Zero))
                throw new ExperimentFailure("test_account_group_inventory_incomplete");
            bool administrator = false, remoteDesktopUser = false;
            for (uint index = 0; index < read; index++)
            {
                IntPtr groupName = Marshal.ReadIntPtr(buffer, checked((int)index * IntPtr.Size));
                string group = Marshal.PtrToStringUni(groupName) ?? throw new ExperimentFailure("invalid_test_account_group_name");
                // Resolve the returned local-group name to a SID; localized
                // group display names are never compared to English literals.
                SecurityIdentifier groupSid = (SecurityIdentifier)new NTAccount(group).Translate(typeof(SecurityIdentifier));
                administrator |= groupSid == Administrators;
                remoteDesktopUser |= groupSid == RemoteDesktopUsers;
            }
            if (administrator) throw new ExperimentFailure("test_account_has_administrator_membership");
            NonAdministratorVerified = true;
            RemoteDesktopUsersMembership = remoteDesktopUser;
        }
        finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
    }

    internal void SetControlPassword(RdpPasswordControl control)
    {
        RequireOwnership();
        if (password is null) throw new ExperimentFailure("test_password_already_consumed");
        try { control.Set(password); }
        finally { ClearPassword(); }
    }

    internal void DeleteAfterSessionsRemoved(bool childRemoved, bool taskRemoved, bool controlDisconnected)
    {
        ClearPassword();
        if (!Created || Removed) return;
        if (!childRemoved || !taskRemoved || !controlDisconnected)
            throw new ExperimentFailure("test_account_cleanup_waits_for_session_and_task");
        if (Sid.Length == 0) throw new ExperimentFailure("test_account_cleanup_sid_receipt_missing");
        string? current = ReadCurrentSid();
        if (current is not null && current != Sid) throw new ExperimentFailure("test_account_name_reused_do_not_delete");
        RequireNoAccountSessions();
        // Fresh checks immediately before deletion: no existing child link and
        // exact created SID. Unexpected sessions are left alone, never logged off.
        if (Native.ChildId() != Native.NoSession)
            throw new ExperimentFailure("test_account_cleanup_child_link_still_present");
        if (current is null) { Removed = true; return; }
        RequireOwnership();
        uint status = NetUserDel(null, name);
        if (status != 0) throw new ExperimentFailure("NetUserDel_owned_test_account", checked((int)status));
        if (ReadCurrentSid() is not null) throw new ExperimentFailure("test_account_still_present_after_delete");
        Removed = true;
    }

    private string? ReadCurrentSid()
    {
        uint status = NetUserGetInfo(null, name, 23, out IntPtr buffer);
        try
        {
            if (status == UserNotFound) return null;
            if (status != 0) throw new ExperimentFailure("NetUserGetInfo_test_account", checked((int)status));
            if (buffer == IntPtr.Zero) throw new ExperimentFailure("empty_test_account_information");
            UserInfo23 user = Marshal.PtrToStructure<UserInfo23>(buffer);
            if (!string.Equals(Marshal.PtrToStringUni(user.Name), name, StringComparison.OrdinalIgnoreCase) || user.Sid == IntPtr.Zero)
                throw new ExperimentFailure("test_account_information_identity_mismatch");
            return new SecurityIdentifier(user.Sid).Value; // Copy before freeing the NetAPI buffer.
        }
        finally { if (buffer != IntPtr.Zero) NetApiBufferFree(buffer); }
    }

    private void RequireNoAccountSessions()
    {
        for (int attempt = 0; attempt < 4; attempt++)
        {
            bool rescan = false;
            Dictionary<uint, int> inventory = Native.SessionStatesForAccountCleanup();
            record("cleanup_account_session_inventory", new
            {
                attempt = attempt + 1,
                count = inventory.Count,
                listener_count = inventory.Values.Count(state => state == 6)
            });
            foreach ((uint session, int state) in inventory)
            {
                // Microsoft: a WTSListen entry has no logged-on user and cannot
                // transition into a regular client session. Do not ask it for a SID.
                if (state == 6 /* WTSListen */) continue;
                try
                {
                    if (Native.SessionSid(session) == Sid)
                        throw new ExperimentFailure("test_account_session_still_exists_do_not_delete");
                }
                catch (ExperimentFailure failure) when (failure.Stage == "session_has_no_logged_on_user") { }
                catch (ExperimentFailure failure) when (failure.Stage == "WTSQuerySessionInformation" && failure.Code == 7022)
                {
                    // The enumerated session no longer resolves. Discard this
                    // entire snapshot; never turn a failed lookup into absence.
                    rescan = true;
                    record("cleanup_session_query_disappeared", new { session_id = session, state, code = failure.Code });
                    break;
                }
            }
            if (rescan) continue;
            Dictionary<uint, int> after = Native.SessionStatesForAccountCleanup();
            if (inventory.Count == after.Count && inventory.All(item =>
                after.TryGetValue(item.Key, out int state) && state == item.Value)) return;
            record("cleanup_account_session_inventory_changed", new { attempt = attempt + 1 });
        }
        throw new ExperimentFailure("cleanup_session_inventory_did_not_stabilize");
    }

    private static SecureString NewPassword()
    {
        const string lower = "abcdefghijkmnopqrstuvwxyz";
        const string upper = "ABCDEFGHJKLMNPQRSTUVWXYZ";
        const string digits = "23456789";
        const string symbols = "!#$%&()*+,-.:;<=>?@[]^_{|}~";
        const string alphabet = lower + upper + digits + symbols;
        char[] characters = new char[40];
        SecureString secret = new();
        try
        {
            for (int index = 0; index < characters.Length; index++) characters[index] = alphabet[RandomNumberGenerator.GetInt32(alphabet.Length)];
            characters[0] = lower[RandomNumberGenerator.GetInt32(lower.Length)];
            characters[1] = upper[RandomNumberGenerator.GetInt32(upper.Length)];
            characters[2] = digits[RandomNumberGenerator.GetInt32(digits.Length)];
            characters[3] = symbols[RandomNumberGenerator.GetInt32(symbols.Length)];
            for (int index = characters.Length - 1; index > 0; index--)
            {
                int other = RandomNumberGenerator.GetInt32(index + 1);
                (characters[index], characters[other]) = (characters[other], characters[index]);
            }
            foreach (char character in characters) secret.AppendChar(character);
            secret.MakeReadOnly();
            return secret;
        }
        catch { secret.Dispose(); throw; }
        finally { CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(characters.AsSpan())); }
    }

    private void ClearPassword() { password?.Dispose(); password = null; }
    // Account deletion is deliberately not hidden in Dispose: it requires the
    // caller's verified session/task cleanup, or must be reported as unverified.
    public void Dispose() => ClearPassword();
}
