using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace SessionContractExperiment;

internal static class TokenEvidence
{
    [StructLayout(LayoutKind.Sequential)]
    private struct SidAndAttributes { internal IntPtr Sid; internal uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    private struct TokenGroupsLayout { internal uint Count; internal SidAndAttributes First; }
    [DllImport("advapi32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetTokenInformation(SafeAccessTokenHandle token, int informationClass,
        IntPtr information, uint length, out uint returnedLength);

    internal static bool HasAdministratorGroupIncludingDenyOnly(WindowsIdentity identity)
    {
        const int tokenGroups = 2;
        bool emptyQuery = GetTokenInformation(identity.AccessToken, tokenGroups, IntPtr.Zero, 0, out uint size);
        int error = Marshal.GetLastWin32Error();
        if (emptyQuery || error != 122 /* ERROR_INSUFFICIENT_BUFFER */ || size < sizeof(uint) || size > 1024 * 1024)
            throw new ExperimentFailure("witness_token_groups_size_query_failed", error);
        IntPtr buffer = Marshal.AllocHGlobal(checked((int)size));
        try
        {
            Native.Require(GetTokenInformation(identity.AccessToken, tokenGroups, buffer, size, out uint returned), "witness_GetTokenInformation_TokenGroups");
            int firstOffset = Marshal.OffsetOf<TokenGroupsLayout>(nameof(TokenGroupsLayout.First)).ToInt32();
            int stride = Marshal.SizeOf<SidAndAttributes>();
            if (returned > size || returned < sizeof(uint)) throw new ExperimentFailure("witness_token_groups_invalid_size");
            uint count = unchecked((uint)Marshal.ReadInt32(buffer));
            if (count > 65536 || (count != 0 && (ulong)firstOffset + (ulong)count * (uint)stride > returned))
                throw new ExperimentFailure("witness_token_groups_invalid_count");
            SecurityIdentifier administrator = new(WellKnownSidType.BuiltinAdministratorsSid, null);
            for (uint index = 0; index < count; index++)
            {
                SidAndAttributes group = Marshal.PtrToStructure<SidAndAttributes>(IntPtr.Add(buffer, checked(firstOffset + (int)index * stride)));
                if (group.Sid == IntPtr.Zero) throw new ExperimentFailure("witness_token_group_sid_missing");
                // Deliberately include disabled and deny-only entries. The
                // managed WindowsIdentity.Groups property filters those out.
                if (new SecurityIdentifier(group.Sid) == administrator) return true;
            }
            return false;
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }
}
