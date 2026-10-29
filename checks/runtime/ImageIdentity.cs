using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace RuntimeProbe;

internal readonly record struct OwnedImageIdentity(ulong Volume, ulong Low, ulong High);

internal static class ImageIdentity
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct FileIdRecord { internal ulong Volume, Low, High; }
    [StructLayout(LayoutKind.Sequential)]
    internal struct AttributeRecord { internal uint Attributes, ReparseTag; }

    internal static bool Regular(uint attributes, uint reparseTag) => reparseTag == 0
        && (attributes & (uint)(FileAttributes.ReadOnly | FileAttributes.Directory | FileAttributes.ReparsePoint | FileAttributes.Device)) == 0;

    // Called through the exclusive CreateNew handle before it is closed.
    // Only the value identity remains; no image handle is kept across execution.
    internal static OwnedImageIdentity Capture(SafeFileHandle handle)
    {
        Wire.Need(GetAttributes(handle, 9, out var attributes, (uint)Marshal.SizeOf<AttributeRecord>()), 630);
        Wire.Need(Regular(attributes.Attributes, attributes.ReparseTag), 631);
        Wire.Need(GetId(handle, 18, out var identity, (uint)Marshal.SizeOf<FileIdRecord>()) && (identity.Low != 0 || identity.High != 0), 632);
        return new OwnedImageIdentity(identity.Volume, identity.Low, identity.High);
    }

    internal static bool Matches(string path, OwnedImageIdentity expected)
    {
        try
        {
            var security = new Native.SecurityAttributes { nLength = Marshal.SizeOf<Native.SecurityAttributes>(), bInheritHandle = false };
            // FILE_READ_ATTRIBUTES, FILE_SHARE_READ|WRITE|DELETE, OPEN_EXISTING,
            // FILE_FLAG_OPEN_REPARSE_POINT: inspect the path object, not its target.
            using var handle = Native.CreateFileW(path, 0x80, 7, ref security, 3, 0x00200000, IntPtr.Zero);
            return !handle.IsInvalid && Capture(handle) == expected;
        }
        catch { return false; }
    }

    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetId(SafeFileHandle handle, int infoClass, out FileIdRecord info, uint size);
    [DllImport("kernel32.dll", EntryPoint = "GetFileInformationByHandleEx", ExactSpelling = true, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetAttributes(SafeFileHandle handle, int infoClass, out AttributeRecord info, uint size);
}
