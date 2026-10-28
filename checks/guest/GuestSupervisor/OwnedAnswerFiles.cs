using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
using System.Xml;

namespace SessionContractExperiment;

// Only known setup-cache candidates on this newly installed, UUID-verified VM.
// An unknown file is a failure. Password subtrees are never interpreted or
// retained. No directory tree, arbitrary XML, ACL, or account is modified.
internal static class OwnedAnswerFiles
{
    private const string Namespace = "urn:schemas-microsoft-com:unattend";
    internal sealed class Failure : Exception
    {
        internal string Code { get; }
        internal Failure(string code, int native = 0)
        { Code = code; HResult = native == 0 ? unchecked((int)0x80131509) : unchecked((int)(0x80070000u | (uint)native)); }
    }
    [StructLayout(LayoutKind.Sequential)]
    private struct AttributeTag { internal uint Attributes, ReparseTag; }
    [DllImport("kernel32.dll", EntryPoint = "CreateFileW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(string path, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool GetFileInformationByHandleEx(SafeFileHandle handle, int information,
        out AttributeTag value, uint bytes);
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool SetFileInformationByHandle(SafeFileHandle handle, int information,
        ref byte deleteFile, uint bytes);

    private static IEnumerable<string> Candidates()
    {
        string windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        string drive = Path.GetPathRoot(windows) ?? throw new Failure("setup_cache_system_drive_unknown");
        string[] directories = { Path.Combine(windows, "Panther"), Path.Combine(windows, "Panther", "Unattend"),
            Path.Combine(drive, "$Windows.~BT", "Sources", "Panther") };
        foreach (string directory in directories)
            foreach (string name in new[] { "Unattend.xml", "Autounattend.xml" })
                yield return Path.Combine(directory, name);
    }

    private static SafeFileHandle? Open(string path, bool deleteAccess)
    {
        // OPEN_REPARSE_POINT avoids following a link at the exact file. Sharing
        // excludes writes/deletion while its owner marker is checked. DELETE
        // access is used only for the same handle after positive ownership.
        SafeFileHandle handle = CreateFile(path, 0x80000000u | (deleteAccess ? 0x10000u : 0u), 1,
            IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
        int error = Marshal.GetLastWin32Error();
        if (!handle.IsInvalid) return handle;
        handle.Dispose();
        if (error is 2 or 3) return null;
        throw new Failure("setup_cache_open_failed", error);
    }

    internal static int RemoveOwned(string nonce)
    {
        string marker = "Owned session fixture " + nonce;
        int removed = 0;
        foreach (string path in Candidates())
        {
            using SafeFileHandle? handle = Open(path, true);
            if (handle is null) continue;
            if (!GetFileInformationByHandleEx(handle, 9 /* FileAttributeTagInfo */, out AttributeTag info,
                    checked((uint)Marshal.SizeOf<AttributeTag>())))
                throw new Failure("setup_cache_attributes_failed", Marshal.GetLastWin32Error());
            if ((info.Attributes & (0x10u | 0x400u)) != 0) throw new Failure("setup_cache_not_regular_file");
            using FileStream stream = new(handle, FileAccess.Read);
            if (stream.Length is <= 0 or > 65536) throw new Failure("setup_cache_size_invalid");
            XmlReaderSettings settings = new() { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null,
                MaxCharactersInDocument = 65536, IgnoreComments = true, CloseInput = false };
            int matches = 0;
            using (XmlReader reader = XmlReader.Create(stream, settings))
            {
                while (reader.Read())
                {
                    if (reader.NodeType != XmlNodeType.Element) continue;
                    if (reader.LocalName == "Password") { reader.Skip(); continue; }
                    if (reader.NamespaceURI == Namespace && reader.LocalName == "Description" &&
                        reader.ReadElementContentAsString() == marker) matches++;
                }
            }
            if (matches != 1) throw new Failure("setup_cache_owner_marker_mismatch");
            byte delete = 1; // FILE_DISPOSITION_INFO contains one BOOLEAN.
            if (!SetFileInformationByHandle(handle, 4 /* FileDispositionInfo */, ref delete, 1))
                throw new Failure("setup_cache_owned_delete_failed", Marshal.GetLastWin32Error());
            // The same verified handle is marked for deletion on close. A
            // pathname replacement between verification and deletion is avoided.
            removed++;
        }
        VerifyAbsent();
        return removed;
    }

    internal static void VerifyAbsent()
    {
        foreach (string path in Candidates())
        {
            using SafeFileHandle? handle = Open(path, false);
            if (handle is not null) throw new Failure("setup_cache_file_still_present");
        }
    }
}
