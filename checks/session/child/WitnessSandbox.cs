using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace SessionContractExperiment;

// A newly created directory only. No repository, profile, runtime, window
// station, desktop, or system-directory ACL is changed for the witness user.
internal sealed class WitnessSandbox
{
    private readonly string root = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "SessionContractExperiment-" + Guid.NewGuid().ToString("N"));
    internal bool Created { get; private set; }
    internal bool Removed { get; private set; }
    internal string BinaryDirectory => Path.Combine(root, "bin");
    internal string ResultPath => Path.Combine(root, "result", "witness.json");
    internal string AssemblyPath => Path.Combine(BinaryDirectory, Path.GetFileName(Assembly.GetExecutingAssembly().Location));
    internal string RuntimeExecutable { get; private set; } = "";
    internal string? PreparationNonce { get; private set; }

    [StructLayout(LayoutKind.Sequential)]
    private struct SecurityAttributes
    {
        internal uint Length;
        internal IntPtr Descriptor;
        [MarshalAs(UnmanagedType.Bool)] internal bool InheritHandle;
    }
    [DllImport("kernel32.dll", EntryPoint = "CreateDirectoryW", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CreateDirectory(string path, ref SecurityAttributes attributes);

    internal static string ResolveSystemRuntimeExecutable()
    {
        // Use the host beside the exact running framework. No PATH, per-user
        // DOTNET_ROOT, or the other user's environment is assumed or changed.
        DirectoryInfo version = new(RuntimeEnvironment.GetRuntimeDirectory());
        DirectoryInfo? framework = version.Parent;
        DirectoryInfo? shared = framework?.Parent;
        DirectoryInfo? install = shared?.Parent;
        if (framework?.Name != "Microsoft.NETCore.App" || shared?.Name != "shared" || install is null)
            throw new ExperimentFailure("witness_runtime_layout_not_supported");
        string programFiles = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
        string programFilesX86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
        if (!IsWithin(install.FullName, programFiles) && !IsWithin(install.FullName, programFilesX86))
            throw new ExperimentFailure("witness_requires_accessible_system_runtime");
        string executable = Path.Combine(install.FullName, "dotnet.exe");
        if (!File.Exists(executable) || !IsWithin(typeof(Form).Assembly.Location, install.FullName))
            throw new ExperimentFailure("witness_system_windowsdesktop_runtime_missing");
        return executable;
    }

    internal void Create(string parentSid, string testSid)
    {
        if (Created || Removed || parentSid == testSid) throw new ExperimentFailure("witness_sandbox_lifecycle_invalid");
        RuntimeExecutable = ResolveSystemRuntimeExecutable();
        SecurityIdentifier parent = new(parentSid), test = new(testSid);
        DirectorySecurity security = new();
        security.SetOwner(parent);
        security.SetAccessRuleProtection(true, false);
        Add(security, parent, FileSystemRights.FullControl);
        Add(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), FileSystemRights.FullControl);
        Add(security, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), FileSystemRights.FullControl);
        Add(security, test, FileSystemRights.ReadAndExecute);
        byte[] descriptor = security.GetSecurityDescriptorBinaryForm();
        IntPtr native = Marshal.AllocHGlobal(descriptor.Length);
        try
        {
            Marshal.Copy(descriptor, 0, native, descriptor.Length);
            SecurityAttributes attributes = new() { Length = checked((uint)Marshal.SizeOf<SecurityAttributes>()), Descriptor = native };
            // CreateDirectoryW rejects an existing path. Never take ownership of
            // an existing directory or change its ACL after a name collision.
            Native.Require(CreateDirectory(root, ref attributes), "CreateDirectory_owned_witness_sandbox");
            Created = true;
        }
        finally { Marshal.FreeHGlobal(native); }
        Directory.CreateDirectory(BinaryDirectory);
        string assembly = Assembly.GetExecutingAssembly().Location;
        string baseName = Path.GetFileNameWithoutExtension(assembly);
        string sourceDirectory = Path.GetDirectoryName(assembly) ?? throw new ExperimentFailure("witness_assembly_directory_missing");
        foreach (string suffix in new[] { ".dll", ".deps.json", ".runtimeconfig.json" })
        {
            string source = Path.Combine(sourceDirectory, baseName + suffix);
            string destination = Path.Combine(BinaryDirectory, baseName + suffix);
            if (!File.Exists(source) || (File.GetAttributes(source) & FileAttributes.ReparsePoint) != 0)
                throw new ExperimentFailure("witness_payload_file_missing_or_reparse_point");
            File.Copy(source, destination, false);
            using FileStream original = File.OpenRead(source);
            using FileStream copied = File.OpenRead(destination);
            if (!CryptographicOperations.FixedTimeEquals(SHA256.HashData(original), SHA256.HashData(copied)))
                throw new ExperimentFailure("witness_payload_copy_digest_mismatch");
        }
        DirectoryInfo result = Directory.CreateDirectory(Path.GetDirectoryName(ResultPath)!);
        DirectorySecurity resultSecurity = result.GetAccessControl();
        Add(resultSecurity, test, FileSystemRights.Modify);
        result.SetAccessControl(resultSecurity);
    }

    internal void PrepareChildSearch(string helper, string parentSid, string childSid, uint parentSession, uint childSession, uint consoleSession)
    {
        if (!Created || Removed || PreparationNonce is not null) throw new ExperimentFailure("child_preparation_sandbox_lifecycle_invalid");
        PreparationNonce = ChildSearchPreparation.Install(BinaryDirectory, helper, parentSid, childSid,
            parentSession, childSession, consoleSession);
    }

    private static void Add(DirectorySecurity security, SecurityIdentifier sid, FileSystemRights rights) =>
        security.AddAccessRule(new FileSystemAccessRule(sid, rights,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit, PropagationFlags.None, AccessControlType.Allow));

    private static bool IsWithin(string path, string rootPath) => rootPath.Length != 0 &&
        Path.GetFullPath(path).StartsWith(Path.TrimEndingDirectorySeparator(Path.GetFullPath(rootPath)) + Path.DirectorySeparatorChar,
            StringComparison.OrdinalIgnoreCase);

    internal void Remove(bool childRemoved, bool taskRemoved)
    {
        if (!Created || Removed) return;
        if (!childRemoved || !taskRemoved) throw new ExperimentFailure("witness_files_cleanup_waits_for_session_and_task");
        if (Directory.Exists(root)) Directory.Delete(root, true);
        Removed = !Directory.Exists(root);
        if (!Removed) throw new ExperimentFailure("witness_sandbox_not_removed");
    }
}
