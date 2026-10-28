# Platform checks

Independent C++17 checks for small utility functions and operating-system API contracts.
Each Windows executable exercises one API family. The portable checks cover bounded
regular-file reads and JSON string encoding, with an independent Python decoder oracle.

## Run

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel 2
ctest --test-dir build -C Release --verbose
```

Requires CMake 3.20+, a C++17 compiler and Python 3.10+. Windows checks use only the
Windows SDK and system libraries. The CI matrix uses standard Windows Server 2022,
Windows Server 2025 and Ubuntu 24.04 runners; Linux also runs address, undefined
behavior and leak checks.

## Scope

- [Portable checks](checks/portable/README.md): text boundaries and regular-file handling.
- [Windows checks](checks/windows/README.md): UTF-16 conversion, display queries,
  Raw Input enumeration, audio endpoint enumeration, device-information sets and sessions.

Results apply only to the source and API calls compiled here. A virtual runner may
have no attached input, display or audio device. Empty successful enumerations are
reported as zero counts. Documented capability limits are reported explicitly as
skips; unexpected API errors fail the corresponding check.

These are isolated checks, with no application, installation target or release package.
Output contains test outcomes, counts and error codes. Hardware identifiers, account
names, device names and file contents are not printed. File fixtures use temporary
directories that are removed after each run. Workflows do not fetch other repositories
or publish executables, caches or artifacts; results remain in the job logs.
