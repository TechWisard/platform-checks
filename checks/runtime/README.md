# Bounded runtime smoke experiment

This independent Windows test receives two authenticated encrypted inputs and
executes four fixed cases. The repository contains only the receiver, workflow,
public per-run challenge, public attestation, and necessary synthetic fixtures.
The first execution uses the synthetic fixtures in this directory.

## Public challenge and trust

The receiver requires its own nonzero active Windows session and a visible
window station before generating an RSA-3072 key. It exports only the public
SPKI. The private key stays in the receiver and is never exported, serialized,
logged, included in an artifact, or intentionally written to a file.

A native launcher starts this receiver suspended with `STARTUPINFOEX`, an
explicit list of three NUL standard handles, and `CREATE_NO_WINDOW`. It writes
an atomic PID, creation-time, and executable-path receipt before resuming it.
This prevents the receiver from holding the launching workflow step's pipe
handles open while it remains alive for the later attestation step. Ordinary
runner tracking and inherited job membership remain in place; the launcher
does not use process breakaway or a short-lived kill-on-close job. Receiver
stdout and stderr go to NUL, and only the separately validated result file
can become public output.

The exact `challenge.json` bytes identify the repository and numeric repository
ID, source commit, workflow and ref, run and attempt, tracked request nonce,
fresh random nonce, public-key fingerprint, and 25-minute expiry. The pinned
official `actions/attest` action signs this public document using its default
SLSA provenance mode. A separate step publishes the public document and public
Sigstore bundle on a newly created `runtime-probe/<run>-<attempt>` branch. An
existing branch is never overwritten. No raw OIDC JWT or bearer token is
published.

Before encrypting anything, the sender must verify the bundle with the official
GitHub CLI, exact repository, signer workflow and digest, source digest/ref and
GitHub-hosted-runner policy. It must also check the verified certificate's
numeric repository ID and `runInvocationURI` against fresh official run
metadata, and require the digest of the exact challenge bytes. Self-asserted
JSON fields and the attestation predicate alone are insufficient identity
evidence. The companion sender helper is maintained separately by the caller.

## Wire format

The only accepted envelope path is `runtime/envelope.json` on that exact
per-run branch. The receiver pins an immutable commit before resolving the
file's Git blob, verifies the blob ID and byte length, and bounds each HTTPS
request including its response body. HTTP redirects are rejected.

The envelope schema is `runtime-envelope/v1` with exactly these fields:
`schema`, `challengeSha256`, `wrappedKey`, `nonce`, `ciphertext`, `tag`.
The wrapped value is exactly 32 AES key bytes encrypted using RSA-OAEP-SHA256
with an empty label. AES-256-GCM uses a 12-byte nonce and 16-byte tag. Its AAD is
the ASCII string `runtime-envelope/v1`, one LF byte, and the lowercase SHA-256
of the exact challenge file, with no trailing newline. Each base64 value must
be canonical. Duplicate or unknown JSON fields are rejected.

The decrypted `runtime-payload/v1` object has exactly `schema`, `files`, and
`expectations`. `files` contains exactly `console.exe` then `window.exe`, each
with `name`, `sha256`, and base64 `data`. Both must be bounded native AMD64 PE
executables with their expected console/GUI subsystem and no CLR directory.
The receiver accepts no DLL, arbitrary filename, extraction path, command,
script, shell, extra executable, or external download URL.

The expectations object contains six output digest strings:
`versionStdoutSha256`, `versionStderrSha256`, `helpStdoutSha256`,
`helpStderrSha256`, `invalidStdoutSha256`, `invalidStderrSha256`, plus the
expected `windowClass`. It contains no arguments or exit-code overrides.

## Four fixed cases

| Index | Program | Arguments/action | Required exit |
|---|---|---|---|
| 1 | `console.exe` | `--version` | 0 |
| 2 | `console.exe` | `--help` | 0 |
| 3 | `console.exe` | `--runtime-probe-invalid` | 64 |
| 4 | `window.exe` | No arguments; observe own visible expected-class window, check responsiveness, then send that HWND `WM_CLOSE` | 0 |

The GUI case requires the same expected window to remain observable for one
second, rejects other visible windows from that process, and checks ownership
again before each message. It sends no keyboard/mouse input, changes no
foreground window, and does not interact with other processes' windows.

Each child is created suspended with an explicit three-handle inheritance
list, assigned to a fresh kill-on-close Job Object, and only then resumed.
Only a fixed allowlist of ordinary Windows runtime environment variables is
inherited. Repository, GitHub Actions, and OIDC credentials are excluded.
Console output is limited to 65,536 bytes per stream and compared by digest
after replacing CRLF pairs with LF. Text is never forwarded to the workflow.
GUI stdout and stderr must both be empty. Timeouts and output-limit failures
terminate only the owned job and cannot produce a passing result.

Public results contain only fixed schema/stage strings, case indices, booleans,
numeric errors, and exit codes. Cleanup must establish process exit, an empty
Job Object, completed pipe readers, and removal of the plaintext files. The
outer wrapper validates scalar types and the four case implications again;
even a malformed result still triggers guarded cleanup after the owned
receiver is confirmed stopped. No artifacts, caches, dumps, screenshots,
plaintext binaries, output text, or private keys are uploaded.
Fixed phase strings and booleans also distinguish an absent receiver, a
missing report, and failed report parsing without forwarding diagnostic text.

Payload cleanup removes only the two fixed executable paths and their empty
directory, with no recursive deletion or attribute changes. It retries only
Windows sharing and lock violations (`0x80070020` and `0x80070021`) within one
five-second retry budget, with at most 50 retries. Access denied (`0x80070005`)
is additionally eligible only while deleting either freshly created
executable, after all four case processes/jobs have verified cleanup. The
exclusive creation handle supplies its volume and 128-bit file identifier.
Before allowing this retry and before each subsequent deletion attempt, a
metadata-only handle must show the same identity and a regular, non-readonly,
non-reparse file. Its share mode permits ordinary image mapping; no identity
handle remains open during execution or deletion. Query failures, changed
identity, other access-denied operations, nonempty directories, unknown I/O,
and persistent denial remain failures. No ACL, security setting, or file
attribute is changed. This checks owned test files in the stated trusted-runner
boundary. The metadata handle closes before path-based deletion, so concurrent
hostile replacement remains outside this ownership check. Final
absence of the directory and both known files is mandatory. A cleanup failure
does not overwrite an earlier case failure.

The result includes fixed numeric cleanup diagnostics: `operation`,
`file_index`, `hresult`, `attempts`, `retries`, `image_hresult`, and
`image_retries`. The image fields retain code 5 and its retry count even if a
later sharing violation becomes the last error. Operation 0 means no observed
error; 1 inspects the directory, 2 inspects a file, 3 deletes a file, 4 removes
the empty directory, and 5 verifies absence. File index 0 means the directory,
1 the console fixture, and 2 the window fixture. The last failed operation and
HRESULT remain visible even if a permitted retry succeeds. No path, filename
from an input, or exception text is forwarded. The outer wrapper validates
these numeric fields and accepts retry success only for the narrowly allowed
codes and completed-case conditions.

## Limits and interpretation

Each executable is at most 3 MiB, plaintext at most 10 MiB, and envelope at
most 14 MiB. The receiver accepts one envelope during its 25-minute lifetime.
Console cases have a 10-second deadline. The GUI has 30 seconds to become
ready and 20 seconds to close normally. A fixed 32-minute job deadline is an
outer limit. Public metadata and ciphertext may remain in repository history.

The trust boundary includes the owned repository's write access, the pinned
workflow/actions, GitHub and its hosted runner, the caller's verified sender,
and the supplied executable. This is an authorized smoke test of trusted
inputs, not an execution sandbox for hostile programs. It does not promise
secure deletion from VM paging or host memory, or protection against a
compromised runner. Successful cases establish startup, fixed CLI behavior,
window responsiveness, and normal process teardown only. They do not establish
an authenticated application connection, physical-device support, input
isolation, compatibility with other Windows machines, or performance limits.

## Sources for the trust mechanism

- [GitHub artifact attestation concepts](https://docs.github.com/en/actions/concepts/security/artifact-attestations)
- [Official attestation action](https://github.com/actions/attest)
- [Official CLI verification options and certificate trust guidance](https://cli.github.com/manual/gh_attestation_verify)
- [Sigstore verification result and certificate run URI](https://github.com/sigstore/sigstore-go/blob/main/docs/verification.md)
- [GitHub content API size and object behavior](https://docs.github.com/en/rest/repos/contents)
- [Runner process and stream lifetime](https://github.com/actions/runner/blob/v2.338.0/src/Runner.Sdk/ProcessInvoker.cs)
- [PowerShell process creation and inherited handles](https://github.com/PowerShell/PowerShell/blob/v7.6.0/src/Microsoft.PowerShell.Commands.Management/commands/management/Process.cs)
- [Windows file closing and deletion](https://learn.microsoft.com/en-us/windows/win32/fileio/closing-and-deleting-files)
- [Windows sharing and lock error codes](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-)
- [.NET executable-in-use and other deletion errors](https://learn.microsoft.com/en-us/dotnet/api/system.io.file.delete)
- [Metadata query by file handle](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getfileinformationbyhandleex)
