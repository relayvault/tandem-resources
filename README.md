# Relay Vault — public operator resources

Public downloads for connecting a dental practice's server to Relay Vault.

Everything in this repository is identical for every practice and safe to share.
**Nothing practice-specific ever lives here.** The connection code that authorizes
one particular machine is minted inside the Relay Vault app by a practice admin,
shown once, and typed into a prompt — it is never part of a download link, a URL,
or a file in this repository.

## Contents

| File | Purpose |
| --- | --- |
| `Test-TandemPrereqs.ps1` | Read-only preflight check for a Windows Server that will run the edge agent |
| `SHA256SUMS` | SHA-256 checksums for every file published here |

## Prerequisite doctor

`Test-TandemPrereqs.ps1` is a read-only PowerShell 5.1 preflight, so it runs
on a stock Windows Server 2022 with nothing installed first. It reports whether a
server is ready for the edge agent; it does not change the server.

It does not install software, write the registry, register a service, read
patient tables, or print passwords, connection strings, or registration tokens.
It writes a file only when `-OutFile` is explicitly supplied. Its only network
requests are the local database probe and an HTTPS reachability and certificate
check against the Relay Vault host.

### Download and verify

```powershell
Invoke-WebRequest `
  -Uri https://raw.githubusercontent.com/relayvault/tandem-resources/main/Test-TandemPrereqs.ps1 `
  -OutFile .\Test-TandemPrereqs.ps1

Unblock-File .\Test-TandemPrereqs.ps1
Get-FileHash .\Test-TandemPrereqs.ps1 -Algorithm SHA256
```

Compare the result against `SHA256SUMS` in this repository before running it.
`Unblock-File` clears the mark-of-the-web that a download applies; without it,
the default `RemoteSigned` policy refuses to run the file and reports it as "not
digitally signed", which reads like a broken script rather than an untrusted one.

Piping a URL directly into a shell — `irm ... | iex` — is deliberately not
documented here. On a server holding patient data, the file should be reviewed
and checksummed before it executes.

### Run

```powershell
.\Test-TandemPrereqs.ps1
```

To include the database version, schema, and grant checks, supply a credential
so no password appears on the command line or in PowerShell history:

```powershell
$credential = Get-Credential
.\Test-TandemPrereqs.ps1 -DbCredential $credential -DbName opendental
```

Without `-DbCredential` every other check still runs and the database checks are
reported as `Unknown`.

If host policy blocks a script you have already reviewed, this invocation is
process-scoped and does not change the machine policy:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\Test-TandemPrereqs.ps1
```

### What it checks

Windows edition, build and architecture; PowerShell version and execution
policy; free disk space; clock skew against the Relay Vault host, since skew
breaks signature validation and surfaces as unexplained authentication failures;
whether Node.js is present; MariaDB/MySQL reachability, server version, Open
Dental program and schema version, the connected account and its grants;
outbound HTTPS reachability with certificate subject, issuer and trust errors,
plus system and WinHTTP proxy settings, which is where TLS interception shows up;
a DPAPI machine-scope protect/unprotect round-trip performed entirely in memory;
service-registration privilege; and antivirus/Defender presence and exclusions.

Each check reports `Pass`, `Fail`, `Warn` or `Unknown`, followed by an overall
readiness summary.

Two results are worth knowing in advance:

- **No Node.js installed is a `Pass`, not a problem.** The agent ships as a
  self-contained executable. Installing Node on the server is unnecessary.
- **Connecting as `root` is flagged.** That is not a failure, but the printed
  grants are used to create a dedicated least-privilege database account for the
  agent, which should not run as `root`.

Send the report back to Relay Vault. The output contains host and account
metadata, versions, grants and connection diagnostics only. Password hashes in
grant output are redacted, and the script self-tests that redaction against
planted secrets before printing anything real.

## Security

The connection code that pairs a machine to a practice is a secret. It is
single-use, expires shortly after it is issued, and anyone holding it can connect
a machine to that practice. Do not email it, paste it into chat, or pass it as a
command-line argument — command lines are visible to other users on the server
and land in shell history. Type it at the prompt.

To report a security issue, email `security@relayvault.ai` rather than opening a
public issue here.
