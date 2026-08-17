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
| `New-TandemAgentDbAccount.ps1` | Creates the least-privilege, read-only `tandem_agent` database account |
| `Export-TandemSchema.ps1` | Read-only capture of Open Dental column definitions, for compatibility review |
| `Install-TandemAgent.ps1` | Installs the edge agent and pairs it to a practice using a connection code |
| `Update-TandemAgentBundle.ps1` | Replaces an installed bundle without changing its pairing |
| `relay-vault-edge-agent.cjs` | The edge agent itself, as a single file run by Node.js |
| `SHA256SUMS` | SHA-256 checksums for every file published here |

The expected order is: check the server, create the database account, capture the
schema, then install and pair the agent.

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
The doctor finds the existing MariaDB/MySQL client on its own, including from
the running database service, and accepts `-MySqlPath` when automatic discovery
cannot locate it. On Windows Server, antivirus status may be Defender-derived
when the client-only Security Center inventory is unavailable.

The intended installation defaults are `C:\Program Files\Tandem` and the
`TandemEdgeAgent` name, which the installer registers as a startup scheduled task
rather than a Windows service.

Each check reports `Pass`, `Fail`, `Warn` or `Unknown`, followed by an overall
readiness summary.

Two results are worth knowing in advance:

- **Node.js 22 or newer is required**, and the doctor fails if it is missing or
  older. Install the current Node.js 22 LTS MSI from https://nodejs.org/en/download
  before installing the agent.
- **Connecting as `root` is flagged.** That is not a failure, but the printed
  grants are used to create a dedicated least-privilege database account for the
  agent, which should not run as `root`.

Send the report back to Relay Vault. The output contains host and account
metadata, versions, grants and connection diagnostics only. Password hashes in
grant output are redacted, and the script self-tests that redaction against
planted secrets before printing anything real.

## Database account

`New-TandemAgentDbAccount.ps1` creates `tandem_agent` — the account the agent
connects with — at both `localhost` and `127.0.0.1`, because which host form a
loopback connection matches depends on the server's name-resolution setting, and
getting it wrong produces an access-denied that looks like a wrong password.

The account is granted `SELECT` on the Open Dental database and nothing else. It
has no `INSERT`, `UPDATE`, `DELETE` or `GRANT OPTION`, so the agent is
structurally incapable of changing patient data. The script proves this rather
than asserting it: after creating the account it performs a read, then attempts a
write that must be denied, and reports both.

```powershell
.\New-TandemAgentDbAccount.ps1
```

It prompts for the database root password, generates the new account's password
locally, prints it once and copies it to the clipboard. Store it in a password
manager before closing the window — the installer prompts for it. Do not
screenshot that window; the printed grants are safe to share, the password line
is not. Re-running the script resets the password and re-applies the grants,
which is also the rotation path.

## Schema capture

`Export-TandemSchema.ps1` connects as `tandem_agent` and writes the practice's
Open Dental column definitions and version rows to three TSV files. It reads
`information_schema` and two configuration rows only — no patient data — so the
output can be reviewed before it is sent anywhere.

```powershell
.\Export-TandemSchema.ps1
```

This exists because an agent proven against one Open Dental release can depend on
a column that a different release does not have. Capturing the schema turns that
from an assumption into a fact before anything writes.

## Installing the agent

Run `Install-TandemAgent.ps1` from an elevated PowerShell window, with the
connection code shown in the Relay Vault app under Settings → Computers. The app
prints the exact command with the code already in it.

```powershell
.\Install-TandemAgent.ps1 -PairingCode <code> -VaultUrl <your Relay Vault URL> -BundlePath .\relay-vault-edge-agent.cjs
```

It refuses to proceed unless it is elevated and finds Node.js 22+, prompts for
the `tandem_agent` password, and tests the database connection before installing
anything — a wrong password fails immediately rather than as an agent that will
not start. It then stores the configuration encrypted with DPAPI at machine
scope, registers a startup scheduled task named `TandemEdgeAgent` running as
`SYSTEM`, and waits until the agent has actually connected before reporting
success. If any step fails it removes the task and restores what was there
before.

Re-running it with a fresh code is the re-pair path after a connector has been
revoked, or after the server has been rebuilt.

The agent's configuration, including the database password, is protected with
DPAPI machine scope, so it can be decrypted only on that machine. Copying the
configuration file to another server does not carry the credentials with it.

## Security

The connection code that pairs a machine to a practice is a secret. It is
single-use, expires shortly after it is issued, and anyone holding it can connect
a machine to that practice. Do not email it, paste it into chat, or pass it as a
command-line argument — command lines are visible to other users on the server
and land in shell history. Type it at the prompt.

To report a security issue, email `security@relayvault.ai` rather than opening a
public issue here.
