# Python code review findings — RelayInformer

Review scope: `Python/relayinformer/**` and `Python/tests/**` (project code only,
`.venv` excluded). Branch: `code-review-python-fixes`.

Status legend: `OPEN`, `FIXED`, `WONTFIX` (with reason).

## Verification methodology

Every fix below was checked before/after against a real `git worktree` of the
pre-fix commit (`7427c5e`) vs. the fixed code, using two reachable labs from
the lab notes (`lab-a`: dc01/srv02/srv03 at 192.0.2.140-144;
`lab-b`: dc02 at 192.0.2.117). Where a bug's trigger condition exists on a
live target reachable from here, the CLI was run directly against it and the
before/after output or timing compared. Where it doesn't (no reachable host
currently redirects across HTTP/HTTPS schemes; this lab's DC returns the same
generic invalid-credentials error for the ordinary ways to misuse
credentials, so the "unrecognized bind error" branch can't be forced through
normal misuse) the real informer/CLI code was driven end-to-end with only the
network boundary mocked (`requests.get`, `ldap3.Connection`, the raw
socket/`ssl` layer) — same technique the existing test suite already uses,
not a rewrite of the logic under test. Each of those cases is called out
explicitly below rather than described as lab-verified.

## BUG-1 (High): `self.is_https` goes stale after a redirect, desyncing EPA test logic

Status: FIXED (1a3807d)

Verify: no reachable lab host currently serves both HTTP and HTTPS to force a
real cross-scheme redirect, so this was driven through the real
`HttpInformer` with only `requests.get` mocked to return a 401 whose `.url`
crossed schemes (http -> https), same pattern as the existing test suite.
Pre-fix: `informer.is_https` stayed `False` after the redirect. Post-fix: it
correctly became `True`. Full end-to-end sanity run against the live ADCS
endpoint at `http://192.0.2.140/certsrv/` (lab-a, srv03) with real
credentials still returns the correct "EPA (service binding) is DISABLED"
result post-fix, confirming no regression on the non-redirect path.

- File: `Python/relayinformer/informers/HttpInformer.py`, `verify_ntlm_required` (~line 199-238)
- File: `Python/relayinformer/commands/http.py`, `main` (~line 64-65)

`verify_ntlm_required()` follows redirects and updates `self.url` to the final
URL, but never re-derives `self.is_https` from that final URL. Separately,
`commands/http.py` computes its own local `is_https` from the *original* URL
before `verify_ntlm_required()` runs, and uses that local variable for the
rest of the command (which branch to run, and `send_cbt=is_https` on the
first `test_epa_connection` call).

If the target redirects across schemes (e.g. `http://` -> `https://`, a
common pattern for web enrollment endpoints), the tool ends up running the
wrong EPA test flow for the protocol actually in use: CBT gets silently
disabled (`effective_send_cbt = send_cbt and self.is_https` in
`test_epa_connection`) while the command still runs the HTTPS multi-step
channel-binding flow, or vice versa. The tool reports an EPA
enforcement verdict for the wrong protocol without any error.

Fix: recompute `self.is_https` in `verify_ntlm_required()` whenever `self.url`
changes, and have `commands/http.py` read `informer.is_https` (post-redirect)
instead of its own pre-redirect local variable.

## BUG-2 (High): `LdapInformer.RunLdap` silently returns `None` on unrecognized bind errors, misreported as "not enforced"

Status: FIXED (4ea00cc)

Verify: this lab's DC returns the same generic invalid-credentials error for
ordinary bad-username/bad-password misuse (already handled), so an
"unrecognized" bind error can't be forced through normal live misuse without
corrupting the DC. Drove the real Typer CLI end-to-end
(`typer.testing.CliRunner`) against `ldap --method BOTH`, mocking only
`ldap3.Connection.bind()`'s result to simulate an unhandled error code (data
775). Pre-fix: CLI printed "(LDAP) SERVER SIGNING REQUIREMENTS NOT ENFORCED!"
— a false negative. Post-fix: CLI printed "Could not determine LDAP signing
enforcement". Regression check: ran the unmodified `ldap --method BOTH`
against the real DC (dc01, 192.0.2.141, contoso.local / alice:<password>) pre- and
post-fix; both produced identical, correct output ("SIGNING REQUIREMENTS NOT
ENFORCED" / "CHANNEL BINDING SET TO NEVER"), matching this lab's documented
security posture (LDAP signing deliberately disabled).

- File: `Python/relayinformer/informers/LdapInformer.py`, `RunLdap` (line 25-42)
- File: `Python/relayinformer/commands/ldap.py`, `main` (line 126-130)

When an LDAP bind fails with an error that is neither `"stronger"` nor
`"data 52e"`/`"data 532"`, `RunLdap` logs the error and falls off the end of
the function, implicitly returning `None`. The caller does
`if informer.RunLdap(dc): ... else: ... NOT ENFORCED ...`, which treats
`None` the same as an explicit `False`. An unexpected/unrecognized bind
failure is therefore reported to the user as "SERVER SIGNING REQUIREMENTS
NOT ENFORCED", a false negative on a security-relevant finding.

Fix: give `RunLdap` a third, explicit outcome for "could not determine" and
have the caller report that distinctly instead of folding it into "not
enforced".

## BUG-3 (Medium): `DoesLdapsCompleteHandshake` has the same implicit-`None` pattern, plus an un-caught `connect()`

Status: FIXED (4ea00cc)

Verify: drove the real CLI end-to-end with the socket/`ssl` layer mocked to
raise a generic (non-cert, non-timeout) handshake exception. Pre-fix: CLI
printed "cannot complete TLS handshake, cert likely not configured" (wrong
diagnosis). Post-fix: CLI printed "Could not determine whether LDAPS is
configured". Separately confirmed the `connect()` fix: mocked `connect()` to
raise `ConnectionRefusedError` directly — pre-fix this escaped
`DoesLdapsCompleteHandshake` uncaught with the socket never closed; post-fix
it's caught inside the function, logged, and the socket is always closed
(`ssl_sock.close()` observed called in both the connect-failure and
handshake-failure cases post-fix).

- File: `Python/relayinformer/informers/LdapInformer.py`, `DoesLdapsCompleteHandshake` (line 52-83)

Same shape as BUG-2: the final `else` branch logs an unexpected error but
has no `return`, so the function returns `None`. The caller
(`commands/ldap.py` line 132) treats that as "cannot complete TLS handshake,
cert likely not configured", which mislabels a genuine unexpected error as a
missing certificate.

Additionally, `ssl_sock.connect((target, 636))` is called *outside* the
`try/except` that wraps `do_handshake()`. A connection-level failure (refused,
timeout, host unreachable) raises past this function entirely, leaving
`ssl_sock` unclosed, and is only caught by the broad `except Exception` in
`commands/ldap.py`'s per-DC loop with a generic message instead of the
specific handshake diagnostics this function is meant to provide.

Fix: give the function an explicit `return None`/sentinel path plus a
distinct caller message, and wrap `connect()` in the same try/except so the
socket is always closed and connection failures get a clear message.

## BUG-4 (Low-Medium): identity comparison against a string sentinel default

Status: FIXED (59149e2) — resolved by deleting the dead branch entirely rather
than swapping `is not` for `!=`, since the branch had no effect either way.
Upstream PR #4 (merged) also replaced this block, so the bug no longer exists
on upstream main.

Verify: not behaviorally testable — the branch was dead code (see above), so
there is no external outcome pre- vs. post-fix to observe. Confirmed by
inspection that the deleted branch's only possible effect (a `logger.warning`
call) never changed control flow, and that the one line kept (the nthash
prefixing) is unchanged.

- File: `Python/relayinformer/commands/ldap.py`, line 88-93

```python
if nthash is not None:
    nthash = f"aad3b435b51404eeaad3b435b51404ee:{nthash}"
elif password is not DEFAULTPASS:
    pass
else:
    logger.warning("Using BOTH method requires a password or NT hash")
```

`password is not DEFAULTPASS` uses identity comparison against the module
constant. CPython does not guarantee that a CLI-parsed string value will be
the same object as the `DEFAULTPASS` literal, so this check is unreliable in
principle (works today only because of coincidental interning for the common
case). Line 98 in the same file correctly uses `password == DEFAULTPASS` for
the equivalent check. Fix: use `!=` for consistency and correctness.

Separately, the `else` branch's warning is dead in practice: the very next
`if` block (line 98) re-checks the identical condition
(`password == DEFAULTPASS and nthash is None`) and prompts for a password
via `getpass` regardless of whether the warning fired. The warning never
actually prevents anything from proceeding without credentials. Low severity,
noted for cleanup.

## BUG-5 (Low): fragile trailing-character strip in `ResolveDCs`

Status: FIXED (59149e2)

Verify: ran the real SRV discovery against the live lab DC (`ResolveDCs`
against dc01, 192.0.2.141, `contoso.local`) pre- and post-fix — both returned the
identical, correct `{'dc.contoso.local'}`, since this lab's `dnspython` output
always includes the trailing dot the old code coincidentally depended on.
Separately proved the latent defect stands on its own: fed a synthetic
response line without a trailing dot (`"dc01.contoso.local 3600 IN A
10.0.0.5"`) into the exact pre-fix expression and it returned
`'dc01.contoso.loca'` (corrupted, last letter eaten); the fixed
`.rstrip(".")` returned `'dc01.contoso.local'` correctly.

- File: `Python/relayinformer/informers/LdapInformer.py`, `ResolveDCs` (line 150-166)

```python
dcList.add(line.split(" ")[0].rstrip(line.split(" ")[0][-1]))
```

This strips *all* trailing occurrences of whatever the last character of the
token happens to be, not specifically a trailing dot. It only "works" today
because `dnspython`'s string rendering of a DNS response always shows
absolute names with a single trailing `.`. If a resolved name were ever
rendered without that trailing dot, this would corrupt the hostname by
chewing through trailing letters (e.g. a name ending in `...local` would have
trailing `l` characters stripped). Fix: strip the trailing dot explicitly
with `.rstrip(".")`.

## BUG-6 (Low-Medium): `SmbInformer.Run()` retries on *any* exception, doubling timeouts on unreachable hosts

Status: FIXED (6b35194; same code as chrisr-smb-signing-check 7fc2f8a). The
first fix (aec29d5) was wrong, see the note at the end of this section.

Verify: ran the real `smb` command with `--timeout 5` against an unused,
black-holed lab IP (192.0.2.200, confirmed to hang rather than immediately
refuse). Pre-fix: 11.4s wall time (retried the full connection a second
time). Post-fix: 6.2s wall time (single attempt, fails on the first
timeout). Regression check: ran the unmodified `smb` command against the
real DCs (dc01 192.0.2.141 and dc02 192.0.2.117) post-fix — both still
correctly report "(SMB) server enforcing signing requirements (dialect
3.1.1)".

- File: `Python/relayinformer/informers/SmbInformer.py`, `Run` (line 46-49)

```python
try:
    conn = SMBConnection(..., preferredDialect=SMB2_DIALECT_311)
except Exception:
    conn = SMBConnection(..., timeout=self.timeout)  # no preferredDialect
```

The bare `except Exception` is meant to catch a server rejecting the
requested dialect (impacket raises `impacket.smbconnection.SessionError` for
that), but it also catches plain connectivity failures (timeout, connection
refused, DNS failure). Against an unreachable host, this makes the tool
attempt the full connection twice, up to double `self.timeout`, and the
second attempt's exception (potentially a different error than the first)
is what actually surfaces to the user, obscuring the real cause.

Fix: narrow the `except` to `impacket.smbconnection.SessionError` so
connectivity errors propagate immediately on the first attempt.

Note on the first fix (aec29d5): it caught `impacket.smbconnection.SessionError`,
but impacket never raises that class here. With `preferredDialect`,
`SMBConnection.negotiateSession()` builds `smb3.SMB3` directly and does not
translate its exceptions. A refused NEGOTIATE raises `impacket.smb3.SessionError`
(from `SMB2Packet.isValidAnswer()`), and an SMB1-only server that closes the
connection raises `impacket.nmb.NetBIOSError`. The two `SessionError` classes are
unrelated. So the fallback never ran, and every host without SMB 3.1.1 failed
with an error.

The correct fix catches `(smb3.SessionError, nmb.NetBIOSError)`. A failed TCP
connect raises `OSError`, which is still not retried. Tested:

| Target | Pre-fix (6df0d65) | First fix (aec29d5) | Correct fix |
|--------|-------------------|---------------------|-------------|
| Samba 4.20, max protocol SMB3_00 | 3.0 verdict | `smb3.SessionError: STATUS_NOT_SUPPORTED` | 3.0 verdict |
| Samba 4.20, NT1 only | 1.0 verdict | `nmb.NetBIOSError: Error while reading from remote` | 1.0 verdict |
| Unreachable host, `--timeout 5` | 10.0s | not run (one attempt by code reading) | 5.0s |
| Lab DC (3.1.1) | not run | not run | 3.1.1, signing required |

## BUG-7 (Medium): MSSQL `--user` help text promises an optional domain the parser doesn't allow

Status: PARTIAL (6eb0fa2). The option help and docstrings are fixed. Two
examples still show a domain-less user, which fails validation:
`commands/mssql.py` line 30 (`-u admin`, printed by `mssql --help`) and
`Python/README.md` (`-u admin`, line 66 here, 69 on upstream main).

Verify: `mssql --help` now shows "Username in format domain/username (domain
required)". Ran the real `mssql` command against the live MSSQL host
(srv02, 192.0.2.143) with a domain-less `--user alice` — confirmed it fails
with "User must include domain in format 'domain/username'" (the actual,
now-documented, behavior). Ran it again with the correctly-formatted
`--user contoso/alice --password <password>` and confirmed the full EPA flow still
completes end-to-end ("EPA setting - Off"), matching this lab's TDS_ENCRYPT_OFF
configuration.

- File: `Python/relayinformer/commands/mssql.py`, line 18 (help text) and docstring line 28-30
- File: `Python/relayinformer/informers/MssqlInformer.py`, `parse_domain_user` (line 193-214)

`mssql.py`'s `--user` help text and docstring say the format is
`[domain/]username` (domain optional), matching the equivalent HTTP command.
But `MssqlInformer.parse_domain_user` raises `ValueError` whenever the input
contains no `/`, i.e. domain is actually mandatory. A user who follows the
documented, domain-less format for `mssql` gets a validation error the help
text gave no reason to expect.

Fix: correct the help text/docstring to state that domain is required for
`mssql` (`domain/username`), since MSSQL Windows-auth testing meaningfully
needs a domain and relaxing the validation would be the riskier change.

## BUG-8 (Low): explicit empty-string password rejected as "no credential provided"

Status: FIXED (9a8f07a)

Verify: ran the real `http` command with `--password ""` against the live
NTLM-protected ADCS endpoint (`http://192.0.2.140/certsrv/`, lab-a
srv03). Pre-fix: failed immediately client-side with "Either password or
hashes must be provided" — no request sent. Post-fix: actually attempted the
NTLM handshake against the server with the blank password and got a real
401 from the server ("Authentication failed with 401 Unauthorized"),
confirming the explicit empty string is now treated as a real credential
attempt instead of being rejected before any network activity.

- File: `Python/relayinformer/informers/HttpInformer.py`, `test_epa_connection` (line 258-274)

```python
auth_password = password
if password is None and hashes:
    ...
elif not password and not hashes:
    logger.error("Either password or hashes must be provided")
    return "error", None, None
```

`not password` is true both when `password is None` (nothing supplied) and
when `password == ""` (an explicitly supplied blank password, e.g. via
`--password ""` or an empty response to the `getpass` prompt for an account
with no password). The second case is a legitimate, if unusual, credential
and gets rejected as if no credential were given at all.

Fix: use `password is None and not hashes` so an explicit empty string is
treated as a real (blank) password.

## N-1 (High): `--nthash` is never used for the LDAP bind

Status: OPEN (upstream bug)

- File: `Python/relayinformer/commands/ldap.py`, `main` (upstream main line 90-91 and 114)

```python
if check_signing:
    if nthash is not None:
        nthash = f"aad3b435b51404eeaad3b435b51404ee:{nthash}"
    ...
informer = LdapInformer(fqdn, user, password)
```

The command builds the `LM:NT` string in `nthash`, then never uses it.
`LdapInformer` gets `password`, which is still the `DEFAULTPASS` placeholder
(`"defaultpass"`) when the user gives `-nh` and no `-p`. With
`--method BOTH -u alice -nh <hash>`, the LDAP bind sends the password
`defaultpass`. The DC answers with `data 52e` (invalid credentials), the tool
reports invalid credentials, and the DC records a failed logon for the account.
Pass-the-hash for the signing check does not work at all.

`ldap3` NTLM accepts an `LM:NT` hash string as the password, so the fix is to
pass the hash to `LdapInformer` when it is set. Check the other users of
`self.password` too: `RunLdapsWithEpa` builds an msldap URL with
`ldaps+ntlm-password://`, which expects a password, not a hash.

## N-2 (Medium): "Invalid credentials - aborting" does not abort

Status: OPEN (upstream bug)

- File: `Python/relayinformer/informers/LdapInformer.py`, `RunLdap` (upstream main line 44)
- File: `Python/relayinformer/commands/ldap.py`, per-DC loop (upstream main line 165)

```python
# LdapInformer.RunLdap
elif "data 52e" in ldapConn_result_str or "data 532" in ldapConn_result_str:
    logger.warning(ldapConn_result_str)
    raise typer.Exit("Invalid credentials - aborting to prevent unnecessary authentication")

# commands/ldap.py
for dc in dc_list:
    ...
        try:
            ...
        except Exception as e:
            logger.error(f"[{dc}] {str(e)}")
```

`typer.Exit` is `click.exceptions.Exit`, which subclasses `RuntimeError` and so
`Exception` (checked with click 8.1.8). The loop's `except Exception` catches
it, logs `[dc] Invalid credentials - aborting to prevent unnecessary
authentication` as an error, skips the rest of that DC's checks, and goes on
to the next DC: every other DC is tried with the same bad credentials. The log line says
"aborting" while the tool keeps going. The abort exists to stop
exactly that, since each attempt is another failed logon and can lock the
account out.

Also, `typer.Exit` takes an exit code, not a message. Here `exit_code` is the
string `"Invalid credentials - aborting ..."`.

## N-3 (Low): HTTP preflight request has no timeout

Status: FIXED (chrisr-http-eparun-fixes 2647068). Fork-only code.

- File: `Python/relayinformer/informers/HttpInformer.py`, `verify_ntlm_required`

`requests.get()` had no `timeout`, so a server that accepts the connection and
never answers made the `http` command hang. The fix adds
`timeout=PREFLIGHT_TIMEOUT` (10 seconds). Tested against a local server that
accepts and never replies: before the fix the command was still waiting when
killed at 30s. After the fix it fails at 10s with `Read timed out. (read
timeout=10)`.

`test_epa_connection()` has the same gap (`session.get()` with no timeout,
upstream main `HttpInformer.py` line 253). That one is in upstream code and is
still OPEN.
