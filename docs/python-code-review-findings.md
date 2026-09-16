# Python code review findings — RelayInformer

Review scope: `Python/relayinformer/**` and `Python/tests/**` (project code only,
`.venv` excluded). Branch: `code-review-python-fixes`.

Status legend: `OPEN`, `FIXED`, `WONTFIX` (with reason).

## BUG-1 (High): `self.is_https` goes stale after a redirect, desyncing EPA test logic

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

## BUG-7 (Medium): MSSQL `--user` help text promises an optional domain the parser doesn't allow

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
