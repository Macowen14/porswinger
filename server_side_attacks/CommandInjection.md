# OS Command Injection — Lab Notes

## 1. Vulnerability Concept

OS command injection occurs when an application takes user-controlled input and passes it — concatenated or otherwise unsanitized — into a call that invokes the underlying operating system's shell. The shell parses the resulting string looking for its own control syntax (`;`, `|`, `&`, `&&`, `||`, backticks, `$()`), so any of these characters present in user input can splice an attacker-chosen command onto the developer's intended one.

Root cause, always: **untrusted input reaches a shell interpreter without being isolated as pure data.**

Common places this shows up:
- "Diagnostic" features (ping, traceroute, DNS lookup) in admin panels/routers
- Legacy CLI tool wrappers (image conversion, PDF generation, report generators — e.g. `stockreport.pl`)
- File processing pipelines that shell out to `convert`, `ffmpeg`, `tar`, `zip`
- CI/CD systems with user-configurable build commands

---

## 2. Types of Command Injection

### By visibility of output

| Type | Description | How you detect it |
|---|---|---|
| **In-band (classic)** | Command output is reflected directly in the HTTP response | Inject `whoami`, `id`, `pwd` and read the result straight from the page |
| **Blind** | Command executes but output is never shown to you | No visible change in response — need indirect confirmation |
| **Blind, time-based** | Same as blind, confirmed via execution delay | Inject `; sleep 10` and measure response time |
| **Blind, out-of-band (OOB)** | Confirmed via a side-channel network callback | Inject `; nslookup <you>.burpcollaborator.net` and watch for the DNS hit |

### By injection operator used

| Payload | Meaning | Notes |
|---|---|---|
| `; cmd` | Run `cmd` after original, regardless of original's success | Works on Linux/Unix shells |
| `\| cmd` | Pipe original stdout into `cmd`; `cmd` still runs even if pointless as a pipe target | |
| `\|\| cmd` | Run `cmd` only if original command **fails** | Useful if you can force the original to error |
| `&& cmd` | Run `cmd` only if original **succeeds** | |
| `& cmd` | Run both, asynchronously (background) | Output timing is unreliable — original app may return before `cmd` finishes. Better suited to blind/OOB triggers than in-band proof |
| `` `cmd` `` | Inline command substitution — output of `cmd` gets spliced into the middle of the original command string | Executes even if input is placed *inside* another argument, and even if everything after a certain point gets discarded/truncated by the app |
| `$(cmd)` | Same as backticks, modern POSIX syntax | Same properties as above |
| `%0a` / `\n` (newline) | On some parsers, a raw newline alone is enough to start a new command line | Worth trying when semicolons/pipes get filtered/encoded |

### Related but distinct vulnerability classes (don't conflate these)

- **Argument injection** — no shell needed at all. The *target binary's own* argv parser treats attacker input starting with `-` as flags rather than data (e.g. `curl -o /tmp/x`, `tar --checkpoint-action=exec=...`, `git clone --upload-pack=...`). Mitigated with `--` (POSIX "end of options" marker), not by disabling the shell.
- **Code injection** — attacker input gets evaluated as code in the app's own language (e.g. Python `eval()`, PHP `eval()`), not passed to the OS at all.
- **Server-Side Template Injection (SSTI)** — attacker input evaluated inside a templating engine; can sometimes escalate *into* command injection depending on the engine.

---

## 3. Exploitation Logic (Methodology)

1. **Identify the sink** — find a parameter that plausibly feeds a shell-out call (diagnostic tools, report generators, file conversion, anything with a "legacy system" or "third-party tool" smell).
2. **Confirm injection with a harmless, observable command first.**
   - In-band: try `pwd`, `whoami`, `id`, `echo <marker>` appended with each operator (`;`, `|`, `&&`).
   - If nothing changes visibly, assume blind — move to time-based (`sleep 10`) or OOB (DNS/HTTP callback via Burp Collaborator).
3. **If a "safe" test binary silently fails** (e.g. `whoami` but not `pwd`) — suspect a restricted `PATH` in the subprocess environment, not "no injection." Retry with:
   - Absolute paths (`/usr/bin/whoami`)
   - Shell builtins (`pwd`, `echo`, `cd` — always available, no `PATH` lookup)
   - `echo $PATH` to inspect what's actually resolvable
4. **Escalate from proof-of-concept to impact** once injection is confirmed: read sensitive files, enumerate the environment, attempt a reverse shell, check for outbound network access.
5. **If characters are filtered/blocked**, try encoding or operator substitution:
   - URL-encode the operator (`%3b` for `;`)
   - Newline instead of semicolon
   - Backticks/`$()` if `;`/`|`/`&` are stripped but substitution isn't
   - Check if input length is truncated — favor short, high-impact payloads

---

## 4. Script Workflow (automation pattern)

For a Python-based test harness (consistent with the rest of the lab automation):
1. `requests.Session()` to hold cookies/CSRF state
2. A list of candidate operators × candidate test commands (`pwd`, `whoami`, `id`, `echo <unique-marker>`)
3. Send each payload as the vulnerable parameter, diff the response against a known-good baseline response
4. Flag any response containing the marker or unexpected new content (e.g. a Linux username, a file path) as a hit
5. For blind cases: measure response time against baseline, and/or trigger an OOB collaborator payload and poll for a hit

---

## 5. Why It Matters Generally

- Typically scored **Critical (CVSS 9-10)** — a working injection usually means arbitrary command execution **as the web server's OS user**, not just data disclosure.
- From there, common follow-on impact: reading credentials/config files, writing a webshell for persistence, pivoting into internal network segments the server can reach but the public internet can't.
- Real-world relevance is high because "shell out to reuse an existing tool" is a very common shortcut, not a rare anti-pattern:
  - **Shellshock (2014)** — a Bash parsing bug meant environment variables containing function definitions could smuggle in trailing shell commands; CGI scripts that copied HTTP headers into env vars were affected en masse.
  - **Router/IoT admin panels** — "ping this IP" / "traceroute" diagnostic features shelling out to system binaries with the IP field concatenated in, essentially the same shape as the PortSwigger stock-checker lab.
  - **ImageMagick "ImageTragick" (CVE-2016-3714)** — malicious filenames/metadata reaching shell-invoked delegate commands during image processing.
  - **CI/CD pipelines** — custom build-command fields are a frequent target since build servers often hold high-value credentials.

---

## 6. Remediation

Ranked by strength:
1. **Avoid shelling out entirely** — call the underlying library/API in-process instead of invoking a CLI tool via the OS.
2. **If a subprocess is unavoidable:** use APIs that take arguments as an **array**, with the shell disabled (Python: `subprocess.run([...], shell=False)`). This routes execution through `execve()` directly — no shell parser is present to interpret `;`, `|`, `&`, backticks as syntax at all.
3. **Strict input allowlisting** as defense-in-depth — e.g. `productID`/`storeID` should match `^\d+$`; reject anything else before it ever reaches the command layer.
4. **If passing user input as CLI flags/args to another program** (separate from shell injection): use `--` to mark "end of options" and prevent argument injection, since disabling the shell does *not* protect against a target binary's own argv parser.
5. **Least privilege**: run the process invoking external tools as a low-privilege OS user, so even a successful injection has limited blast radius.

---

## Appendix: Quick reference — operator behavior summary

| Operator | Runs 2nd command when... | Output timing | Best for |
|---|---|---|---|
| `;` | Always | Synchronous | General in-band testing |
| `\|` | Always (pipes stdout) | Synchronous | In-band, especially if original has no stdout of its own |
| `&&` | 1st command succeeds | Synchronous | Confirming exact success conditions |
| `\|\|` | 1st command fails | Synchronous | When you can force original to error |
| `&` | Always, but async | Unreliable/racy | Blind/OOB triggers, not in-band proof |
| `` ` ` `` / `$()` | Always, inline substitution | Synchronous, embedded in original output | Bypassing truncation/filtering, sneaking execution mid-string |