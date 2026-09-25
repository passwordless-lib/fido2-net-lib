# Conformance expectations ledger

The [FIDO conformance tool](https://fidoalliance.org/certification/functional-certification/conformance/)
passes a negative test whenever the server rejects the request. It never looks at *why*. A server that crashes
with a `NullReferenceException` before reaching the check the test targets passes exactly like one that runs the
check, so a 100% pass rate says less than it appears to.

This folder closes that gap for the demo server:

- The demo records every request to the four conformance endpoints when `conformance:trafficLog` names a file
  (see `Demo/ConformanceTrafficLog.cs`): the body, the response, and on rejection the exception type,
  `Fido2ErrorCode` and message, classified as `verified` (a coded library decision), `uncoded`, `rejected`
  (the endpoint refused a body that would not bind) or `crash`.
- `tests.json` lists the tool's suites and tests in the order it runs them, with the number of
  `/attestation/result` or `/assertion/result` requests each one issues.
- `expectations.json` pins, per test, the outcome, error code and message the library is expected to produce.
  Entries whose `note` explains that the test passes for a reason other than the one it states, or that the
  tool's own payload is broken, are the ones worth reading.
- `Ledger.cs` generates and checks the ledger. It is a single-file app; no project is needed.

## Nothing from the tool is in this repository

The conformance tool is licensed to the individual or organization who registers for it, under FIDO Alliance's
own End User License Agreement (shown on first launch, and bundled inside the tool's installer as
`END USER LICENSE AGREEMENT FOR FIDO ALLIANCE FUNCTIONAL CERTIFICATION TEST TOOLS.pdf`). That license is
non-transferable (§1.1); prohibits redistributing, sub-licensing, or otherwise letting a third party use the
tool (§2.2) or making derivative works of it (§2.4); and separately treats the tool and "any and all other
software, documentation or other information licensed to you by FIDO" as confidential for five years from
disclosure (§5.1, §5.3) -- a broader, standalone obligation, not just a copyright restriction.

**If you're running this yourself: register for the tool under your own name or organization, and don't hand
your `metadata.zip`, traffic logs, or the installer itself to anyone else -- including a teammate, even
informally.** Each person who needs it registers for their own copy.

This folder holds only what this library itself produces: its own error codes and messages (with the tool's
test values trimmed off), the request *shape* (attestation format and algorithm), and paraphrased one-line
descriptions of what each test probes. Suite and test identifiers are kept because the checker aligns by them.

Keep it that way. Traffic logs contain the tool's full request payloads and the metadata zip is the tool's;
`.gitignore` here excludes both, and a run should never be committed.

## Running the tool against the demo

Whoever runs the tool supplies its metadata statements: under **Tests configuration**, the **Download test
metadata** button saves a `metadata.zip`. Point `conformance:metadata` at that zip, or at a directory it was
unpacked into (subdirectories are searched, so unpacking it as-is is fine). Without it every attestation test
fails with `AaGuidNotFound`, and the demo says so at startup.

Run the demo where the tool can reach it over HTTPS, with the RP ID and origin set to that host. For example,
behind a tunnel that terminates TLS:

```sh
cd Demo/bin/Release/net10.0
ASPNETCORE_URLS=http://127.0.0.1:5000 ASPNETCORE_FORWARDEDHEADERS_ENABLED=true \
fido2__serverDomain=<host> fido2__origins__0=https://<host> \
conformance__metadata=<path to metadata.zip> conformance__trafficLog=<run>.jsonl \
dotnet Demo.dll
```

On Windows, PowerShell doesn't support that `VAR=value command` form -- set each one first, then run the command:

```powershell
cd Demo\bin\Release\net10.0
$env:ASPNETCORE_URLS = "http://127.0.0.1:5000"
$env:ASPNETCORE_FORWARDEDHEADERS_ENABLED = "true"
$env:fido2__serverDomain = "<host>"
$env:fido2__origins__0 = "https://<host>"
$env:conformance__metadata = "<path to metadata.zip>"
$env:conformance__trafficLog = "<run>.jsonl"
dotnet Demo.dll
```

`serverDomain` is the bare host only (`127.0.0.1`, or the tunnel's hostname) -- never a full URL with a scheme
or port. Setting it to something like `http://127.0.0.1:5000` makes the server compute the RP ID hash from that
whole string, which will never match the hash the browser computes from the actual host, and every ceremony
fails with `InvalidRpidHash`. `origins` is the one that takes the full URL (scheme and port included).

`ASPNETCORE_FORWARDEDHEADERS_ENABLED` and the tunnel are only needed if the tool can't reach `127.0.0.1`
directly -- testing purely on `localhost` (tool and demo on the same machine) needs neither; just point
`serverDomain`/`origins` at `127.0.0.1`/`http://127.0.0.1:5000` and skip the tunnel entirely.

At startup the demo prints how many statements it loaded and one line per conformance MDS BLOB it refused,
with the reason. The Server-MDS3 F-tests can only be judged from those lines: a refused BLOB leaves nothing for
the request log to see but `AaGuidNotFound`.

Then enter `https://<host>` as the server URL and run the server tests. The ledger was generated with every
suite and every optional algorithm selected; a run may select fewer (see below), but a run used to *generate*
must select everything.

## Checking a run

```sh
dotnet run conformance/Ledger.cs -- check <run>.jsonl
```

Every result request is compared with its ledger entry: outcome, code and message prefix must match one of the
entry's expectations. A test whose attestation format or algorithm differs from the ledger is reported as
drift. The exit code is non-zero on any mismatch or on result requests the ledger cannot account for.

**Selecting fewer tests.** Every suite, and every test behind an optional-algorithm checkbox, may be left out
of a run. The checker works out what was selected by finding the selection whose request shapes reproduce the
run, reports each suite or option as `NOT RUN`, and checks the rest. If more than one selection fits — or none,
because the tool itself changed — it says so and compares by position instead; `--without <suite id, group or
option name>` (as shown in the tool) settles it.

**The tool is not deterministic.** Some tests draw a random wrong-typed value each run (an object, an array,
a boolean, a number), and which layer rejects it depends on the draw; the MDS3 status test picks one of several
compromise statuses. The ledger records every reason seen as an alternative (`anyOf`), which is why it is
generated from several runs.

## Reading the output

This is what distinguishes a legitimate result from an accidental one -- the entire point of this tool. Two
entries from `expectations.json` as it stood when this was written, for a packed registration ceremony (the tool
itself changes every few days, so treat the specifics below -- test count included -- as illustrative rather
than current; see "When the tool changes" below). The total entry count also only means anything for a run with
every suite and option selected, per "Selecting fewer tests" above -- a run that left some out legitimately
checks fewer than the total, with a `NOT RUN` line for each one skipped:

```json
{
  "test": "Server-ServerAuthenticatorAttestationResponse-Resp-1 P-1",
  "description": "Valid packed registration; a second options request must list it in excludeCredentials",
  "request": { "path": "/attestation/result", "fmt": "packed", "alg": -7 },
  "outcome": "ok",
  "message": ""
},
{
  "test": "Server-ServerAuthenticatorAttestationResponse-Resp-1 F-1",
  "description": "\"id\" missing",
  "request": { "path": "/attestation/result", "fmt": "packed", "alg": -7 },
  "outcome": "verified",
  "code": "InvalidAttestationResponse",
  "message": "AttestationResponse Id is missing"
}
```

P-1 is a positive test: the tool expects (and the ledger pins) an `ok` outcome. F-1 is a negative test: the tool
only checks that the server rejected the request, but the ledger additionally pins *how* -- outcome `verified`
(a coded library decision, not a crash or a bind failure), code `InvalidAttestationResponse`, and a message that
starts with `AttestationResponse Id is missing`. That is what a legitimate pass for F-1 looks like.

Now suppose a code change accidentally made the library throw a `NullReferenceException` while checking `Id`,
before ever reaching the "is it missing" check F-1 targets. The conformance tool still sees a rejected request
and still scores F-1 as a pass. The traffic log would instead show `Outcome: "crash"` for that request, and
`check` catches exactly this:

```
MISMATCH #2 seq 2 Server-ServerAuthenticatorAttestationResponse-Resp-1 F-1: "id" missing
    got      crash/- 'Object reference not set to an instance of an object.'
    expected verified/InvalidAttestationResponse 'AttestationResponse Id is missing'…
M of N ledger entries checked against run.jsonl: 1 mismatch(es), 0 drift warning(s), 0 unmatched request(s)
```

A clean run against an unchanged library instead prints only the final summary line, with zero mismatches. M
equals N only if every suite and option was selected; run with fewer, and a `NOT RUN` line precedes the summary
for each one skipped, with M short of N by exactly that many:

```
M of N ledger entries checked against run.jsonl: 0 mismatch(es), 0 drift warning(s), 0 unmatched request(s)
```

The exit code is `0` only in that second case, so `check` is scriptable in CI: any `MISMATCH`, `DRIFT`, or
`COUNT` line means at least one test the tool called a "pass" was not legitimate, and is worth reading before
trusting the tool's own scorecard.

## When the tool changes

The tool and its metadata are updated without notice. The check reads the tool version from the run's
`User-Agent` and warns when it differs from the version the ledger was generated from; after that, read every
mismatch, drift and count report as a question about the tool first and the library second:

- **Count differs** — a test was added, removed or now issues a different number of requests. Update
  `tests.json` (the report names the first slot where the run and the test order part ways), then check again.
- **Drift** — a test now sends a different attestation format or algorithm. Confirm the alignment in
  `tests.json` is still right before believing any mismatch after that point.
- **Mismatch** — the library rejected something differently. Decide whether the library or the tool changed,
  and whether the new reason is the one the test states, before accepting it.

Once the differences are understood, regenerate from two or more complete runs:

```sh
dotnet run conformance/Ledger.cs -- generate <run-1>.jsonl <run-2>.jsonl
```

Generation copies whatever the runs did — including any test that passed for the wrong reason — so review the
diff before committing it. Reasons that differ between the runs become alternatives; `note` fields are carried
over by test id. Messages that embed run-specific values (JSON byte positions, the TPM magic the tool picks, the
RP's own origin, the status the tool drew) or the tool's own test values are trimmed to their stable prefix.
