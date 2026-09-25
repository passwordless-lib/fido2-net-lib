#:property PublishAot=false
#:property Nullable=enable
#:package System.Formats.Cbor

// Expectations ledger for the FIDO conformance tool.
//
// The tool passes any negative test the server rejects, whatever the reason. The demo's conformance traffic log
// (conformance:trafficLog) records the reason for every rejection; this tool pins those reasons down per test.
//
//   dotnet run conformance/Ledger.cs -- generate <run.jsonl>...             writes conformance/expectations.json
//   dotnet run conformance/Ledger.cs -- check <run.jsonl> [--without <unit>]...   diffs a run against it
//
// The tool runs its tests sequentially and in a fixed order, so a run is aligned to tests.json by position. Every
// suite and every optional-algorithm test can be left unselected in the tool, so the check first works out which
// were run: it searches for the selection whose expected request shapes (path, attestation format, algorithm)
// reproduce the run exactly. --without names a suite id, group or option to rule out when that is ambiguous.
//
// Some tests draw a random wrong-typed value each run, and which layer rejects it depends on the draw; generating
// from several runs records every reason seen as an alternative. Generation copies whatever the runs did, so
// review the diff before committing it: a test that passed for the wrong reason is still a pass to the tool, and
// the ledger is where that gets caught.

using System.Formats.Cbor;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

var (command, logPaths, without, expectationsPath) = ParseArgs(args);
if (command is null)
{
    Console.Error.WriteLine("usage: dotnet run conformance/Ledger.cs -- generate <run.jsonl>... | check <run.jsonl> [--without <suite|group|option>]... [--expectations <file>]");
    return 2;
}

string testsPath = Locate("tests.json");
var slots = ReadSlots(testsPath);

return command == "generate" ? Generate() : Check();

int Generate()
{
    var runs = logPaths.Select(ReadResults).ToList();

    foreach (var (path, run) in logPaths.Zip(runs))
    {
        if (run.Results.Count != slots.Count)
        {
            Console.Error.WriteLine($"{path} has {run.Results.Count} result requests but {testsPath} expects {slots.Count}. Generate from runs with every suite and option selected; nothing was written.");
            ReportFirstDivergence(run.Results);
            return 1;
        }
    }

    // Notes are written by hand after review; keep them across regenerations (read loosely, so an older ledger layout still yields them)
    var previousNotes = new Dictionary<string, string>();
    if (File.Exists(expectationsPath) && JsonNode.Parse(File.ReadAllText(expectationsPath))?["entries"] is JsonArray previous)
    {
        foreach (var entry in previous)
        {
            if (entry?["test"]?.GetValue<string>() is { } test && entry["note"]?.GetValue<string>() is { } note)
                previousNotes[test] = note;
        }
    }

    var entries = new List<Entry>(slots.Count);

    for (int i = 0; i < slots.Count; i++)
    {
        var slot = slots[i];
        var shape = runs[0].Results[i].Request;

        foreach (var (path, run) in logPaths.Zip(runs).Skip(1))
        {
            if (!SameShape(run.Results[i].Request, shape))
                Console.WriteLine($"WARNING  {slot.Key}: {Path.GetFileName(path)} sent fmt={run.Results[i].Request.Fmt ?? "-"} alg={run.Results[i].Request.Alg?.ToString() ?? "-"} where {Path.GetFileName(logPaths[0])} sent fmt={shape.Fmt ?? "-"} alg={shape.Alg?.ToString() ?? "-"}; the first is recorded");
        }

        var seen = runs
            .Select(run => new Expectation { Outcome = run.Results[i].Outcome, Code = run.Results[i].Code, Message = run.Results[i].Message is null ? null : StablePrefix(run.Results[i].Message!) })
            .DistinctBy(e => (e.Outcome, e.Code, e.Message))
            .ToList();

        var entry = new Entry { Test = slot.Key, Description = slot.Description, Request = shape, Note = previousNotes.GetValueOrDefault(slot.Key) };

        if (seen.Count == 1)
            (entry.Outcome, entry.Code, entry.Message) = (seen[0].Outcome, seen[0].Code, seen[0].Message);
        else
            entry.AnyOf = seen;

        entries.Add(entry);
    }

    var ledger = new Ledger
    {
        Tool = runs.Select(run => run.Tool).FirstOrDefault(t => t is not null),
        GeneratedFrom = logPaths.Select(Path.GetFileName).ToList()!,
        Entries = entries
    };

    File.WriteAllText(expectationsPath, JsonSerializer.Serialize(ledger, LedgerJson()) + Environment.NewLine);
    Console.WriteLine($"wrote {entries.Count} expectations to {expectationsPath} from {runs.Count} run(s); {entries.Count(e => e.AnyOf is not null)} carry alternatives");
    return 0;
}

int Check()
{
    var ledger = ReadLedger(expectationsPath);
    var (results, tool) = ReadResults(logPaths[0]);

    if (ledger.Entries.Count != slots.Count)
    {
        Console.Error.WriteLine($"{expectationsPath} has {ledger.Entries.Count} entries but {testsPath} has {slots.Count} result slots; regenerate the ledger after changing tests.json.");
        return 2;
    }

    // The tool and its metadata change without notice; a different version is the first thing to suspect
    if (tool is not null && ledger.Tool is not null && tool != ledger.Tool)
        Console.WriteLine($"TOOL     this run is {tool}; the ledger was generated from {ledger.Tool}. Review every difference below with that in mind and regenerate once they are understood.");

    var alignments = Align(ledger.Entries, results, without);
    int[] mapping;

    if (alignments.Count == 1)
    {
        mapping = alignments[0];
        bool ran(int i) => mapping[i] >= 0;
        var absent = slots.SelectMany(s => s.Units).Distinct()
            .Where(unit => Enumerable.Range(0, slots.Count).All(i => !slots[i].Units.Contains(unit) || !ran(i)))
            // an option whose suite did not run at all is moot, not "not run"
            .Where(unit => slots.Any(s => s.Suite == unit) || Enumerable.Range(0, slots.Count).Any(i => slots[i].Option == unit && slots.Where((s, j) => s.Suite == slots[i].Suite && ran(j)).Any()))
            .ToList();
        foreach (var unit in absent)
        {
            var suiteOption = slots.FirstOrDefault(s => s.Suite == unit && s.SuiteOption is not null)?.SuiteOption;
            Console.WriteLine($"NOT RUN  {unit}{(suiteOption is not null ? $" ({suiteOption})" : "")}");
        }
    }
    else
    {
        Console.WriteLine(alignments.Count == 0
            ? "ALIGN    no selection of suites and options reproduces this run's request shapes; comparing by position as if everything was selected. A count or drift report below marks where the run and the test order part ways."
            : $"ALIGN    {alignments.Count}+ selections reproduce this run's request shapes; comparing by position. Pass --without <suite|group|option> for what was not selected.");
        mapping = Enumerable.Range(0, slots.Count).Select(i => i < results.Count ? i : -1).ToArray();
    }

    int checkedCount = 0, mismatches = 0, drift = 0;

    for (int i = 0; i < slots.Count; i++)
    {
        if (mapping[i] < 0)
            continue;

        var expected = ledger.Entries[i];
        var actual = results[mapping[i]];
        checkedCount++;

        var acceptable = expected.AnyOf ?? [new Expectation { Outcome = expected.Outcome!, Code = expected.Code, Message = expected.Message }];

        if (!acceptable.Any(e => Matches(e, actual)))
        {
            mismatches++;
            Console.WriteLine($"MISMATCH #{i + 1} seq {actual.Sequence} {expected.Test}: {expected.Description}");
            Console.WriteLine($"    got      {Describe(actual.Outcome, actual.Code, actual.Message)}");
            foreach (var e in acceptable)
                Console.WriteLine($"    expected {Describe(e.Outcome, e.Code, e.Message)}{(e.Message is not null ? "…" : "")}");
        }

        if (!SameShape(actual.Request, expected.Request))
        {
            drift++;
            Console.WriteLine($"DRIFT    #{i + 1} seq {actual.Sequence} {expected.Test}: request is {actual.Request.Path} fmt={actual.Request.Fmt ?? "-"} alg={actual.Request.Alg?.ToString() ?? "-"}, ledger has {expected.Request.Path} fmt={expected.Request.Fmt ?? "-"} alg={expected.Request.Alg?.ToString() ?? "-"}");
        }
    }

    int unmatched = results.Count - mapping.Count(m => m >= 0);
    if (unmatched > 0)
    {
        Console.WriteLine($"COUNT    {unmatched} result request(s) in the run have no ledger entry");
        if (alignments.Count != 1)
            ReportFirstDivergence(results);
    }

    Console.WriteLine($"{checkedCount} of {slots.Count} ledger entries checked against {Path.GetFileName(logPaths[0])}: {mismatches} mismatch(es), {drift} drift warning(s), {unmatched} unmatched request(s)");
    return mismatches == 0 && unmatched == 0 ? 0 : 1;
}

// Every way of choosing which suites and options were selected that makes the ledger's request shapes reproduce
// the run, at most two of them (one means the selection is known; two means it is ambiguous).
List<int[]> Align(List<Entry> entries, List<Result> results, HashSet<string> without)
{
    var solutions = new List<int[]>();
    var decisions = new Dictionary<string, bool>();

    // --without names a suite, a group of suites, or an option; each rules out the units it covers
    foreach (var name in without)
    {
        bool known = false;
        foreach (var slot in slots.Where(s => s.Uses(name)))
        {
            decisions[name == slot.Option ? slot.Option : slot.Suite] = false;
            known = true;
        }
        if (!known)
            Console.WriteLine($"WARNING  --without {name}: no suite, group or option in {testsPath} has that name");
    }
    var mapping = new int[slots.Count];
    var deadEnds = new HashSet<(int, int, string)>();

    Search(0, 0);
    return solutions;

    void Search(int slotIndex, int resultIndex)
    {
        if (solutions.Count >= 2)
            return;

        if (slotIndex == slots.Count)
        {
            if (resultIndex == results.Count)
                solutions.Add((int[])mapping.Clone());
            return;
        }

        var slot = slots[slotIndex];
        Decide(slot, 0, slotIndex, resultIndex);
    }

    // Decide the units a slot depends on, suite first and "selected" first. An option is only decided once its
    // suite is known to have run; for a suite that did not, the option is moot and must not multiply solutions.
    void Decide(Slot slot, int unitIndex, int slotIndex, int resultIndex)
    {
        var units = slot.Units.ToList();

        if (unitIndex == units.Count)
        {
            Advance(slot, slotIndex, resultIndex);
            return;
        }

        string unit = units[unitIndex];

        if (decisions.ContainsKey(unit) || (unitIndex > 0 && !decisions[slot.Suite]))
        {
            Decide(slot, unitIndex + 1, slotIndex, resultIndex);
            return;
        }

        foreach (bool selected in new[] { true, false })
        {
            decisions[unit] = selected;
            Decide(slot, unitIndex + 1, slotIndex, resultIndex);
            decisions.Remove(unit);
        }
    }

    void Advance(Slot slot, int slotIndex, int resultIndex)
    {
        var key = (slotIndex, resultIndex, string.Join(",", decisions.OrderBy(d => d.Key).Select(d => d.Key + "=" + d.Value)));
        if (deadEnds.Contains(key))
            return;

        int before = solutions.Count;
        bool present = decisions[slot.Suite] && (slot.Option is null || decisions[slot.Option]);

        if (present)
        {
            if (resultIndex < results.Count && SameShape(results[resultIndex].Request, entries[slotIndex].Request))
            {
                mapping[slotIndex] = resultIndex;
                Search(slotIndex + 1, resultIndex + 1);
            }
        }
        else
        {
            mapping[slotIndex] = -1;
            Search(slotIndex + 1, resultIndex);
        }

        if (solutions.Count == before)
            deadEnds.Add(key);
    }
}

void ReportFirstDivergence(List<Result> results)
{
    for (int i = 0; i < Math.Min(slots.Count, results.Count); i++)
    {
        if (results[i].Request.Path != slots[i].Path)
        {
            Console.WriteLine($"    first divergence at #{i + 1} (seq {results[i].Sequence}): run has {results[i].Request.Path}, {slots[i].Key} expects {slots[i].Path}");
            return;
        }
    }
}

static bool Matches(Expectation expected, Result actual)
{
    return actual.Outcome == expected.Outcome
        && actual.Code == expected.Code
        && (expected.Message is null || (actual.Message ?? "").StartsWith(expected.Message, StringComparison.Ordinal));
}

static bool SameShape(RequestShape a, RequestShape b)
{
    return a.Path == b.Path && a.Fmt == b.Fmt && a.Alg == b.Alg;
}

static string Describe(string outcome, string? code, string? message)
{
    return $"{outcome}/{code ?? "-"} '{message}'";
}

static (string? Command, List<string> Logs, HashSet<string> Without, string Expectations) ParseArgs(string[] args)
{
    var logs = new List<string>();
    var without = new HashSet<string>();
    string? expectations = null;
    string? command = args.Length > 0 && args[0] is "generate" or "check" ? args[0] : null;

    for (int i = 1; i < args.Length; i++)
    {
        if (args[i] == "--without" && i + 1 < args.Length)
            without.Add(args[++i]);
        else if (args[i] == "--expectations" && i + 1 < args.Length)
            expectations = args[++i];
        else
            logs.Add(args[i]);
    }

    if (logs.Count == 0 || (command == "check" && logs.Count != 1))
        command = null;

    return (command, logs, without, expectations ?? Locate("expectations.json"));
}

static string Locate(string name)
{
    // Relative to the repository root when run from there, or to the directory this file lives in
    foreach (var candidate in new[] { Path.Combine("conformance", name), name })
    {
        if (File.Exists(candidate))
            return candidate;
    }
    return Path.Combine("conformance", name);
}

// Messages that embed values which change from run to run are pinned by the part that stays the same. Values the
// tool chose (its bad origins, its stand-in type strings, its random magic, the status it picked) are cut as
// well: the ledger must not carry any of the tool's material.
static string StablePrefix(string message)
{
    foreach (var (marker, keepMarker) in new[]
    {
        (" | LineNumber", false),           // System.Text.Json: byte positions move with the payload
        ("Bad magic number ", true),        // the tool picks the bad magic at random
        ("Fully qualified origin ", true),  // the tool's origin, then the RP's own
        (". Was '", true),                  // the tool's stand-in for a wrong type or format
        ("undesirable status. Was ", true), // one of several compromise statuses, drawn per run
        (" but found ", true),              // Base64UrlConverter names the JSON token the tool drew
    })
    {
        int at = message.IndexOf(marker, StringComparison.Ordinal);
        if (at >= 0)
            return message[..(keepMarker ? at + marker.Length : at)];
    }
    return message;
}

static List<Slot> ReadSlots(string path)
{
    var doc = JsonNode.Parse(File.ReadAllText(path))!;
    var slots = new List<Slot>();

    foreach (var suite in doc["suites"]!.AsArray())
    {
        string suiteId = suite!["id"]!.GetValue<string>();
        string group = suite["group"]!.GetValue<string>();
        string? suiteOption = suite["option"]?.GetValue<string>();

        foreach (var test in suite["tests"]!.AsArray())
        {
            int count = test!["results"]!.GetValue<int>();
            string testId = test["id"]!.GetValue<string>();
            string description = test["description"]!.GetValue<string>();
            string? option = test["option"]?.GetValue<string>();

            for (int n = 1; n <= count; n++)
            {
                string key = $"{suiteId} {testId}" + (count > 1 ? $" ({n}/{count})" : "");
                // A setup entry is a registration; an assertion suite's own tests register first and assert last
                bool asserts = testId != "setup" && suiteId.Contains("Assertion") && n == count;
                slots.Add(new Slot(key, description, asserts ? "/assertion/result" : "/attestation/result", suiteId, group, option, suiteOption));
            }
        }
    }

    return slots;
}

static (List<Result> Results, string? Tool) ReadResults(string path)
{
    var results = new List<Result>();
    string? tool = null;

    foreach (var line in File.ReadLines(path))
    {
        if (string.IsNullOrWhiteSpace(line))
            continue;

        var record = JsonNode.Parse(line)!;
        string requestPath = record["Path"]!.GetValue<string>();

        // e.g. "... fido-conformance-tools-electron/1.9.1 Chrome/..." — the product token is all that identifies the tool version
        if (tool is null && record["UserAgent"]?.GetValue<string>() is { } userAgent)
            tool = Regex.Match(userAgent, @"fido-conformance-tools\S*/[\w.]+").Value is { Length: > 0 } token ? token : null;

        if (!requestPath.EndsWith("/result", StringComparison.Ordinal))
            continue;

        var (fmt, alg) = Fingerprint(record["Request"]);

        results.Add(new Result(
            record["Sequence"]!.GetValue<int>(),
            new RequestShape { Path = requestPath, Fmt = fmt, Alg = alg },
            record["Outcome"]!.GetValue<string>(),
            record["ErrorCode"]?.GetValue<string>(),
            record["ErrorMessage"]?.GetValue<string>()));
    }

    return (results, tool);
}

// fmt and attStmt.alg of an attestation object, tolerant of every malformation the tool sends
static (string? Fmt, long? Alg) Fingerprint(JsonNode? request)
{
    // The structure tests send every wrong shape here: a string for the body, a string for response, a number for attestationObject
    if (request is not JsonObject body || body["response"] is not JsonObject response || response["attestationObject"] is not JsonValue value
        || !value.TryGetValue(out string? encoded) || string.IsNullOrEmpty(encoded))
        return (null, null);

    try
    {
        var reader = new CborReader(Convert.FromBase64String(encoded.Replace('-', '+').Replace('_', '/').PadRight((encoded.Length + 3) / 4 * 4, '=')), CborConformanceMode.Lax);
        string? fmt = null;
        long? alg = null;

        reader.ReadStartMap();
        while (reader.PeekState() != CborReaderState.EndMap)
        {
            string key = reader.ReadTextString();

            if (key == "fmt" && reader.PeekState() == CborReaderState.TextString)
                fmt = reader.ReadTextString();
            else if (key == "attStmt" && reader.PeekState() == CborReaderState.StartMap)
            {
                reader.ReadStartMap();
                while (reader.PeekState() != CborReaderState.EndMap)
                {
                    string statementKey = reader.PeekState() == CborReaderState.TextString ? reader.ReadTextString() : SkipAndName(reader);

                    if (statementKey == "alg" && reader.PeekState() is CborReaderState.NegativeInteger or CborReaderState.UnsignedInteger)
                        alg = reader.ReadInt64();
                    else
                        reader.SkipValue();
                }
                reader.ReadEndMap();
            }
            else
                reader.SkipValue();
        }

        return (fmt, alg);
    }
    catch (Exception e) when (e is CborContentException or FormatException or InvalidOperationException)
    {
        return ("<unparseable>", null);
    }

    static string SkipAndName(CborReader reader)
    {
        reader.SkipValue();
        return "<non-text key>";
    }
}

static Ledger ReadLedger(string path)
{
    return JsonSerializer.Deserialize<Ledger>(File.ReadAllText(path), LedgerJson())!;
}

static JsonSerializerOptions LedgerJson() => new()
{
    WriteIndented = true,
    DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
};

sealed class Ledger
{
    public string? Tool { get; set; }
    public List<string>? GeneratedFrom { get; set; }
    public List<Entry> Entries { get; set; } = [];
}

sealed class Entry
{
    public required string Test { get; set; }
    public required string Description { get; set; }
    public required RequestShape Request { get; set; }
    public string? Outcome { get; set; }
    public string? Code { get; set; }
    public string? Message { get; set; }
    public List<Expectation>? AnyOf { get; set; }
    public string? Note { get; set; }
}

sealed class Expectation
{
    public required string Outcome { get; set; }
    public string? Code { get; set; }
    public string? Message { get; set; }
}

sealed class RequestShape
{
    public required string Path { get; set; }
    public string? Fmt { get; set; }
    public long? Alg { get; set; }
}

// Option is an optional-algorithm checkbox that gates this one test; SuiteOption is one that gates the whole suite,
// which cannot be told apart from the suite's own checkbox in a run, so it is not a unit of its own.
sealed record Slot(string Key, string Description, string Path, string Suite, string Group, string? Option, string? SuiteOption)
{
    // A slot runs only if its suite and its test-level option, if any, were selected
    public IEnumerable<string> Units => Option is null ? [Suite] : [Suite, Option];

    public bool Uses(string name) => name == Suite || name == Group || name == Option || name == SuiteOption;
}

sealed record Result(int Sequence, RequestShape Request, string Outcome, string? Code, string? Message);
