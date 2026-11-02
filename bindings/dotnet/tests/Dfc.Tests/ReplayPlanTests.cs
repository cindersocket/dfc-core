namespace Dfc.Tests;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using Dfc.Credentials;
using Dfc.Emulation;
using NUnit.Framework;

/// <summary>
/// Replays every DESFire conformance vector through the .NET binding. The plans under
/// <c>tests/replay-plans</c> come from the C conformance runner (<c>make -C tests replay-plans</c>):
/// the initial credential in the library's own encoding, then explicit steps. The binding is held
/// to the same expectations as the C engine.
/// </summary>
[TestFixture]
public sealed class ReplayPlanTests
{
    [Test]
    public void VectorReplayPlansMatchTheCEngine()
    {
        var directory = Path.Combine(AppContext.BaseDirectory, "replay-plans");
        var plans = Directory.GetFiles(directory, "*.plan").Order(StringComparer.Ordinal).Select(Plan.Parse).ToList();
        Assert.That(plans, Is.Not.Empty, "no replay plans found; run make -C tests replay-plans");

        var failures = new List<string>();
        var skipped = new SortedDictionary<string, List<string>>(StringComparer.Ordinal);
        int replayed = 0, checkedAsserts = 0, uncheckedAsserts = 0;
        foreach (var plan in plans)
        {
            if (plan.Skip is not null)
            {
                if (!skipped.TryGetValue(plan.Skip, out var names))
                {
                    skipped[plan.Skip] = names = [];
                }

                names.Add(plan.Name);
                continue;
            }

            var outcome = Replay(plan);
            failures.AddRange(outcome.Failures);
            replayed++;
            checkedAsserts += outcome.Checked;
            uncheckedAsserts += outcome.Unchecked;
        }

        TestContext.Progress.WriteLine(
            $"dotnet replay: {replayed} vectors replayed, {skipped.Values.Sum(names => names.Count)} skipped, "
            + $"{failures.Count} failures; {checkedAsserts} assertions evaluated, "
            + $"{uncheckedAsserts} left to the final credential comparison");
        foreach (var (reason, names) in skipped)
        {
            TestContext.Progress.WriteLine($"  skipped {names.Count}: {reason}: {string.Join(", ", names)}");
        }

        Assert.That(failures, Is.Empty, () => string.Join('\n', failures.Take(20)));

        // Exactly these plans are skipped (the plan files carry the reason), and every other plan
        // is replayed: a regression that skips more would otherwise pass.
        string[] expectedSkips = ["v4-emulator-model_key_set_invariants", "v4-emulator-model_sdm_encrypted_range_overflow", "v4-emulator-vecb-ev1-create-file-full-pool"];
        Assert.That(skipped.Values.SelectMany(names => names).Order(StringComparer.Ordinal), Is.EqualTo(expectedSkips));
        Assert.That(replayed, Is.EqualTo(plans.Count - expectedSkips.Length));
    }

    private static (List<string> Failures, int Checked, int Unchecked) Replay(Plan plan)
    {
        var failures = new List<string>();
        int checkedAsserts = 0, uncheckedAsserts = 0;
        var queue = new DfcScriptedRandomSource(ReadOnlyMemory<byte>.Empty);
        var credential = Fixtures.Ok(DfcCredentialCodec.Decode(plan.Credential));
        using var picc = Fixtures.Ok(
            DfcVirtualPicc.Create(credential, plan.FiniteRandom ? queue : null));
        DfcActivation? activation = null;
        for (var index = 0; index < plan.Steps.Count; index++)
        {
            var step = plan.Steps[index];
            var where = $"{plan.Name} step {index + 1} ({step[0]})";
            var args = step.Skip(1).ToArray();
            switch (step[0])
            {
                case "scan":
                    {
                        var result = picc.Activate();
                        if (result.IsFailure)
                        {
                            failures.Add($"{where}: {result.Error}");
                        }
                        else
                        {
                            activation = result.Value;
                        }

                        break;
                    }

                case "field-off":
                    picc.FieldOff();
                    activation = null;
                    break;
                case "clear-dirty":
                    picc.MarkPersisted();
                    break;
                case "random-clear":
                    queue.Clear();
                    break;
                case "random-inject":
                    queue.Append(Plan.Hex(args[0]));
                    break;
                case "advance-time":
                    picc.AdvanceTime(TimeSpan.FromMilliseconds(ulong.Parse(args[0], CultureInfo.InvariantCulture)));
                    break;
                case "exchange":
                case "frame":
                    {
                        var request = Plan.Hex(args[0]);
                        var result = step[0] == "exchange" ? picc.Exchange(request) : picc.ExchangeFrame(request);
                        if (result.IsFailure)
                        {
                            failures.Add($"{where}: {result.Error}");
                        }
                        else if (!Plan.Matches(result.Value, args[1], args[2..]))
                        {
                            failures.Add($"{where}: expected {args[1]} got {Convert.ToHexString(result.Value)}");
                        }

                        break;
                    }

                case "error":
                    {
                        var random = args[0] == "random-source";
                        var before = queue.Remaining;
                        var error = args[1] switch
                        {
                            "scan" => ActivationFailure(picc),
                            "exchange" => FailureOf(picc.Exchange(Plan.Hex(args[2]))),
                            _ => FailureOf(picc.ExchangeFrame(Plan.Hex(args[2]))),
                        };
                        if (error is null)
                        {
                            failures.Add($"{where}: expected an error");
                        }
                        else if ((error.Kind == DfcProtocolErrorKind.RandomSource) != random)
                        {
                            failures.Add($"{where}: wrong error class {error}");
                        }

                        if (random && queue.Remaining != before)
                        {
                            failures.Add($"{where}: failed draw consumed random bytes");
                        }

                        if (random && args[1] == "scan")
                        {
                            activation = null;
                        }

                        break;
                    }

                case "assert":
                    {
                        var (path, value) = (args[0], args[1]);
                        if (path == "credential.dirty")
                        {
                            checkedAsserts++;
                            if (picc.IsDirty != (value != "0"))
                            {
                                failures.Add($"{where}: {path} expected {value}");
                            }
                        }
                        else if (path.StartsWith("activation.", StringComparison.Ordinal) && activation is not null)
                        {
                            checkedAsserts++;
                            string actual = path["activation.".Length..] switch
                            {
                                "uid" => Convert.ToHexString(activation.Uid),
                                "atqa" => Convert.ToHexString(activation.Atqa),
                                "ats" => Convert.ToHexString(activation.Ats),
                                "uid_len" => activation.Uid.Length.ToString(CultureInfo.InvariantCulture),
                                "sak" => activation.Sak.ToString(CultureInfo.InvariantCulture),
                                _ => "unsupported",
                            };
                            var want = path.EndsWith("uid_len", StringComparison.Ordinal) || path.EndsWith("sak", StringComparison.Ordinal)
                                ? Convert.ToInt64(value, value.StartsWith("0x", StringComparison.Ordinal) ? 16 : 10).ToString(CultureInfo.InvariantCulture)
                                : value;
                            if (!string.Equals(actual, want, StringComparison.OrdinalIgnoreCase))
                            {
                                failures.Add($"{where}: {path} expected {value} got {actual}");
                            }
                        }
                        else
                        {
                            uncheckedAsserts++;
                        }

                        break;
                    }

                default:
                    failures.Add($"{where}: unknown plan step");
                    break;
            }
        }

        var exported = DfcCredentialCodec.Encode(picc.ExportCredential());
        if (exported.IsFailure || !exported.Value.AsSpan().SequenceEqual(plan.Final))
        {
            failures.Add($"{plan.Name}: final credential differs from the C engine");
        }

        return (failures, checkedAsserts, uncheckedAsserts);
    }

    private static DfcProtocolError? ActivationFailure(DfcVirtualPicc picc)
    {
        var result = picc.Activate();
        return result.IsFailure ? result.Error : null;
    }

    private static DfcProtocolError? FailureOf(CSharpFunctionalExtensions.Result<byte[], DfcProtocolError> result) =>
        result.IsFailure ? result.Error : null;

    private sealed class Plan
    {
        public string Name { get; private init; } = string.Empty;

        public byte[] Credential { get; private set; } = [];

        public bool FiniteRandom { get; private set; }

        public string? Skip { get; private set; }

        public List<string[]> Steps { get; } = [];

        public byte[] Final { get; private set; } = [];

        public static byte[] Hex(string text) => text == "-" ? [] : Convert.FromHexString(text);

        public static Plan Parse(string path)
        {
            var plan = new Plan { Name = Path.GetFileNameWithoutExtension(path) };
            foreach (var line in File.ReadAllLines(path))
            {
                var split = line.IndexOf(' ', StringComparison.Ordinal);
                var (key, rest) = split < 0 ? (line, string.Empty) : (line[..split], line[(split + 1)..]);
                switch (key)
                {
                    case "credential":
                        plan.Credential = Hex(rest);
                        break;
                    case "random":
                        plan.FiniteRandom = rest == "finite";
                        break;
                    case "skip":
                        plan.Skip = rest;
                        break;
                    case "step":
                        plan.Steps.Add(rest.Split(' '));
                        break;
                    case "final":
                        plan.Final = Hex(rest);
                        break;
                    case "plan" or "source":
                        break;
                    default:
                        throw new InvalidDataException($"{plan.Name}: unknown plan line '{line}'");
                }
            }

            return plan;
        }

        /// <summary>Compares with ?? wildcards and tol=offset+length:delta clauses.</summary>
        public static bool Matches(byte[] actual, string expected, string[] tolerances)
        {
            var want = expected == "-" ? [] : Enumerable.Range(0, expected.Length / 2).Select(i => expected.Substring(2 * i, 2)).ToArray();
            if (actual.Length != want.Length)
            {
                return false;
            }

            var ranges = tolerances.Select(clause =>
            {
                var parts = clause["tol=".Length..].Split('+', ':');
                return (Offset: int.Parse(parts[0], CultureInfo.InvariantCulture), Length: int.Parse(parts[1], CultureInfo.InvariantCulture), Delta: ulong.Parse(parts[2], CultureInfo.InvariantCulture));
            }).ToList();
            for (var index = 0; index < want.Length; index++)
            {
                var tolerated = ranges.Any(r => index >= r.Offset && index < r.Offset + r.Length);
                if (!tolerated && want[index] != "??" && actual[index] != Convert.ToByte(want[index], 16))
                {
                    return false;
                }
            }

            return ranges.All(r =>
            {
                var got = LittleEndian(actual.AsSpan(r.Offset, r.Length));
                var expect = LittleEndian(Hex(expected.Substring(2 * r.Offset, 2 * r.Length)));
                return (got > expect ? got - expect : expect - got) <= r.Delta;
            });
        }

        private static ulong LittleEndian(ReadOnlySpan<byte> bytes)
        {
            ulong value = 0;
            for (var i = bytes.Length - 1; i >= 0; i--)
            {
                value = (value << 8) | bytes[i];
            }

            return value;
        }
    }
}
