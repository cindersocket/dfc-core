namespace Dfc.Tests;

using System;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using Dfc.Credentials;
using Dfc.Emulation;
using Dfc.Reader;
using NUnit.Framework;

[TestFixture]
public sealed class PiccBehaviorTests
{
    [Test]
    public void Dispose_IsIdempotent_WithoutReleasingOtherCallbackRoots()
    {
        var picc = Fixtures.Picc(
            Fixtures.Credential(),
            new DfcScriptedRandomSource(ReadOnlyMemory<byte>.Empty)
        );
        picc.Dispose();

        var targets = new object[4096];
        var roots = new GCHandle[targets.Length];
        try
        {
            for (var i = 0; i < targets.Length; i++)
            {
                targets[i] = new object();
                roots[i] = GCHandle.Alloc(targets[i]);
            }

            Assert.DoesNotThrow(picc.Dispose);
            Assert.Multiple(() =>
            {
                for (var i = 0; i < targets.Length; i++)
                {
                    Assert.That(roots[i].Target, Is.SameAs(targets[i]), $"callback root {i}");
                }
            });
        }
        finally
        {
            foreach (var root in roots)
            {
                if (root.IsAllocated)
                {
                    root.Free();
                }
            }
        }
    }

    [Test]
    public void DisposedCalls_ReportThePublicTypeName()
    {
        var picc = Fixtures.Picc(Fixtures.Credential());
        picc.Dispose();

        (string Name, Action Call)[] calls =
        [
            (nameof(DfcVirtualPicc.Activate), () => _ = picc.Activate()),
            (nameof(DfcVirtualPicc.Exchange), () => _ = picc.Exchange(ReadOnlySpan<byte>.Empty)),
            (nameof(DfcVirtualPicc.ExchangeFrame), () => _ = picc.ExchangeFrame(ReadOnlySpan<byte>.Empty)),
            (
                nameof(DfcVirtualPicc.TransmitAsync),
                () => _ = picc.TransmitAsync(ReadOnlyMemory<byte>.Empty, CancellationToken.None)
            ),
            (nameof(DfcVirtualPicc.FieldOff), picc.FieldOff),
            (nameof(DfcVirtualPicc.ResetProtocol), picc.ResetProtocol),
            (nameof(DfcVirtualPicc.AdvanceTime), () => picc.AdvanceTime(TimeSpan.Zero)),
            (nameof(DfcVirtualPicc.Snapshot), () => _ = picc.Snapshot()),
            (nameof(DfcVirtualPicc.IsDirty), () => _ = picc.IsDirty),
            (nameof(DfcVirtualPicc.ExportCredential), () => _ = picc.ExportCredential()),
            (nameof(DfcVirtualPicc.MarkPersisted), picc.MarkPersisted),
        ];

        Assert.Multiple(() =>
        {
            foreach (var (name, call) in calls)
            {
                var exception = Assert.Throws<ObjectDisposedException>(() => call(), name);
                Assert.That(exception!.ObjectName, Is.EqualTo(nameof(DfcVirtualPicc)), name);
            }
        });
    }

    [Test]
    public async Task Dispose_WaitsForInFlightNativeCallback()
    {
        var random = new BlockingRandomSource();
        var picc = Fixtures.Picc(Fixtures.Credential(), random);
        Fixtures.Ok(picc.Activate());

        var exchange = Task.Run(() => picc.Exchange(Hex("901A0000010000")));
        Assert.That(random.Entered.Wait(TimeSpan.FromSeconds(5)), Is.True);

        using var disposeStarted = new ManualResetEventSlim();
        var dispose = Task.Factory.StartNew(
            () =>
            {
                disposeStarted.Set();
                picc.Dispose();
            },
            CancellationToken.None,
            TaskCreationOptions.LongRunning,
            TaskScheduler.Default
        );
        Assert.That(disposeStarted.Wait(TimeSpan.FromSeconds(5)), Is.True);

        var disposedDuringCallback = dispose.Wait(TimeSpan.FromMilliseconds(250));
        random.Continue.Set();
        await Task.WhenAll(exchange, dispose);

        Assert.Multiple(() =>
        {
            Assert.That(disposedDuringCallback, Is.False);
            Assert.DoesNotThrow(picc.Dispose);
            var exception = Assert.Throws<ObjectDisposedException>(() => picc.Snapshot());
            Assert.That(exception!.ObjectName, Is.EqualTo(nameof(DfcVirtualPicc)));
        });
    }

    [Test]
    public async Task ConcurrentCallAndDispose_UseThePublicTypeNameWhenDisposeWins()
    {
        for (var iteration = 0; iteration < 64; iteration++)
        {
            var picc = Fixtures.Picc(Fixtures.Credential());
            using var start = new ManualResetEventSlim();
            ObjectDisposedException? observed = null;
            var call = Task.Run(() =>
            {
                start.Wait();
                try
                {
                    _ = picc.Snapshot();
                }
                catch (ObjectDisposedException exception)
                {
                    observed = exception;
                }
            });
            var dispose = Task.Run(() =>
            {
                start.Wait();
                picc.Dispose();
            });

            start.Set();
            await Task.WhenAll(call, dispose);

            if (observed is not null)
            {
                Assert.That(observed.ObjectName, Is.EqualTo(nameof(DfcVirtualPicc)));
            }
            var after = Assert.Throws<ObjectDisposedException>(() => picc.Snapshot());
            Assert.That(after!.ObjectName, Is.EqualTo(nameof(DfcVirtualPicc)));
        }
    }

    [Test]
    public void Finalization_ReleasesTheRandomCallbackRoot()
    {
        var random = CreateAbandonedPicc();

        for (var i = 0; i < 10 && random.IsAlive; i++)
        {
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }

        Assert.That(random.IsAlive, Is.False);
    }

    [Test]
    public void Dispose_FromRandomCallback_DefersNativeReleaseUntilTheExchangeCompletes()
    {
        var random = new DisposingRandomSource();
        var picc = Fixtures.Picc(Fixtures.Credential(), random);
        random.Attach(picc);
        Fixtures.Ok(picc.Activate());

        var response = Fixtures.Ok(picc.Exchange(Hex("901A0000010000")));

        Assert.Multiple(() =>
        {
            Assert.That(response[^2..], Is.EqualTo(new byte[] { 0x91, 0xAF }));
            var exception = Assert.Throws<ObjectDisposedException>(() => picc.Snapshot());
            Assert.That(exception!.ObjectName, Is.EqualTo(nameof(DfcVirtualPicc)));
        });
    }

    [Test]
    public void RandomExhaustion_AbortsWithoutChangingState()
    {
        using var picc = Fixtures.Picc(
            Fixtures.Credential(),
            new DfcScriptedRandomSource(ReadOnlyMemory<byte>.Empty)
        );
        Fixtures.Ok(picc.Activate());
        var before = picc.Snapshot();

        var failed = picc.Exchange(Hex("901A0000010000"));
        var after = picc.Snapshot();

        Assert.Multiple(() =>
        {
            Assert.That(failed.IsFailure, Is.True);
            Assert.That(failed.Error.Kind, Is.EqualTo(DfcProtocolErrorKind.RandomSource));
            Assert.That(before.Selection, Is.EqualTo(after.Selection));
            Assert.That(before.SelectedAid, Is.EqualTo(after.SelectedAid));
            Assert.That(before.Authentication, Is.EqualTo(after.Authentication));
            Assert.That(before.Ev2Session, Is.EqualTo(after.Ev2Session));
            Assert.That(before.ProximityVerified, Is.EqualTo(after.ProximityVerified));
        });

        picc.ResetProtocol();
        Assert.That(Fixtures.Ok(picc.Exchange(Hex("9060000000"))).Length, Is.GreaterThan(2));
    }

    [Test]
    public void ScriptedRandomSource_ShortRequestConsumesNothing()
    {
        var source = new DfcScriptedRandomSource(new byte[] { 0x11, 0x22 });
        Assert.Throws<InvalidOperationException>(() => source.Fill(new byte[3]));
        Assert.That(source.Remaining, Is.EqualTo(2));
        source.Append(new byte[] { 0x33 });
        var exact = new byte[2];
        source.Fill(exact);
        var later = new byte[1];
        source.Fill(later);

        Assert.Multiple(() =>
        {
            Assert.That(exact, Is.EqualTo(new byte[] { 0x11, 0x22 }));
            Assert.That(later, Is.EqualTo(new byte[] { 0x33 }));
            Assert.That(source.Remaining, Is.Zero);
        });
    }

    [Test]
    public void ScriptedRandomSource_ClearDiscardsUnreadBytes()
    {
        var source = new DfcScriptedRandomSource(new byte[] { 0x11, 0x22, 0x33 });
        var storage = ScriptedRandomBuffer(source);
        source.Fill(new byte[1]);
        Assert.That(source.Remaining, Is.EqualTo(2));

        source.Clear();

        Assert.That(source.Remaining, Is.Zero);
        Assert.That(storage, Is.EqualTo(new byte[3]), "clear must wipe unread bytes");
        source.Append(new byte[] { 0xA5, 0x5A });
        var replacement = new byte[2];
        source.Fill(replacement);
        Assert.That(replacement, Is.EqualTo(new byte[] { 0xA5, 0x5A }));
    }

    [Test]
    public void ScriptedRandomSource_WipesConsumedCompactedAndRetiredStorage()
    {
        var source = new DfcScriptedRandomSource(Enumerable.Range(1, 16).Select(value => (byte)value).ToArray());
        var original = ScriptedRandomBuffer(source);

        source.Fill(new byte[4]);
        Assert.That(original[..4], Is.EqualTo(new byte[4]), "consumed bytes");
        Assert.That(original[4..], Is.EqualTo(Enumerable.Range(5, 12).Select(value => (byte)value)));

        source.Append(new byte[] { 0xA5 });
        Assert.That(original[..13], Is.EqualTo(Enumerable.Range(5, 12).Select(value => (byte)value).Append((byte)0xA5)));
        Assert.That(original[13..], Is.EqualTo(new byte[3]), "vacated compaction bytes");

        source.Append(new byte[20]);
        Assert.That(ScriptedRandomBuffer(source), Is.Not.SameAs(original));
        Assert.That(original, Is.EqualTo(new byte[16]), "retired allocation");

        var replay = new byte[33];
        source.Fill(replay);
        Assert.That(replay[..13], Is.EqualTo(Enumerable.Range(5, 12).Select(value => (byte)value).Append((byte)0xA5)));
        Assert.That(replay[13..], Is.EqualTo(new byte[20]));
        Assert.That(source.Remaining, Is.Zero);
    }

    private static byte[] ScriptedRandomBuffer(DfcScriptedRandomSource source) =>
        (byte[])typeof(DfcScriptedRandomSource)
            .GetField("buffer", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(source)!;

    [Test]
    public void GetVersion_UsesThreeNativeResponseFrames()
    {
        using var picc = Fixtures.Picc(Fixtures.Credential(DfcGeneration.Ev1));

        var first = Fixtures.Ok(picc.Exchange(Hex("9060000000")));
        var second = Fixtures.Ok(picc.Exchange(Hex("90AF000000")));
        var last = Fixtures.Ok(picc.Exchange(Hex("90AF000000")));

        Assert.Multiple(() =>
        {
            Assert.That(first.Length, Is.EqualTo(9));
            Assert.That(second.Length, Is.EqualTo(9));
            Assert.That(last.Length, Is.EqualTo(16));
            Assert.That(first[^2..], Is.EqualTo(new byte[] { 0x91, 0xAF }));
            Assert.That(second[^2..], Is.EqualTo(new byte[] { 0x91, 0xAF }));
            Assert.That(last[^2..], Is.EqualTo(new byte[] { 0x91, 0x00 }));
        });
    }

    [Test]
    public void WriteData_TwoFrames_AppliesTheWholePayload()
    {
        using var picc = FreeFilePicc(DfcCommunicationMode.Plain);
        Assert.That(Fixtures.Ok(picc.Exchange(Hex("905A00000301020300"))), Is.EqualTo(Hex("9100")));

        var first = Fixtures.Ok(picc.Exchange(Hex("903D00000B01000000080000AABBCCDD00")));
        Assert.That(first, Is.EqualTo(Hex("91AF")));

        var second = Fixtures.Ok(picc.Exchange(Hex("90AF000004EEFF001100")));
        var read = Fixtures.Ok(picc.Exchange(Hex("90BD0000070100000008000000")));
        Assert.Multiple(() =>
        {
            Assert.That(second, Is.EqualTo(Hex("9100")));
            Assert.That(read, Is.EqualTo(Hex("AABBCCDDEEFF00119100")));
        });
    }

    [Test]
    public void ReadData_FreeAccessFullMode_ReturnsPlaintextWithoutAuthentication()
    {
        using var picc = FreeFilePicc(DfcCommunicationMode.Full);
        Assert.That(Fixtures.Ok(picc.Exchange(Hex("905A00000301020300"))), Is.EqualTo(Hex("9100")));

        var read = Fixtures.Ok(picc.Exchange(Hex("90BD0000070100000000000000")));

        Assert.That(read, Is.EqualTo(Hex("00000000000000009100")));
    }

    [TestCase("C2")]
    [TestCase("CA00")]
    public void IsoDepRelease_EchoesTheFrame(string release)
    {
        using var picc = Fixtures.Picc(Fixtures.Credential(DfcGeneration.Ev1));
        Fixtures.Ok(picc.ExchangeFrame(Hex("E050")));

        var frame = Hex(release);
        Assert.That(Fixtures.Ok(picc.ExchangeFrame(frame)), Is.EqualTo(frame));
    }

    [TestCase("904200000000", "911C")]
    [TestCase("906A00000200", "917E")]
    [TestCase("900A0000010100", "9140")]
    [TestCase("90AA0000010000", "91AE")]
    [TestCase("90AF00000000", "911C")]
    public void NativeApdu_RejectsInvalidCommands(string command, string response)
    {
        using var picc = Fixtures.Picc(Fixtures.Credential(DfcGeneration.Ev1));

        Assert.That(Fixtures.Ok(picc.Exchange(Hex(command))), Is.EqualTo(Hex(response)));
    }

    [Test]
    public void DataFile_RejectsWritesAndReadsPastItsEnd()
    {
        using var picc = FreeFilePicc(DfcCommunicationMode.Plain);
        Assert.That(Fixtures.Ok(picc.Exchange(Hex("905A00000301020300"))), Is.EqualTo(Hex("9100")));

        var write = Fixtures.Ok(picc.Exchange(Hex("903D00000901070000020000010200")));
        var readPastEnd = Fixtures.Ok(picc.Exchange(Hex("90BD0000070107000002000000")));
        var unchanged = Fixtures.Ok(picc.Exchange(Hex("90BD0000070100000000000000")));

        Assert.Multiple(() =>
        {
            Assert.That(write, Is.EqualTo(Hex("91BE")));
            Assert.That(readPastEnd, Is.EqualTo(Hex("91BE")));
            Assert.That(unchanged, Is.EqualTo(Hex("00000000000000009100")));
        });
    }

    [Test]
    public async Task BackupData_HidesUncommittedWrite()
    {
        using var picc = FreeFilePicc(DfcCommunicationMode.Plain, DfcFileType.BackupData, 4);
        using var reader = new DfcReader(picc);
        Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.SelectApplication(Hex("030201"))));

        Fixtures.Ok(await reader.WriteDataAsync(1, 0, Hex("01020304")));
        var before = Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.ReadData(1, 0, 0)));
        Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.CommitTransaction()));
        var after = Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.ReadData(1, 0, 0)));

        Assert.Multiple(() =>
        {
            Assert.That(before.Data, Is.EqualTo(new byte[4]));
            Assert.That(after.Data, Is.EqualTo(Hex("01020304")));
        });
    }

    private static DfcVirtualPicc FreeFilePicc(
        DfcCommunicationMode mode,
        DfcFileType type = DfcFileType.StandardData,
        uint size = 8)
    {
        var credential = Fixtures.Credential(DfcGeneration.Ev1);
        var application = new DfcApplication(
            [0x03, 0x02, 0x01],
            0x0F,
            0x01,
            DfcAuthenticationMode.D40,
            [new DfcKey(new byte[16], 0)],
            [new DfcFile(1, type, (byte)mode, 0xEEEE,
                new DfcFileContents.Data(size, new byte[size], true))]
        );
        return Fixtures.Picc(credential with { Applications = [application] });
    }

    private static byte[] Hex(string value) => Convert.FromHexString(value);

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static WeakReference CreateAbandonedPicc()
    {
        var random = new DfcScriptedRandomSource(ReadOnlyMemory<byte>.Empty);
        var weak = new WeakReference(random);
        _ = Fixtures.Picc(Fixtures.Credential(), random);
        return weak;
    }

    private sealed class BlockingRandomSource : IDfcRandomSource
    {
        public ManualResetEventSlim Entered { get; } = new();

        public ManualResetEventSlim Continue { get; } = new();

        public void Fill(Span<byte> destination)
        {
            Entered.Set();
            if (!Continue.Wait(TimeSpan.FromSeconds(5)))
            {
                throw new TimeoutException("The test did not release the random callback.");
            }
            destination.Fill(0x5A);
        }
    }

    private sealed class DisposingRandomSource : IDfcRandomSource
    {
        private DfcVirtualPicc? picc;

        public void Attach(DfcVirtualPicc value) => picc = value;

        public void Fill(Span<byte> destination)
        {
            Interlocked.Exchange(ref picc, null)?.Dispose();
            destination.Fill(0x5A);
        }
    }
}
