namespace Dfc.Tests;

using System;
using System.Reflection;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Dfc.Credentials;
using Dfc.Reader;
using NUnit.Framework;

[TestFixture]
public sealed class ReaderLifetimeTests
{
    private static readonly string[] ThrowingOperations =
    [
        "exchange",
        "write-data",
        "write-record",
        "update-record",
        "authenticate",
        "authenticate-iso7816",
        "authenticate-ev2-first",
        "authenticate-ev2-non-first",
        "change-key",
        "change-key-ev2",
        "delegated-application",
        "proximity-check",
        "select-virtual-card",
    ];

    [TestCaseSource(nameof(ThrowingOperations))]
    public async Task TransportException_ClearsSessionAndRethrows(string operation)
    {
        using var picc = Fixtures.Picc(Fixtures.Credential());
        var transport = new ThrowingTransport(picc);
        using var reader = new DfcReader(transport);
        await Fixtures.SelectAsync(reader, Fixtures.AesAid);

        var needsEv2 = operation is "authenticate-ev2-non-first" or "change-key-ev2" or "delegated-application";
        if (needsEv2)
        {
            Fixtures.Ok(await reader.AuthenticateEv2FirstAsync(0, Fixtures.AesKey0));
        }
        else
        {
            Fixtures.Ok(await reader.AuthenticateAsync(DfcAuthenticationMode.Aes, 0, Fixtures.AesKey0));
        }

        var expected = new TransportProbeException();
        transport.Exception = expected;

        var actual = await Assert.ThrowsAsync<TransportProbeException>(async () => await InvokeAsync(operation, reader));

        Assert.Multiple(() =>
        {
            Assert.That(actual, Is.SameAs(expected));
            Assert.That(reader.IsAuthenticated, Is.False);
            Assert.That(FrameBuffer(reader), Has.All.EqualTo((byte)0));
        });
    }

    [Test]
    public async Task TransportExceptionAfterAResponse_ClearsSessionAndRethrows()
    {
        using var picc = Fixtures.Picc(Fixtures.Credential());
        var transport = new ThrowingTransport(picc);
        using var reader = new DfcReader(transport);
        await Fixtures.SelectAsync(reader, Fixtures.AesAid);
        Fixtures.Ok(await reader.AuthenticateAsync(DfcAuthenticationMode.Aes, 0, Fixtures.AesKey0));

        var expected = new TransportProbeException();
        transport.SuccessfulCallsBeforeThrow = 1;
        transport.Exception = expected;

        var actual = await Assert.ThrowsAsync<TransportProbeException>(
            async () => _ = await reader.ExchangeAsync(DfcCommand.GetVersion())
        );

        Assert.Multiple(() =>
        {
            Assert.That(actual, Is.SameAs(expected));
            Assert.That(reader.IsAuthenticated, Is.False);
        });
    }

    [Test]
    public async Task DisposedOperation_ReportsThePublicTypeName()
    {
        using var picc = Fixtures.Picc(Fixtures.Credential());
        var reader = new DfcReader(picc);
        Array.Fill(FrameBuffer(reader), (byte)0xA5);
        reader.Dispose();

        Assert.That(FrameBuffer(reader), Has.All.EqualTo((byte)0));

        var exception = await Assert.ThrowsAsync<ObjectDisposedException>(
            async () => _ = await reader.ExchangeAsync(DfcCommand.GetVersion())
        );

        Assert.That(exception!.ObjectName, Is.EqualTo(nameof(DfcReader)));
    }

    [Test]
    public async Task DisposeFromTransport_DefersNativeReleaseUntilTheOperationCompletes()
    {
        using var picc = Fixtures.Picc(Fixtures.Credential());
        var transport = new DisposingTransport(picc);
        var reader = new DfcReader(transport);
        transport.Attach(reader);

        var response = Fixtures.Ok(await reader.ExchangeAsync(DfcCommand.GetVersion()));

        Assert.Multiple(() =>
        {
            Assert.That(response.Data, Has.Length.GreaterThan(0));
            var exception = Assert.Throws<ObjectDisposedException>(() => _ = reader.Session);
            Assert.That(exception!.ObjectName, Is.EqualTo(nameof(DfcReader)));
            Assert.DoesNotThrow(reader.Dispose);
        });
    }

    [Test]
    public async Task ConcurrentDispose_DefersNativeReleaseUntilTheOperationCompletes()
    {
        using var picc = Fixtures.Picc(Fixtures.Credential());
        var transport = new BlockingTransport(picc);
        var reader = new DfcReader(transport);

        var operation = reader.ExchangeAsync(DfcCommand.GetVersion());
        await transport.Entered.Task.WaitAsync(TimeSpan.FromSeconds(5));
        reader.Dispose();
        transport.Continue.TrySetResult();

        var response = Fixtures.Ok(await operation);
        Assert.That(response.Data, Has.Length.GreaterThan(0));
        var exception = Assert.Throws<ObjectDisposedException>(reader.ClearSession);
        Assert.That(exception!.ObjectName, Is.EqualTo(nameof(DfcReader)));
    }

    [Test]
    public async Task DisposeFromRandomSource_DefersNativeReleaseUntilAuthenticationCompletes()
    {
        using var picc = Fixtures.Picc(Fixtures.Credential());
        var random = new DisposingRandomSource();
        var reader = new DfcReader(picc, random: random);
        await Fixtures.SelectAsync(reader, Fixtures.AesAid);
        random.Attach(reader);

        Fixtures.Ok(await reader.AuthenticateAsync(DfcAuthenticationMode.Aes, 0, Fixtures.AesKey0));

        Assert.That(picc.Snapshot().Authentication, Is.EqualTo(DfcAuthenticationMode.Aes));
        var exception = Assert.Throws<ObjectDisposedException>(() => _ = reader.IsAuthenticated);
        Assert.That(exception!.ObjectName, Is.EqualTo(nameof(DfcReader)));
    }

    private sealed class DisposingTransport(IDfcApduExchange inner) : IDfcApduExchange
    {
        private DfcReader? reader;

        public void Attach(DfcReader value)
        {
            this.reader = value;
        }

        public async ValueTask<Result<byte[], DfcProtocolError>> TransmitAsync(
            ReadOnlyMemory<byte> frame,
            CancellationToken cancellationToken
        )
        {
            var answer = await inner.TransmitAsync(frame, cancellationToken).ConfigureAwait(false);
            Interlocked.Exchange(ref this.reader, null)?.Dispose();
            return answer;
        }
    }

    private static async Task InvokeAsync(string operation, DfcReader reader)
    {
        _ = operation switch
        {
            "exchange" => await reader.ExchangeAsync(DfcCommand.GetVersion()),
            "write-data" => await reader.WriteDataAsync(Fixtures.FilePlain, 0, new byte[1]),
            "write-record" => await reader.WriteRecordAsync(Fixtures.FilePlain, 0, new byte[1]),
            "update-record" => await reader.UpdateRecordAsync(Fixtures.FilePlain, 0, 0, new byte[1]),
            "authenticate" => await reader.AuthenticateAsync(DfcAuthenticationMode.Aes, 0, Fixtures.AesKey0),
            "authenticate-iso7816" => await reader.AuthenticateIso7816Async(0, DfcIso7816AuthAlgorithm.Aes, Fixtures.AesKey0),
            "authenticate-ev2-first" => await reader.AuthenticateEv2FirstAsync(0, Fixtures.AesKey0),
            "authenticate-ev2-non-first" => await reader.AuthenticateEv2NonFirstAsync(0, Fixtures.AesKey0),
            "change-key" => await reader.ChangeKeyAsync(1, Fixtures.AesKey1, Fixtures.AesKey1, true, 0),
            "change-key-ev2" => await reader.ChangeKeyEv2Async(0, 1, Fixtures.AesKey1, Fixtures.AesKey1, 0),
            "delegated-application" => await reader.CreateDelegatedApplicationAsync(
                                new DfcDelegatedApplicationRequest(
                                    [0x0A, 0x0B, 0x0C],
                                    1,
                                    0,
                                    64,
                                    0x0F,
                                    0x81,
                                    new byte[16],
                                    new byte[16],
                                    new byte[24],
                                    0
                                )
                            ),
            "proximity-check" => await reader.ProximityCheckAsync(new byte[16]),
            "select-virtual-card" => await reader.SelectVirtualCardAsync(new byte[] { 0x01 }, new byte[16], new byte[16]),
            _ => throw new InvalidOperationException($"Unknown reader operation {operation}."),
        };
    }

    private sealed class ThrowingTransport(IDfcApduExchange inner) : IDfcApduExchange
    {
        public Exception? Exception { get; set; }

        public int SuccessfulCallsBeforeThrow { get; set; }

        public async ValueTask<Result<byte[], DfcProtocolError>> TransmitAsync(
            ReadOnlyMemory<byte> frame,
            CancellationToken cancellationToken
        )
        {
            if (this.Exception is null || this.SuccessfulCallsBeforeThrow-- > 0)
            {
                return await inner.TransmitAsync(frame, cancellationToken).ConfigureAwait(false);
            }
            throw this.Exception;
        }
    }

    private sealed class TransportProbeException : Exception;

    private static byte[] FrameBuffer(DfcReader reader)
    {
        return (byte[])typeof(DfcReader)
            .GetField("frameBuffer", BindingFlags.Instance | BindingFlags.NonPublic)!
            .GetValue(reader)!;
    }

    private sealed class BlockingTransport(IDfcApduExchange inner) : IDfcApduExchange
    {
        private int block = 1;

        public TaskCompletionSource Entered { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public TaskCompletionSource Continue { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);

        public async ValueTask<Result<byte[], DfcProtocolError>> TransmitAsync(
            ReadOnlyMemory<byte> frame,
            CancellationToken cancellationToken
        )
        {
            var answer = await inner.TransmitAsync(frame, cancellationToken).ConfigureAwait(false);
            if (Interlocked.Exchange(ref this.block, 0) != 0)
            {
                this.Entered.TrySetResult();
                await this.Continue.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            return answer;
        }
    }

    private sealed class DisposingRandomSource : IDfcRandomSource
    {
        private DfcReader? reader;

        public void Attach(DfcReader value)
        {
            this.reader = value;
        }

        public void Fill(Span<byte> destination)
        {
            destination.Clear();
            Interlocked.Exchange(ref this.reader, null)?.Dispose();
        }
    }
}
