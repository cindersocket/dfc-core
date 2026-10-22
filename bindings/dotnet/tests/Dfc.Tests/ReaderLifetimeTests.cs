namespace Dfc.Tests;

using System;
using System.Threading;
using System.Threading.Tasks;
using CSharpFunctionalExtensions;
using Dfc.Credentials;
using Dfc.Emulation;
using Dfc.Reader;
using NUnit.Framework;

[TestFixture]
public sealed class ReaderLifetimeTests
{
    [Test]
    public void DisposedOperation_ReportsThePublicTypeName()
    {
        using var picc = Fixtures.Picc(Fixtures.Credential());
        var reader = new DfcReader(picc);
        reader.Dispose();

        var exception = Assert.ThrowsAsync<ObjectDisposedException>(
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
        var exception = Assert.Throws<ObjectDisposedException>(() => reader.ClearSession());
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

        public void Attach(DfcReader value) => reader = value;

        public async ValueTask<Result<byte[], DfcProtocolError>> TransmitAsync(
            ReadOnlyMemory<byte> frame,
            CancellationToken cancellationToken
        )
        {
            var answer = await inner.TransmitAsync(frame, cancellationToken).ConfigureAwait(false);
            Interlocked.Exchange(ref reader, null)?.Dispose();
            return answer;
        }
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
            if (Interlocked.Exchange(ref block, 0) != 0)
            {
                Entered.TrySetResult();
                await Continue.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            }
            return answer;
        }
    }

    private sealed class DisposingRandomSource : IDfcRandomSource
    {
        private DfcReader? reader;

        public void Attach(DfcReader value) => reader = value;

        public void Fill(Span<byte> destination)
        {
            destination.Clear();
            Interlocked.Exchange(ref reader, null)?.Dispose();
        }
    }
}
