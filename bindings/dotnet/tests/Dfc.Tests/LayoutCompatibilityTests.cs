namespace Dfc.Tests;

using System;
using Dfc.Credentials;
using Dfc.Interop;
using NUnit.Framework;

public sealed class LayoutCompatibilityTests
{
    [Test]
    public void MismatchedNativeLayoutIsRejectedBeforeHandles()
    {
        var expected = Native.ExpectedLayoutFingerprint();
        var error = Assert.Throws<InvalidOperationException>(() =>
            Native.RequireCompatible(Native.AbiVersion, expected ^ 1)
        );
        Assert.That(error!.Message, Does.Contain("native DFC layout fingerprint"));
    }

    [Test]
    public void MismatchedNativeLibraryIsRejectedBeforeHandlesOnEveryCall()
    {
        if (Environment.GetEnvironmentVariable("DFC_EXPECT_LAYOUT_MISMATCH") != "1")
        {
            Assert.Ignore("mismatched native test library was not selected");
        }

        for (var attempt = 0; attempt < 2; attempt++)
        {
            var error = Assert.Throws<InvalidOperationException>(() => DfcCredentialCodec.Decode([]));
            Assert.That(error!.Message, Does.Contain("native DFC layout fingerprint"));
        }
    }
}
