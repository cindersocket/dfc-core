namespace Dfc.Tests;

using System;
using Dfc.Reader;
using NUnit.Framework;

/// <summary>A caller-supplied length must be refused, never narrowed to a byte that looks valid.</summary>
[TestFixture]
public sealed class NarrowingTests
{
    // DfcCommand is a public record, so its constructor can bypass the Raw factory's 255-octet check.
    [TestCase(256)]
    [TestCase(300)]
    public void DfcCommand_BuiltDirectlyWithTooMuchData_RefusesToEncodeAnApdu(int length)
    {
        var command = new DfcCommand(0x3D, new byte[length]);

        Assert.Throws<InvalidOperationException>(() => command.ToApdu());
        var largest = new DfcCommand(0x3D, new byte[DfcCommand.MaximumData]).ToApdu();
        Assert.That(largest[4], Is.EqualTo((byte)DfcCommand.MaximumData));
    }
}
