namespace Dfc.Tests;

using System;
using Dfc.Reader;
using NUnit.Framework;

/// <summary>A caller-supplied length must be refused, never narrowed to a byte that looks valid.</summary>
[TestFixture]
public sealed class NarrowingTests
{
    [TestCase(256)]
    [TestCase(300)]
    public void DfcCommand_BuiltDirectlyWithTooMuchData_IsRefused(int length)
    {
        Assert.Throws<InvalidOperationException>(() => _ = new DfcCommand(0x3D, new byte[length]));
    }

    [Test]
    public void DfcCommand_MaximumData_EncodesWithoutNarrowing()
    {
        var largest = new DfcCommand(0x3D, new byte[DfcCommand.MaximumData]).ToApdu();

        Assert.That(largest[4], Is.EqualTo((byte)DfcCommand.MaximumData));
    }
}
