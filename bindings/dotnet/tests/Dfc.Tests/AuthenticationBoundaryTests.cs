namespace Dfc.Tests;

using System.Globalization;
using System.IO;
using Dfc.Credentials;
using Dfc.Reader;
using NUnit.Framework;

public sealed class AuthenticationBoundaryTests
{
    [Test]
    public void NativeAuthenticationBoundariesMatchSharedContract()
    {
        var path = Path.Combine(TestContext.CurrentContext.TestDirectory, "authentication-boundaries.txt");
        foreach (var line in File.ReadLines(path))
        {
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var fields = line.Split('|');
            var mode = fields[0] switch
            {
                "legacy" => DfcAuthenticationMode.D40,
                "iso" => DfcAuthenticationMode.Iso,
                "aes" => DfcAuthenticationMode.Aes,
                _ => throw new InvalidDataException($"Unknown cipher {fields[0]}"),
            };
            var actual = DfcReader.NativeAuthenticationChallengeLength(
                mode,
                int.Parse(fields[1], CultureInfo.InvariantCulture)
            );
            var accepted = actual == int.Parse(fields[2], CultureInfo.InvariantCulture);
            Assert.That(accepted, Is.EqualTo(fields[3] == "yes"), line);
        }
    }
}
