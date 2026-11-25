namespace Dfc.Tests;

using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using Dfc.Reader;
using NUnit.Framework;

public sealed class CommandConstructorTests
{
    [Test]
    public void IsoAppendRecordAndResponseHelpersPreserveTwoByteStatus()
    {
        foreach (var line in File.ReadLines(Path.Combine(TestContext.CurrentContext.TestDirectory, "iso7816-helper-vectors.txt")))
        {
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }
            var fields = line.Split('|');
            if (fields[0] == "append-record")
            {
                Assert.That(
                    DfcIso7816.BuildAppendRecord(
                        byte.Parse(fields[2], CultureInfo.InvariantCulture),
                        Convert.FromHexString(fields[1])
                    ),
                    Is.EqualTo(Convert.FromHexString(fields[3]))
                );
            }
            else
            {
                Assert.That(fields[0], Is.EqualTo("parse-response"));
                var parsed = DfcIso7816.ParseResponse(Convert.FromHexString(fields[1]));
                Assert.That(parsed.Data.ToArray(), Is.EqualTo(Convert.FromHexString(fields[2])));
                Assert.That(
                    parsed.StatusWord,
                    Is.EqualTo(ushort.Parse(fields[3], NumberStyles.HexNumber, CultureInfo.InvariantCulture))
                );
            }
        }
    }

    [Test]
    public void ConstructorsMatchSharedVectors()
    {
        foreach (var line in File.ReadLines(Path.Combine(TestContext.CurrentContext.TestDirectory, "command-constructor-vectors.txt")))
        {
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var fields = line.Split('|');
            var command = Construct(fields[0], fields[1]);
            var actual = new List<byte> { command.Instruction };
            actual.AddRange(command.Data.ToArray());
            Assert.That(actual, Is.EqualTo(Convert.FromHexString(fields[2])), fields[0]);
        }
    }

    [TestCase(32)]
    [TestCase(255)]
    public void FileConstructorsRejectOutOfRangeNumbers(byte fileNumber)
    {
        Assert.Multiple(() =>
        {
            Assert.Throws<ArgumentOutOfRangeException>(() => DfcCommand.GetFileSettings(fileNumber));
            Assert.Throws<ArgumentOutOfRangeException>(() => DfcCommand.GetFileCounters(fileNumber));
            Assert.Throws<ArgumentOutOfRangeException>(() => DfcCommand.DeleteFile(fileNumber));
            Assert.Throws<ArgumentOutOfRangeException>(() => DfcCommand.ClearRecordFile(fileNumber));
            Assert.Throws<ArgumentOutOfRangeException>(() => DfcCommand.GetValue(fileNumber));
            Assert.That(DfcCommand.ReadData(fileNumber, 0, 1).IsFailure, Is.True);
        });
    }

    [Test]
    public void PayloadBoundariesMatchSharedVectors()
    {
        foreach (var line in File.ReadLines(Path.Combine(TestContext.CurrentContext.TestDirectory, "command-constructor-boundaries.txt")))
        {
            if (line.Length == 0 || line.StartsWith('#'))
            {
                continue;
            }

            var fields = line.Split('|');
            var length = int.Parse(fields[1], CultureInfo.InvariantCulture);
            var data = new byte[length];
            var result = fields[0] switch
            {
                "write-data" => DfcCommand.WriteData(1, 0, data),
                "write-record" => DfcCommand.WriteRecord(1, 0, data),
                "update-record" => DfcCommand.UpdateRecord(1, 0, 0, data),
                _ => throw new InvalidDataException($"Unknown constructor {fields[0]}.")
            };
            Assert.That(result.IsSuccess, Is.EqualTo(fields[2] == "accept"), $"{fields[0]} {length}");
        }
    }

    private static DfcCommand Construct(string name, string arguments)
    {
        var number = () => byte.Parse(arguments, CultureInfo.InvariantCulture);
        return name switch
        {
            "get-version" => DfcCommand.GetVersion(),
            "get-free-memory" => DfcCommand.GetFreeMemory(),
            "format-picc" => DfcCommand.FormatPicc(),
            "get-key-settings" => DfcCommand.GetKeySettings(),
            "get-application-ids" => DfcCommand.GetApplicationIds(),
            "get-df-names" => DfcCommand.GetDfNames(),
            "get-file-ids" => DfcCommand.GetFileIds(),
            "get-iso-file-ids" => DfcCommand.GetIsoFileIds(),
            "get-card-uid" => DfcCommand.GetCardUid(),
            "read-signature" => DfcCommand.ReadSignature(number()),
            "get-key-version" => DfcCommand.GetKeyVersion(number()),
            "select-application" => Fixtures.Ok(DfcCommand.SelectApplication(Convert.FromHexString(arguments))),
            "get-file-settings" => DfcCommand.GetFileSettings(number()),
            "get-file-counters" => DfcCommand.GetFileCounters(number()),
            "delete-file" => DfcCommand.DeleteFile(number()),
            "clear-record-file" => DfcCommand.ClearRecordFile(number()),
            "get-value" => DfcCommand.GetValue(number()),
            "read-data" => ReadData(arguments),
            "read-data-iso-chaining" => ReadData(arguments, true),
            "write-data" => WriteRange(
                arguments,
                (file, offset, data) => DfcCommand.WriteData(file, offset, data)
            ),
            "write-data-iso-chaining" => WriteRange(
                arguments,
                (file, offset, data) => DfcCommand.WriteData(file, offset, data, true)
            ),
            "read-records" => ReadRecords(arguments),
            "read-records-iso-chaining" => ReadRecords(arguments, true),
            "write-record" => WriteRange(arguments, (file, offset, data) => DfcCommand.WriteRecord(file, offset, data)),
            "write-record-iso-chaining" => WriteRange(
                arguments,
                (file, offset, data) => DfcCommand.WriteRecord(file, offset, data, true)
            ),
            "update-record" => UpdateRecord(arguments),
            "update-record-iso-chaining" => UpdateRecord(arguments, true),
            "credit" => ValueOperation(arguments, DfcCommand.Credit),
            "debit" => ValueOperation(arguments, DfcCommand.Debit),
            "limited-credit" => ValueOperation(arguments, DfcCommand.LimitedCredit),
            "commit-transaction" => arguments.Length == 0
                ? DfcCommand.CommitTransaction()
                : DfcCommand.CommitTransaction(number()),
            "abort-transaction" => DfcCommand.AbortTransaction(),
            _ => throw new InvalidDataException($"Unknown constructor {name}."),
        };
    }

    private static DfcCommand ReadData(string arguments, bool isoChaining = false)
    {
        var fields = Array.ConvertAll(arguments.Split(','), value => uint.Parse(value, CultureInfo.InvariantCulture));
        return Fixtures.Ok(DfcCommand.ReadData((byte)fields[0], fields[1], fields[2], isoChaining));
    }

    private delegate CSharpFunctionalExtensions.Result<DfcCommand, DfcProtocolError> RangeEncoder(
        byte fileNumber,
        uint offset,
        ReadOnlySpan<byte> data
    );

    private static DfcCommand WriteRange(string arguments, RangeEncoder encoder)
    {
        var fields = arguments.Split(',');
        return Fixtures.Ok(
            encoder(
                byte.Parse(fields[0], CultureInfo.InvariantCulture),
                uint.Parse(fields[1], CultureInfo.InvariantCulture),
                Convert.FromHexString(fields[2])
            )
        );
    }

    private static DfcCommand ReadRecords(string arguments, bool isoChaining = false)
    {
        var fields = Array.ConvertAll(arguments.Split(','), value => uint.Parse(value, CultureInfo.InvariantCulture));
        return Fixtures.Ok(
            DfcCommand.ReadRecords((byte)fields[0], fields[1], fields[2], isoChaining)
        );
    }

    private static DfcCommand UpdateRecord(string arguments, bool isoChaining = false)
    {
        var fields = arguments.Split(',');
        return Fixtures.Ok(
            DfcCommand.UpdateRecord(
                byte.Parse(fields[0], CultureInfo.InvariantCulture),
                uint.Parse(fields[1], CultureInfo.InvariantCulture),
                uint.Parse(fields[2], CultureInfo.InvariantCulture),
                Convert.FromHexString(fields[3]),
                isoChaining
            )
        );
    }

    private static DfcCommand ValueOperation(
        string arguments,
        Func<byte, int, CSharpFunctionalExtensions.Result<DfcCommand, DfcProtocolError>> encoder
    )
    {
        var fields = arguments.Split(',');
        return Fixtures.Ok(
            encoder(
                byte.Parse(fields[0], CultureInfo.InvariantCulture),
                int.Parse(fields[1], CultureInfo.InvariantCulture)
            )
        );
    }
}
