namespace Dfc.Credentials;

/// <summary>File type.</summary>
public enum DfcFileType : byte
{
    /// <summary>Standard data file.</summary>
    StandardData = 0x00,

    /// <summary>Backup data file.</summary>
    BackupData = 0x01,

    /// <summary>Value file.</summary>
    Value = 0x02,

    /// <summary>Linear record file.</summary>
    LinearRecord = 0x03,

    /// <summary>Cyclic record file.</summary>
    CyclicRecord = 0x04,

    /// <summary>Transaction MAC file.</summary>
    TransactionMac = 0x05,
}

/// <summary>What a file holds, by type.</summary>
public abstract record DfcFileContents
{
    private DfcFileContents() { }

    /// <summary>A standard or backup data file.</summary>
    /// <param name="Size">Declared size.</param>
    /// <param name="Known">The contents known, from offset 0; may be shorter than the size.</param>
    /// <param name="Complete">Whether the known contents cover the whole file.</param>
    public sealed record Data(uint Size, byte[] Known, bool Complete) : DfcFileContents
    {
        /// <summary>Whether an uncommitted transaction holds changes.</summary>
        public bool TransactionPending { get; init; }
    }

    /// <summary>A value file.</summary>
    public sealed record Value(int LowerLimit, int UpperLimit, int Current, byte LimitedCredit) : DfcFileContents
    {
        /// <summary>Whether an uncommitted transaction holds a change.</summary>
        public bool Pending { get; init; }

        /// <summary>The uncommitted change.</summary>
        public int PendingDelta { get; init; }
    }

    /// <summary>A linear or cyclic record file.</summary>
    /// <param name="RecordSize">Octets per record.</param>
    /// <param name="MaximumRecords">Records the file holds at most.</param>
    /// <param name="RecordCount">Records written.</param>
    /// <param name="Known">The leading records known, in card order.</param>
    /// <param name="Complete">Whether every record is known.</param>
    public sealed record Records(uint RecordSize, uint MaximumRecords, uint RecordCount, byte[] Known, bool Complete)
        : DfcFileContents
    {
        /// <summary>Whether an uncommitted transaction holds changes.</summary>
        public bool TransactionPending { get; init; }
    }

    /// <summary>A transaction MAC file.</summary>
    public sealed record TransactionMac(
        byte KeyType,
        byte[] Key,
        byte KeyVersion,
        uint Counter,
        byte[] Mac,
        byte[] PreviousReaderId
    ) : DfcFileContents;
}

/// <summary>Secure dynamic messaging settings of a standard data file.</summary>
public sealed record DfcSdmConfiguration(byte Options, ushort AccessRights)
{
    /// <summary>Offset of the UID mirror.</summary>
    public uint? UidOffset { get; init; }

    /// <summary>Offset of the read-counter mirror.</summary>
    public uint? CounterOffset { get; init; }

    /// <summary>Offset of the encrypted PICC data.</summary>
    public uint? PiccDataOffset { get; init; }

    /// <summary>Offset the MAC input starts at.</summary>
    public uint? MacInputOffset { get; init; }

    /// <summary>Offset of the MAC.</summary>
    public uint? MacOffset { get; init; }

    /// <summary>Offset of the encrypted file data.</summary>
    public uint? EncryptedFileOffset { get; init; }

    /// <summary>Length of the encrypted file data.</summary>
    public uint EncryptedFileLength { get; init; }

    /// <summary>Read-counter limit.</summary>
    public uint? CounterLimit { get; init; }

    /// <summary>Reads so far.</summary>
    public uint ReadCounter { get; init; }
}

/// <summary>One file.</summary>
/// <param name="Number">File number.</param>
/// <param name="Type">File type.</param>
/// <param name="CommunicationSettings">Communication settings octet; the low bits are a <see cref="DfcCommunicationMode" />.</param>
/// <param name="AccessRights">Access rights: read, write, read and write, change, from the top nibble.</param>
/// <param name="Contents">What the file holds.</param>
public sealed record DfcFile(
    byte Number,
    DfcFileType Type,
    byte CommunicationSettings,
    ushort AccessRights,
    DfcFileContents Contents
)
{
    /// <summary>ISO file identifier.</summary>
    public ushort? IsoFileId { get; init; }

    /// <summary>Secure dynamic messaging, when enabled.</summary>
    public DfcSdmConfiguration? Sdm { get; init; }

    /// <summary>The communication mode the settings select.</summary>
    public DfcCommunicationMode CommunicationMode =>
        (CommunicationSettings & 0x03) switch
        {
            0x01 => DfcCommunicationMode.Mac,
            0x03 => DfcCommunicationMode.Full,
            _ => DfcCommunicationMode.Plain,
        };
}
