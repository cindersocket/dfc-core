namespace Dfc.Credentials;

using System.Collections.Generic;

/// <summary>Card generation a credential describes.</summary>
public enum DfcGeneration
{
    /// <summary>DESFire EV1.</summary>
    Ev1 = 1,

    /// <summary>DESFire EV2.</summary>
    Ev2 = 2,

    /// <summary>DESFire EV3.</summary>
    Ev3 = 3,
}

/// <summary>Where a credential's UID came from.</summary>
public enum DfcUidProvenance
{
    /// <summary>Read from a card.</summary>
    Real = 0,

    /// <summary>Generated.</summary>
    Random = 1,

    /// <summary>Not recorded.</summary>
    Unknown = 2,
}

/// <summary>The authentication a key set answers; the value is the command that starts it.</summary>
public enum DfcAuthenticationMode : byte
{
    /// <summary>Legacy DES authentication.</summary>
    D40 = 0x0A,

    /// <summary>ISO authentication with DES, 2K3DES or 3K3DES.</summary>
    Iso = 0x1A,

    /// <summary>AES authentication.</summary>
    Aes = 0xAA,
}

/// <summary>Communication mode of a file: how its data travels under a session.</summary>
public enum DfcCommunicationMode : byte
{
    /// <summary>In the clear.</summary>
    Plain = 0x00,

    /// <summary>MACed.</summary>
    Mac = 0x01,

    /// <summary>Encrypted.</summary>
    Full = 0x03,
}

/// <summary>One key slot.</summary>
/// <param name="Value">Key material, at the length the key type gives.</param>
/// <param name="Version">Key version.</param>
public sealed record DfcKey(byte[] Value, byte Version);

/// <summary>Chip-level description.</summary>
/// <param name="Generation">The generation the card answers as.</param>
/// <param name="Storage">User memory in octets.</param>
/// <param name="Uid">The UID: four, seven or ten octets.</param>
/// <param name="UidProvenance">Where the UID came from.</param>
public sealed record DfcCard(DfcGeneration Generation, uint Storage, byte[] Uid, DfcUidProvenance UidProvenance)
{
    /// <summary>Seven-octet hardware GetVersion override.</summary>
    public byte[]? HardwareVersion { get; init; }

    /// <summary>Seven-octet software GetVersion override.</summary>
    public byte[]? SoftwareVersion { get; init; }

    /// <summary>The 56-octet originality signature ReadSignature returns.</summary>
    public byte[]? StaticSignature { get; init; }
}

/// <summary>Proximity-check parameters.</summary>
public sealed record DfcProximityConfiguration(byte[] Key, byte Option, ushort PublishedResponseTime)
{
    /// <summary>The bit rate published by PrepareProximityCheck, when there is one.</summary>
    public byte? Bitrate { get; init; }
}

/// <summary>Virtual-card identity and selection keys.</summary>
public sealed record DfcVirtualCardConfiguration(
    byte[] InstallationId,
    byte Information,
    byte[] Capabilities,
    byte[] Uid,
    byte[] SelectMacKey,
    byte[] SelectEncryptionKey,
    bool AuthenticationMandatory,
    bool ProximityMandatory
);

/// <summary>Delegated-application management keys.</summary>
public sealed record DfcDamKeys(byte[] AuthenticationKey, byte[] MacKey, byte[] EncryptionKey);

/// <summary>The master application and card-wide settings.</summary>
/// <param name="KeySettings1">Key settings 1.</param>
/// <param name="KeySettings2">Key settings 2: key type and count.</param>
/// <param name="AuthenticationMode">The authentication the PICC keys answer.</param>
/// <param name="Keys">PICC keys, slot 0 first.</param>
/// <param name="Files">PICC-level files.</param>
public sealed record DfcPicc(
    byte KeySettings1,
    byte KeySettings2,
    DfcAuthenticationMode AuthenticationMode,
    IReadOnlyList<DfcKey> Keys,
    IReadOnlyList<DfcFile> Files
)
{
    /// <summary>Whether anticollision presents a random UID.</summary>
    public bool RandomId { get; init; }

    /// <summary>Whether FormatPICC is refused.</summary>
    public bool FormatDisabled { get; init; }

    /// <summary>A user ATS, when set.</summary>
    public byte[]? Ats { get; init; }

    /// <summary>A SAK override.</summary>
    public byte? Sak { get; init; }

    /// <summary>A two-octet ATQA override.</summary>
    public byte[]? Atqa { get; init; }

    /// <summary>The secure-messaging disable option.</summary>
    public byte? SmDisable { get; init; }

    /// <summary>Six-octet EV2 PICC capabilities.</summary>
    public byte[]? Ev2Capabilities { get; init; }

    /// <summary>Proximity check, when configured.</summary>
    public DfcProximityConfiguration? ProximityCheck { get; init; }

    /// <summary>Virtual card, when configured.</summary>
    public DfcVirtualCardConfiguration? VirtualCard { get; init; }

    /// <summary>Delegated-application management keys, when present.</summary>
    public DfcDamKeys? DamKeys { get; init; }
}

/// <summary>One key set of an application that carries several.</summary>
public sealed record DfcKeySet(byte Version, byte Type, bool Initialized, IReadOnlyList<DfcKey> Keys);

/// <summary>The key sets of an application.</summary>
/// <param name="MaximumKeySize">Largest key any set may hold: 16 or 24.</param>
/// <param name="Settings">Key-set settings.</param>
/// <param name="Sets">Every set, set 0 active.</param>
public sealed record DfcKeySets(byte MaximumKeySize, byte Settings, IReadOnlyList<DfcKeySet> Sets);

/// <summary>Delegated-application state.</summary>
public sealed record DfcDelegation(ushort SlotNumber, byte SlotVersion, ushort QuotaLimit, ushort FreeBlocks);

/// <summary>One application.</summary>
/// <param name="Aid">The AID, most significant octet first, as the text encoding writes it.</param>
/// <param name="KeySettings1">Key settings 1.</param>
/// <param name="KeySettings2">Key settings 2: key type and count.</param>
/// <param name="AuthenticationMode">The authentication the application's keys answer.</param>
/// <param name="Keys">Keys of the active set, slot 0 first.</param>
/// <param name="Files">The application's files.</param>
public sealed record DfcApplication(
    byte[] Aid,
    byte KeySettings1,
    byte KeySettings2,
    DfcAuthenticationMode AuthenticationMode,
    IReadOnlyList<DfcKey> Keys,
    IReadOnlyList<DfcFile> Files
)
{
    /// <summary>ISO file identifier.</summary>
    public ushort? IsoFileId { get; init; }

    /// <summary>ISO DF name.</summary>
    public byte[]? DfName { get; init; }

    /// <summary>Key sets, when the application carries more than one.</summary>
    public DfcKeySets? KeySets { get; init; }

    /// <summary>Ten-octet application capability data.</summary>
    public byte[]? CapabilityData { get; init; }

    /// <summary>Delegated-application state.</summary>
    public DfcDelegation? Delegation { get; init; }
}

/// <summary>Everything one credential file describes.</summary>
/// <param name="Card">Chip-level description.</param>
/// <param name="Picc">Master application and card-wide settings.</param>
/// <param name="Applications">Applications in the order the card lists them.</param>
public sealed record DfcCredential(DfcCard Card, DfcPicc Picc, IReadOnlyList<DfcApplication> Applications);
