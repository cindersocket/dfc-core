namespace Dfc.Interop;

using System.Runtime.InteropServices;

// Mirrors of the structs in ffi/dfc_ffi.h. Field order and widths follow the
// header exactly; Native checks the sizes against the loaded library.

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeCapabilities
{
    public uint AbiVersion;
    public uint BuildRole;
    public uint BuildProfile;
    public byte GenerationEv1;
    public byte GenerationEv2;
    public byte GenerationEv3;
    public byte Storage2K;
    public byte Storage4K;
    public byte Storage8K;
    public byte Ev2SecureMessaging;
    public byte Iso7816;
    public byte TransactionMac;
    public byte SecureDynamicMessaging;
    public byte ProximityCheck;
    public byte VirtualCard;
    public byte KeySets;
    public byte DelegatedApplications;
    public byte TransactionTimer;
    public byte ApplicationCapabilityData;
    public byte StaticSignature;
    public byte AuthD40;
    public byte AuthIso;
    public byte AuthAes;
    public byte Emulator;
    public byte Reader;
    public byte DerDecoder;
    public byte DerEncoder;
    public byte TextCodec;
    public uint MaxApplications;
    public uint MaxFiles;
    public uint MaxKeys;
    public uint FilePoolSize;
    public uint KeyPoolSize;
}

[StructLayout(LayoutKind.Sequential)]
internal struct NativeStructSizes
{
    public uint Capabilities;
    public uint Error;
    public uint Card;
    public uint Picc;
    public uint Application;
    public uint File;
    public uint Key;
    public uint Activation;
    public uint Snapshot;
    public uint ReaderState;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeError
{
    public int Status;
    public uint Line;
    public fixed byte Message[96];
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeCard
{
    public uint Generation;
    public uint Storage;
    public uint UidProvenance;
    public uint UidLen;
    public fixed byte Uid[10];
    public byte HasHardwareVersion;
    public fixed byte HardwareVersion[7];
    public byte HasSoftwareVersion;
    public fixed byte SoftwareVersion[7];
    public byte HasStaticSignature;
    public fixed byte StaticSignature[56];
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativePicc
{
    public uint NumKeys;
    public uint KeyLen;
    public byte KeySettings1;
    public byte KeySettings2;
    public byte AuthCommand;
    public byte RandomId;
    public byte FormatDisabled;
    public byte AtsLen;
    public fixed byte Ats[20];
    public byte HasSak;
    public byte Sak;
    public byte HasAtqa;
    public fixed byte Atqa[2];
    public byte HasSmDisable;
    public byte SmDisable;
    public byte HasEv2Capabilities;
    public fixed byte Ev2Capabilities[6];
    public byte HasProximityKey;
    public fixed byte ProximityKey[16];
    public byte ProximityOption;
    public byte HasProximityBitrate;
    public byte ProximityBitrate;
    public ushort ProximityPublishedResponseTime;
    public byte VirtualCardConfigured;
    public byte VirtualCardInstallationIdLen;
    public fixed byte VirtualCardInstallationId[16];
    public byte VirtualCardInformation;
    public fixed byte VirtualCardCapabilities[2];
    public byte VirtualCardUidLen;
    public fixed byte VirtualCardUid[10];
    public fixed byte VirtualCardSelectMacKey[16];
    public fixed byte VirtualCardSelectEncryptionKey[16];
    public byte VirtualCardAuthenticationMandatory;
    public byte VirtualCardProximityMandatory;
    public byte HasDamKeys;
    public fixed byte DamAuthKey[16];
    public fixed byte DamMacKey[16];
    public fixed byte DamEncryptionKey[16];
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeApplication
{
    public uint NumKeys;
    public uint KeyLen;
    public uint DfNameLen;
    public uint NumKeySets;
    public ushort IsoFileId;
    public ushort DelegatedSlotNumber;
    public ushort DelegatedQuotaLimit;
    public ushort DelegatedFreeBlocks;
    public fixed byte Aid[3];
    public byte HasIsoFileId;
    public fixed byte DfName[16];
    public byte KeySettings1;
    public byte KeySettings2;
    public byte AuthCommand;
    public byte KeySetMaxSize;
    public byte KeySetSettings;
    public fixed byte KeySetVersions[16];
    public fixed byte KeySetTypes[16];
    public fixed byte KeySetInitialized[16];
    public byte HasCapabilityData;
    public fixed byte CapabilityData[10];
    public byte Delegated;
    public byte DelegatedSlotVersion;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeFile
{
    public int Owner;
    public uint DeclaredSize;
    public uint DataLen;
    public int ValueLowerLimit;
    public int ValueUpperLimit;
    public int Value;
    public int ValuePendingDelta;
    public uint RecordSize;
    public uint MaxRecords;
    public uint RecordCount;
    public uint SdmUidOffset;
    public uint SdmCounterOffset;
    public uint SdmPiccDataOffset;
    public uint SdmMacInputOffset;
    public uint SdmMacOffset;
    public uint SdmEncryptedFileOffset;
    public uint SdmEncryptedFileLength;
    public uint SdmCounterLimit;
    public uint SdmReadCounter;
    public uint TransactionCounter;
    public ushort AccessRights;
    public ushort IsoFileId;
    public ushort SdmAccessRights;
    public byte Number;
    public byte Type;
    public byte CommSettings;
    public byte HasIsoFileId;
    public byte ContentsComplete;
    public byte TransactionPending;
    public byte LimitedCredit;
    public byte ValuePending;
    public byte SdmEnabled;
    public byte SdmOptions;
    public byte SdmHasUidOffset;
    public byte SdmHasCounterOffset;
    public byte SdmHasPiccDataOffset;
    public byte SdmHasMacInputOffset;
    public byte SdmHasMacOffset;
    public byte SdmHasEncryptedFileOffset;
    public byte SdmHasCounterLimit;
    public byte TransactionMacKeyType;
    public byte TransactionMacKeyVersion;
    public fixed byte TransactionMacKey[16];
    public fixed byte TransactionMac[8];
    public fixed byte PreviousReaderId[16];
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeKey
{
    public uint Len;
    public fixed byte Value[24];
    public byte Version;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeActivation
{
    public uint UidLen;
    public uint AtsLen;
    public uint AtqaLen;
    public uint ProtocolLen;
    public uint RfDetailLen;
    public fixed byte Uid[10];
    public fixed byte Ats[20];
    public fixed byte Atqa[2];
    public byte Sak;
    public fixed byte Protocol[2];
    public fixed byte RfDetail[3];
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeSnapshot
{
    public uint Selected;
    public uint SelectedApplicationIndex;
    public uint Ev2CommandCounter;
    public fixed byte SelectedAid[3];
    public byte Dirty;
    public byte AuthMode;
    public byte AuthKeyNo;
    public byte Ev2Active;
    public byte Ev2KeyNo;
    public fixed byte Ev2TransactionIdentifier[4];
    public fixed byte Ev2EncryptionKey[16];
    public fixed byte Ev2MacKey[16];
    public byte VirtualCardSelected;
    public byte ProximityVerified;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeReaderState
{
    public uint Ev2CommandCounter;
    public byte AuthMode;
    public byte KeyNo;
    public fixed byte Ev2TransactionIdentifier[4];
    public fixed byte Ev2CardCapabilities[6];
    public fixed byte Ev2ReaderCapabilities[6];
}

// DfcCommand from src/dfc_command.h: one native frame.
[StructLayout(LayoutKind.Sequential)]
internal unsafe struct NativeCommand
{
    public byte Ins;
    public fixed byte Data[255];
    public nuint DataLen;
}
