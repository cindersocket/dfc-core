namespace Dfc.Interop;

using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using CSharpFunctionalExtensions;
using Dfc.Credentials;

/// <summary>Owns one native credential.</summary>
internal sealed class CredentialHandle : SafeHandle
{
    public CredentialHandle()
        : base(IntPtr.Zero, ownsHandle: true) { }

    internal CredentialHandle(nint handle)
        : base(IntPtr.Zero, ownsHandle: true)
    {
        SetHandle(handle);
    }

    public override bool IsInvalid => handle == IntPtr.Zero;

    protected override bool ReleaseHandle()
    {
        Native.dfc_ffi_credential_free(handle);
        return true;
    }
}

/// <summary>Moves a credential between the managed record tree and a native handle.</summary>
internal static unsafe class CredentialMarshaller
{
    private const int FileTypeStandard = 0;
    private const int FileTypeBackup = 1;
    private const int FileTypeValue = 2;
    private const int FileTypeTransactionMac = 5;

    // --------------------------------------------------------- native in ---

    internal static DfcCredential Read(CredentialHandle handle)
    {
        bool added = false;
        handle.DangerousAddRef(ref added);
        try
        {
            return Read(handle.DangerousGetHandle());
        }
        finally
        {
            if (added)
            {
                handle.DangerousRelease();
            }
        }
    }

    internal static DfcCredential Read(nint credential)
    {
        NativeCard card;
        NativePicc picc;
        Check(Native.dfc_ffi_credential_get_card(credential, &card));
        Check(Native.dfc_ffi_credential_get_picc(credential, &picc));

        uint appCount = Native.dfc_ffi_credential_application_count(credential);
        var appFiles = new List<DfcFile>[appCount];
        for (var i = 0; i < appCount; i++)
        {
            appFiles[i] = [];
        }

        var piccFiles = new List<DfcFile>();
        uint fileCount = Native.dfc_ffi_credential_file_count(credential);
        for (uint i = 0; i < fileCount; i++)
        {
            NativeFile file;
            Check(Native.dfc_ffi_credential_get_file(credential, i, &file));
            var known = ReadFileData(credential, i);
            var managed = ToFile(file, known);
            if (file.Owner == Native.OwnerPicc)
            {
                piccFiles.Add(managed);
            }
            else
            {
                appFiles[file.Owner].Add(managed);
            }
        }

        var applications = new List<DfcApplication>((int)appCount);
        for (uint i = 0; i < appCount; i++)
        {
            NativeApplication app;
            Check(Native.dfc_ffi_credential_get_application(credential, i, &app));
            applications.Add(ToApplication(credential, (int)i, app, appFiles[i]));
        }

        var piccKeys = ReadKeys(credential, Native.OwnerPicc, 0, picc.NumKeys);
        return new DfcCredential(ToCard(card), ToPicc(picc, piccKeys, piccFiles), applications);
    }

    private static byte[] ReadFileData(nint credential, uint index)
    {
        nuint length;
        Check(Native.dfc_ffi_credential_get_file_data(credential, index, null, 0, &length));
        var data = new byte[(int)length];
        fixed (byte* p = data)
        {
            Check(Native.dfc_ffi_credential_get_file_data(credential, index, p, length, &length));
        }

        return data;
    }

    private static List<DfcKey> ReadKeys(nint credential, int owner, uint keySet, uint count)
    {
        var keys = new List<DfcKey>((int)count);
        for (uint slot = 0; slot < count; slot++)
        {
            NativeKey key;
            Check(Native.dfc_ffi_credential_get_key(credential, owner, keySet, slot, &key));
            keys.Add(new DfcKey(Bytes(key.Value, (int)key.Len), key.Version));
        }

        return keys;
    }

    private static DfcCard ToCard(NativeCard c) =>
        new((DfcGeneration)c.Generation, c.Storage, Copy(c.Uid, (int)c.UidLen), (DfcUidProvenance)c.UidProvenance)
        {
            HardwareVersion = c.HasHardwareVersion != 0 ? Copy(c.HardwareVersion, 7) : null,
            SoftwareVersion = c.HasSoftwareVersion != 0 ? Copy(c.SoftwareVersion, 7) : null,
            StaticSignature = c.HasStaticSignature != 0 ? Copy(c.StaticSignature, 56) : null,
        };

    private static DfcPicc ToPicc(NativePicc p, List<DfcKey> keys, List<DfcFile> files) =>
        new(p.KeySettings1, p.KeySettings2, (DfcAuthenticationMode)p.AuthCommand, keys, files)
        {
            SupportedAuthenticationCommands = p.HasAuthCommands != 0 ? (DfcAuthenticationCommands)p.AuthCommands : null,
            PreferredAuthenticationCommand = p.HasPreferredAuthCommand != 0 ? (DfcAuthenticationCommands)p.PreferredAuthCommand : null,
            RandomId = p.RandomId != 0,
            FormatDisabled = p.FormatDisabled != 0,
            Ats = p.AtsLen > 0 ? Copy(p.Ats, p.AtsLen) : null,
            Sak = p.HasSak != 0 ? p.Sak : null,
            Atqa = p.HasAtqa != 0 ? Copy(p.Atqa, 2) : null,
            SmDisable = p.HasSmDisable != 0 ? p.SmDisable : null,
            Ev2Capabilities = p.HasEv2Capabilities != 0 ? Copy(p.Ev2Capabilities, 6) : null,
            ProximityCheck =
                p.HasProximityKey != 0
                    ? new DfcProximityConfiguration(Copy(p.ProximityKey, 16), p.ProximityOption, p.ProximityPublishedResponseTime)
                    {
                        Bitrate = p.HasProximityBitrate != 0 ? p.ProximityBitrate : null,
                    }
                    : null,
            VirtualCard =
                p.VirtualCardConfigured != 0
                    ? new DfcVirtualCardConfiguration(
                        Copy(p.VirtualCardInstallationId, p.VirtualCardInstallationIdLen),
                        p.VirtualCardInformation,
                        Copy(p.VirtualCardCapabilities, 2),
                        Copy(p.VirtualCardUid, p.VirtualCardUidLen),
                        Copy(p.VirtualCardSelectMacKey, 16),
                        Copy(p.VirtualCardSelectEncryptionKey, 16),
                        p.VirtualCardAuthenticationMandatory != 0,
                        p.VirtualCardProximityMandatory != 0
                    )
                    : null,
            DamKeys =
                p.HasDamKeys != 0
                    ? new DfcDamKeys(Copy(p.DamAuthKey, 16), Copy(p.DamMacKey, 16), Copy(p.DamEncryptionKey, 16))
                    : null,
        };

    private static DfcApplication ToApplication(nint credential, int index, NativeApplication a, List<DfcFile> files)
    {
        var keys = ReadKeys(credential, index, 0, a.NumKeys);
        DfcKeySets? keySets = null;
        if (a.NumKeySets >= 2)
        {
            var sets = new List<DfcKeySet>((int)a.NumKeySets);
            for (uint set = 0; set < a.NumKeySets; set++)
            {
                sets.Add(
                    new DfcKeySet(
                        a.KeySetVersions[set],
                        a.KeySetTypes[set],
                        a.KeySetInitialized[set] != 0,
                        ReadKeys(credential, index, set, a.NumKeys)
                    )
                );
            }

            keySets = new DfcKeySets(a.KeySetMaxSize, a.KeySetSettings, sets);
        }

        return new DfcApplication(
            Copy(a.Aid, 3),
            a.KeySettings1,
            a.KeySettings2,
            (DfcAuthenticationMode)a.AuthCommand,
            keys,
            files
        )
        {
            SupportedAuthenticationCommands = a.HasAuthCommands != 0 ? (DfcAuthenticationCommands)a.AuthCommands : null,
            PreferredAuthenticationCommand = a.HasPreferredAuthCommand != 0 ? (DfcAuthenticationCommands)a.PreferredAuthCommand : null,
            SecureMessagingDisable = a.HasSmDisable != 0 ? a.SmDisable : null,
            IsoFileId = a.HasIsoFileId != 0 ? a.IsoFileId : null,
            DfName = a.DfNameLen > 0 ? Copy(a.DfName, (int)a.DfNameLen) : null,
            KeySets = keySets,
            CapabilityData = a.HasCapabilityData != 0 ? Copy(a.CapabilityData, 10) : null,
            Delegation =
                a.Delegated != 0
                    ? new DfcDelegation(a.DelegatedSlotNumber, a.DelegatedSlotVersion, a.DelegatedQuotaLimit, a.DelegatedFreeBlocks)
                    : null,
        };
    }

    private static DfcFile ToFile(NativeFile f, byte[] known)
    {
        DfcFileContents contents = f.Type switch
        {
            FileTypeStandard or FileTypeBackup => new DfcFileContents.Data(f.DeclaredSize, known, f.ContentsComplete != 0)
            {
                TransactionPending = f.TransactionPending != 0,
            },
            FileTypeValue => new DfcFileContents.Value(f.ValueLowerLimit, f.ValueUpperLimit, f.Value, f.LimitedCredit)
            {
                Pending = f.ValuePending != 0,
                PendingDelta = f.ValuePendingDelta,
            },
            FileTypeTransactionMac => new DfcFileContents.TransactionMac(
                f.TransactionMacKeyType,
                Copy(f.TransactionMacKey, 16),
                f.TransactionMacKeyVersion,
                f.TransactionCounter,
                Copy(f.TransactionMac, 8),
                Copy(f.PreviousReaderId, 16)
            ),
            _ => new DfcFileContents.Records(f.RecordSize, f.MaxRecords, f.RecordCount, known, f.ContentsComplete != 0)
            {
                TransactionPending = f.TransactionPending != 0,
            },
        };

        DfcSdmConfiguration? sdm = null;
        if (f.SdmEnabled != 0)
        {
            sdm = new DfcSdmConfiguration(f.SdmOptions, f.SdmAccessRights)
            {
                UidOffset = f.SdmHasUidOffset != 0 ? f.SdmUidOffset : null,
                CounterOffset = f.SdmHasCounterOffset != 0 ? f.SdmCounterOffset : null,
                PiccDataOffset = f.SdmHasPiccDataOffset != 0 ? f.SdmPiccDataOffset : null,
                MacInputOffset = f.SdmHasMacInputOffset != 0 ? f.SdmMacInputOffset : null,
                MacOffset = f.SdmHasMacOffset != 0 ? f.SdmMacOffset : null,
                EncryptedFileOffset = f.SdmHasEncryptedFileOffset != 0 ? f.SdmEncryptedFileOffset : null,
                EncryptedFileLength = f.SdmEncryptedFileLength,
                CounterLimit = f.SdmHasCounterLimit != 0 ? f.SdmCounterLimit : null,
                ReadCounter = f.SdmReadCounter,
            };
        }

        return new DfcFile(f.Number, (DfcFileType)f.Type, f.CommSettings, f.AccessRights, contents)
        {
            IsoFileId = f.HasIsoFileId != 0 ? f.IsoFileId : null,
            Sdm = sdm,
        };
    }

    // -------------------------------------------------------- native out ---

    internal static Result<CredentialHandle, DfcError> Write(DfcCredential credential)
    {
        ArgumentNullException.ThrowIfNull(credential);
        Native.EnsureCompatible();
        nint raw;
        int st = Native.dfc_ffi_credential_new(&raw);
        if (st != 0)
        {
            return DfcError.FromStatus(st);
        }

        var handle = new CredentialHandle(raw);
        var result = Populate(raw, credential);
        if (result.IsFailure)
        {
            handle.Dispose();
            return result.Error;
        }

        return handle;
    }

    private static UnitResult<DfcError> Populate(nint target, DfcCredential credential)
    {
        var card = FromCard(credential.Card);
        if (card.IsFailure)
        {
            return card.Error;
        }

        var cardValue = card.Value;
        var st = Native.dfc_ffi_credential_set_card(target, &cardValue);
        if (st != 0)
        {
            return DfcError.FromStatus(st, "the card cannot be represented");
        }

        var picc = FromPicc(credential.Picc);
        if (picc.IsFailure)
        {
            return picc.Error;
        }

        var piccValue = picc.Value;
        st = Native.dfc_ffi_credential_set_picc(target, &piccValue);
        if (st != 0)
        {
            return DfcError.FromStatus(st, "the PICC settings cannot be represented");
        }

        var keyResult = WriteKeys(target, Native.OwnerPicc, 0, credential.Picc.Keys);
        if (keyResult.IsFailure)
        {
            return keyResult.Error;
        }

        for (var i = 0; i < credential.Applications.Count; i++)
        {
            var app = credential.Applications[i];
            var native = FromApplication(app);
            if (native.IsFailure)
            {
                return native.Error;
            }

            var nativeValue = native.Value;
            uint index;
            st = Native.dfc_ffi_credential_add_application(target, &nativeValue, &index);
            if (st != 0)
            {
                return DfcError.FromStatus(st, $"application {i} cannot be added");
            }

            if (app.KeySets is { } keySets)
            {
                for (var set = 0; set < keySets.Sets.Count; set++)
                {
                    keyResult = WriteKeys(target, (int)index, (uint)set, keySets.Sets[set].Keys);
                    if (keyResult.IsFailure)
                    {
                        return keyResult.Error;
                    }
                }
            }
            else
            {
                keyResult = WriteKeys(target, (int)index, 0, app.Keys);
                if (keyResult.IsFailure)
                {
                    return keyResult.Error;
                }
            }
        }

        var files = WriteFiles(target, Native.OwnerPicc, credential.Picc.Files);
        if (files.IsFailure)
        {
            return files.Error;
        }

        for (var i = 0; i < credential.Applications.Count; i++)
        {
            files = WriteFiles(target, i, credential.Applications[i].Files);
            if (files.IsFailure)
            {
                return files.Error;
            }
        }

        NativeError error;
        st = Native.dfc_ffi_credential_finish(target, &error);
        return st == 0 ? UnitResult.Success<DfcError>() : ToError(in error, st);
    }

    private static UnitResult<DfcError> WriteKeys(nint target, int owner, uint keySet, IReadOnlyList<DfcKey> keys)
    {
        for (var slot = 0; slot < keys.Count; slot++)
        {
            var value = keys[slot].Value ?? [];
            if (value.Length > 24)
            {
                return new DfcError(DfcErrorClass.Malformed, $"key {slot} is longer than 24 octets");
            }

            NativeKey key = default;
            key.Len = (uint)value.Length;
            key.Version = keys[slot].Version;
            Fill(key.Value, value);
            int st = Native.dfc_ffi_credential_set_key(target, owner, keySet, (uint)slot, &key);
            if (st != 0)
            {
                return DfcError.FromStatus(st, $"key {slot} does not fit its key type");
            }
        }

        return UnitResult.Success<DfcError>();
    }

    private static UnitResult<DfcError> WriteFiles(nint target, int owner, IReadOnlyList<DfcFile> files)
    {
        foreach (var file in files)
        {
            var native = FromFile(owner, file, out var known);
            uint index;
            int st = Native.dfc_ffi_credential_add_file(target, &native, &index);
            if (st != 0)
            {
                return DfcError.FromStatus(st, $"file {file.Number:X2} cannot be added");
            }

            if (known.Length > 0)
            {
                fixed (byte* p = known)
                {
                    st = Native.dfc_ffi_credential_set_file_data(target, index, p, (nuint)known.Length);
                }

                if (st != 0)
                {
                    return DfcError.FromStatus(st, $"the contents of file {file.Number:X2} do not fit");
                }
            }
        }

        return UnitResult.Success<DfcError>();
    }

    private static Result<NativeCard, DfcError> FromCard(DfcCard card)
    {
        if (card.Uid is null || card.Uid.Length > 10)
        {
            return new DfcError(DfcErrorClass.Malformed, "the UID must be four, seven or ten octets");
        }

        NativeCard c = default;
        c.Generation = (uint)card.Generation;
        c.Storage = card.Storage;
        c.UidProvenance = (uint)card.UidProvenance;
        c.UidLen = (uint)card.Uid.Length;
        Fill(c.Uid, card.Uid);
        if (!Optional(card.HardwareVersion, 7, c.HardwareVersion, ref c.HasHardwareVersion)
            || !Optional(card.SoftwareVersion, 7, c.SoftwareVersion, ref c.HasSoftwareVersion)
            || !Optional(card.StaticSignature, 56, c.StaticSignature, ref c.HasStaticSignature))
        {
            return new DfcError(DfcErrorClass.Malformed, "a card field has the wrong length");
        }

        return c;
    }

    private static Result<NativePicc, DfcError> FromPicc(DfcPicc picc)
    {
        NativePicc p = default;
        p.NumKeys = (uint)picc.Keys.Count;
        p.KeyLen = picc.Keys.Count > 0 ? (uint)picc.Keys[0].Value.Length : 16;
        p.KeySettings1 = picc.KeySettings1;
        p.KeySettings2 = picc.KeySettings2;
        p.AuthCommand = (byte)picc.AuthenticationMode;
        if (picc.SupportedAuthenticationCommands is { } commands)
        {
            p.HasAuthCommands = 1;
            p.AuthCommands = (byte)commands;
        }
        if (picc.PreferredAuthenticationCommand is { } preferred)
        {
            p.HasPreferredAuthCommand = 1;
            p.PreferredAuthCommand = (byte)preferred;
        }
        p.RandomId = Flag(picc.RandomId);
        p.FormatDisabled = Flag(picc.FormatDisabled);
        var ok = true;
        if (picc.Ats is { } ats)
        {
            ok &= ats.Length <= 20;
            if (ok)
            {
                p.AtsLen = (byte)ats.Length;
                Fill(p.Ats, ats);
            }
        }

        if (picc.Sak is { } sak)
        {
            p.HasSak = 1;
            p.Sak = sak;
        }

        ok &= Optional(picc.Atqa, 2, p.Atqa, ref p.HasAtqa);
        if (picc.SmDisable is { } smDisable)
        {
            p.HasSmDisable = 1;
            p.SmDisable = smDisable;
        }

        ok &= Optional(picc.Ev2Capabilities, 6, p.Ev2Capabilities, ref p.HasEv2Capabilities);
        if (picc.ProximityCheck is { } proximity)
        {
            ok &= Optional(proximity.Key, 16, p.ProximityKey, ref p.HasProximityKey);
            p.ProximityOption = proximity.Option;
            p.ProximityPublishedResponseTime = proximity.PublishedResponseTime;
            if (proximity.Bitrate is { } bitrate)
            {
                p.HasProximityBitrate = 1;
                p.ProximityBitrate = bitrate;
            }
        }

        if (picc.VirtualCard is { } vc)
        {
            ok &= vc.InstallationId.Length <= 16 && vc.Uid.Length <= 10 && vc.Capabilities.Length == 2
                && vc.SelectMacKey.Length == 16 && vc.SelectEncryptionKey.Length == 16;
            if (ok)
            {
                p.VirtualCardConfigured = 1;
                p.VirtualCardInstallationIdLen = (byte)vc.InstallationId.Length;
                Fill(p.VirtualCardInstallationId, vc.InstallationId);
                p.VirtualCardInformation = vc.Information;
                Fill(p.VirtualCardCapabilities, vc.Capabilities);
                p.VirtualCardUidLen = (byte)vc.Uid.Length;
                Fill(p.VirtualCardUid, vc.Uid);
                Fill(p.VirtualCardSelectMacKey, vc.SelectMacKey);
                Fill(p.VirtualCardSelectEncryptionKey, vc.SelectEncryptionKey);
                p.VirtualCardAuthenticationMandatory = Flag(vc.AuthenticationMandatory);
                p.VirtualCardProximityMandatory = Flag(vc.ProximityMandatory);
            }
        }

        if (picc.DamKeys is { } dam)
        {
            ok &= dam.AuthenticationKey.Length == 16 && dam.MacKey.Length == 16 && dam.EncryptionKey.Length == 16;
            if (ok)
            {
                p.HasDamKeys = 1;
                Fill(p.DamAuthKey, dam.AuthenticationKey);
                Fill(p.DamMacKey, dam.MacKey);
                Fill(p.DamEncryptionKey, dam.EncryptionKey);
            }
        }

        return ok ? p : new DfcError(DfcErrorClass.Malformed, "a PICC field has the wrong length");
    }

    private static Result<NativeApplication, DfcError> FromApplication(DfcApplication app)
    {
        if (app.Aid is null || app.Aid.Length != 3)
        {
            return new DfcError(DfcErrorClass.Malformed, "an AID is three octets");
        }

        NativeApplication a = default;
        Fill(a.Aid, app.Aid);
        a.KeySettings1 = app.KeySettings1;
        a.KeySettings2 = app.KeySettings2;
        a.AuthCommand = (byte)app.AuthenticationMode;
        if (app.SupportedAuthenticationCommands is { } commands)
        {
            a.HasAuthCommands = 1;
            a.AuthCommands = (byte)commands;
        }
        if (app.PreferredAuthenticationCommand is { } preferred)
        {
            a.HasPreferredAuthCommand = 1;
            a.PreferredAuthCommand = (byte)preferred;
        }
        if (app.SecureMessagingDisable is { } smDisable)
        {
            a.HasSmDisable = 1;
            a.SmDisable = smDisable;
        }
        var activeKeys = app.KeySets is { } sets && sets.Sets.Count > 0 ? sets.Sets[0].Keys : app.Keys;
        a.NumKeys = (uint)activeKeys.Count;
        a.KeyLen = activeKeys.Count > 0 ? (uint)activeKeys[0].Value.Length : KeyLengthFor(app.KeySettings2);
        if (app.IsoFileId is { } fid)
        {
            a.HasIsoFileId = 1;
            a.IsoFileId = fid;
        }

        if (app.DfName is { } name)
        {
            if (name.Length > 16)
            {
                return new DfcError(DfcErrorClass.Malformed, "a DF name is at most sixteen octets");
            }

            a.DfNameLen = (uint)name.Length;
            Fill(a.DfName, name);
        }

        if (app.KeySets is { } keySets)
        {
            if (keySets.Sets.Count > 16)
            {
                return new DfcError(DfcErrorClass.Capacity, "an application holds at most sixteen key sets");
            }

            a.NumKeySets = (uint)keySets.Sets.Count;
            a.KeySetMaxSize = keySets.MaximumKeySize;
            a.KeySetSettings = keySets.Settings;
            for (var i = 0; i < keySets.Sets.Count; i++)
            {
                a.KeySetVersions[i] = keySets.Sets[i].Version;
                a.KeySetTypes[i] = keySets.Sets[i].Type;
                a.KeySetInitialized[i] = Flag(keySets.Sets[i].Initialized);
            }
        }

        var ok = Optional(app.CapabilityData, 10, a.CapabilityData, ref a.HasCapabilityData);
        if (app.Delegation is { } delegation)
        {
            a.Delegated = 1;
            a.DelegatedSlotNumber = delegation.SlotNumber;
            a.DelegatedSlotVersion = delegation.SlotVersion;
            a.DelegatedQuotaLimit = delegation.QuotaLimit;
            a.DelegatedFreeBlocks = delegation.FreeBlocks;
        }

        return ok ? a : new DfcError(DfcErrorClass.Malformed, "application capability data is ten octets");
    }

    private static uint KeyLengthFor(byte keySettings2) => (keySettings2 & 0xC0) == 0x40 ? 24u : 16u;

    private static NativeFile FromFile(int owner, DfcFile file, out byte[] known)
    {
        NativeFile f = default;
        f.Owner = owner;
        f.Number = file.Number;
        f.Type = (byte)file.Type;
        f.CommSettings = file.CommunicationSettings;
        f.AccessRights = file.AccessRights;
        if (file.IsoFileId is { } fid)
        {
            f.HasIsoFileId = 1;
            f.IsoFileId = fid;
        }

        known = [];
        switch (file.Contents)
        {
            case DfcFileContents.Data data:
                f.DeclaredSize = data.Size;
                f.ContentsComplete = Flag(data.Complete);
                f.TransactionPending = Flag(data.TransactionPending);
                known = data.Known ?? [];
                break;
            case DfcFileContents.Value value:
                f.ValueLowerLimit = value.LowerLimit;
                f.ValueUpperLimit = value.UpperLimit;
                f.Value = value.Current;
                f.LimitedCredit = value.LimitedCredit;
                f.ValuePending = Flag(value.Pending);
                f.ValuePendingDelta = value.PendingDelta;
                break;
            case DfcFileContents.Records records:
                f.RecordSize = records.RecordSize;
                f.MaxRecords = records.MaximumRecords;
                f.RecordCount = records.RecordCount;
                f.ContentsComplete = Flag(records.Complete);
                f.TransactionPending = Flag(records.TransactionPending);
                known = records.Known ?? [];
                break;
            case DfcFileContents.TransactionMac tmac:
                f.TransactionMacKeyType = tmac.KeyType;
                Fill(f.TransactionMacKey, tmac.Key);
                f.TransactionMacKeyVersion = tmac.KeyVersion;
                f.TransactionCounter = tmac.Counter;
                Fill(f.TransactionMac, tmac.Mac);
                Fill(f.PreviousReaderId, tmac.PreviousReaderId);
                break;
        }

        if (file.Sdm is { } sdm)
        {
            f.SdmEnabled = 1;
            f.SdmOptions = sdm.Options;
            f.SdmAccessRights = sdm.AccessRights;
            f.SdmHasUidOffset = Present(sdm.UidOffset, ref f.SdmUidOffset);
            f.SdmHasCounterOffset = Present(sdm.CounterOffset, ref f.SdmCounterOffset);
            f.SdmHasPiccDataOffset = Present(sdm.PiccDataOffset, ref f.SdmPiccDataOffset);
            f.SdmHasMacInputOffset = Present(sdm.MacInputOffset, ref f.SdmMacInputOffset);
            f.SdmHasMacOffset = Present(sdm.MacOffset, ref f.SdmMacOffset);
            f.SdmHasEncryptedFileOffset = Present(sdm.EncryptedFileOffset, ref f.SdmEncryptedFileOffset);
            f.SdmEncryptedFileLength = sdm.EncryptedFileLength;
            f.SdmHasCounterLimit = Present(sdm.CounterLimit, ref f.SdmCounterLimit);
            f.SdmReadCounter = sdm.ReadCounter;
        }

        return f;
    }

    // ---------------------------------------------------------- helpers ---

    internal static DfcError ToError(in NativeError error, int status)
    {
        fixed (byte* message = error.Message)
        {
            var text = Marshal.PtrToStringUTF8((nint)message) ?? string.Empty;
            return DfcError.FromStatus(status, text.Length > 0 ? text : null, (int)error.Line);
        }
    }

    internal static void Check(int status)
    {
        if (status != 0)
        {
            throw new InvalidOperationException($"The native credential walk failed with status {status}.");
        }
    }

    private static byte Flag(bool value) => value ? (byte)1 : (byte)0;

    private static byte Present(uint? value, ref uint field)
    {
        if (value is not { } v)
        {
            return 0;
        }

        field = v;
        return 1;
    }

    private static bool Optional(byte[]? value, int length, byte* field, ref byte present)
    {
        if (value is null)
        {
            return true;
        }

        if (value.Length != length)
        {
            return false;
        }

        present = 1;
        Fill(field, value);
        return true;
    }

    private static void Fill(byte* field, byte[]? value)
    {
        if (value is null)
        {
            return;
        }

        for (var i = 0; i < value.Length; i++)
        {
            field[i] = value[i];
        }
    }

    private static byte[] Copy(byte* field, int length) => new ReadOnlySpan<byte>(field, length).ToArray();

    private static byte[] Bytes(byte* field, int length) => Copy(field, length);
}
