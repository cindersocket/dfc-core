package com.cindersocket.dfc;

final class DfcNative {
  static {
    DfcNativeLoader.load();
    DfcCompatibility.requireCompatible(
        abiVersion(), layoutFingerprint(), expectedLayoutFingerprint());
  }
  private DfcNative() {}
  static native int abiVersion();
  static native long layoutFingerprint();
  static native long expectedLayoutFingerprint();
  static native long capabilities();
  static native byte[] an10922Diversify(int algorithm, byte[] masterKey, byte[] input)
      throws DfcException;
  static native byte[] responseDecodeVersion(byte[] response) throws DfcException;
  static native byte[] responseDecodeApplicationIds(byte[] response) throws DfcException;
  static native byte[] responseDecodeFileIds(byte[] response) throws DfcException;
  static native byte[] responseDecodeFileSettings(byte[] response) throws DfcException;
  static native byte[] responseDecodeKeySettings(byte[] response) throws DfcException;
  static native int responseDecodeKeyVersion(byte[] response) throws DfcException;
  static native byte[] sdmVerify(byte[] message, int fields, long plainUidOffset,
      long plainUidLength, long plainCounterOffset, long encryptedPiccOffset,
      long encryptedPiccLength, long encryptedFileOffset, long encryptedFileLength,
      long macInputOffset, long macOffset, byte[] metaReadKey, byte[] fileReadKey)
      throws DfcException;
  static native long transactionMacCreate(int capacity, byte[] key, byte[] uid, long counter)
      throws DfcException;
  static native void transactionMacFree(long handle);
  static native void transactionMacAddData(long handle, int command, int fileNumber, long offset,
      long length, byte[] data) throws DfcException;
  static native void transactionMacAddRecord(long handle, int command, int fileNumber,
      long recordNumber, long offset, long length, byte[] data) throws DfcException;
  static native void transactionMacAddValue(long handle, int command, int fileNumber, long value)
      throws DfcException;
  static native void transactionMacAddClearRecord(long handle, int fileNumber) throws DfcException;
  static native void transactionMacAddReaderId(long handle, byte[] current, byte[] previous)
      throws DfcException;
  static native boolean transactionMacVerify(long handle, byte[] mac) throws DfcException;
  static native byte[] credentialParse(byte[] text) throws DfcException;
  static native byte[] credentialLoad(byte[] content) throws DfcException;
  static native String credentialText(byte[] binary) throws DfcException;
  static native void credentialValidate(byte[] binary) throws DfcException;
  static native long piccCreate(byte[] binary, byte[] randomScript) throws DfcException;
  static native void piccAppendReplayRandom(long handle, byte[] bytes) throws DfcException;
  static native void piccClearReplayRandom(long handle) throws DfcException;
  static native int piccReplayRandomRemaining(long handle) throws DfcException;
  static native void piccFree(long handle);
  static native byte[] piccActivate(long handle) throws DfcException;
  static native byte[] piccSnapshot(long handle) throws DfcException;
  static native byte[] piccDiagnosticSnapshot(long handle) throws DfcException;
  static native byte[] piccExchange(long handle, byte[] command, boolean frame) throws DfcException;
  static native void piccFieldOff(long handle) throws DfcException;
  static native void piccResetProtocol(long handle) throws DfcException;
  static native void piccAdvanceTime(long handle, long milliseconds) throws DfcException;
  static native byte[] piccExport(long handle) throws DfcException;
  static native void piccMarkPersisted(long handle) throws DfcException;
  static native long readerCreate() throws DfcException;
  static native void readerFree(long handle);
  static native void readerClear(long handle);
  static native void readerBegin(long handle, int framing, int instruction, byte[] data,
      int communicationMode, int encryptedHeaderLength) throws DfcException;
  static native void readerAuthenticate(long handle, int framing, int cipher, int keyNumber,
      byte[] key, byte[] randomA) throws DfcException;
  static native void readerAuthenticateIso7816(long handle, int keyReference, int algorithm,
      byte[] key, byte[] randomFirst, byte[] randomSecond) throws DfcException;
  static native void readerAuthenticateEv2(long handle, int framing, boolean first, int keyNumber,
      byte[] key, byte[] randomA, byte[] capabilities) throws DfcException;
  static native byte[] readerStep(long handle, byte[] answer) throws DfcException;
  static native byte[] readerResult(long handle) throws DfcException;
  static native int readerStatus(long handle);
  static native byte[] readerState(long handle) throws DfcException;
}
