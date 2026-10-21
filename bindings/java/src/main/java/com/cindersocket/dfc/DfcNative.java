package com.cindersocket.dfc;

final class DfcNative {
  static {
    System.loadLibrary("dfc_jni");
    if (abiVersion() != 3)
      throw new UnsatisfiedLinkError("dfc JNI ABI mismatch: " + abiVersion());
  }
  private DfcNative() {}
  static native int abiVersion();
  static native long capabilities();
  static native byte[] credentialParse(byte[] text) throws DfcException;
  static native byte[] credentialLoad(byte[] content) throws DfcException;
  static native String credentialText(byte[] binary) throws DfcException;
  static native void credentialValidate(byte[] binary) throws DfcException;
  static native long piccCreate(byte[] binary, byte[] randomScript) throws DfcException;
  static native void piccFree(long handle);
  static native byte[] piccActivate(long handle) throws DfcException;
  static native byte[] piccSnapshot(long handle) throws DfcException;
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
