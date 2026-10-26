package com.cindersocket.dfc;

import java.nio.file.Files;
import java.nio.file.Path;

/** Verifies that raw JNI integer arguments are rejected before byte narrowing. */
public final class DfcJniNarrowingTest {
  private static final int INVALID_ARGUMENT = -1;
  private static final int ISO = 0;

  private static void check(boolean condition, String message) {
    if (!condition)
      throw new AssertionError(message);
  }

  private static void refused(String label, ThrowingCall call) {
    try {
      call.run();
    } catch (DfcException expected) {
      check(expected.status() == INVALID_ARGUMENT, label + ": status " + expected.status());
      return;
    } catch (Throwable other) {
      throw new AssertionError(label + ": wrong exception " + other, other);
    }
    throw new AssertionError(label + ": accepted");
  }

  private static void publiclyRefused(String label, ThrowingCall call) {
    try {
      call.run();
    } catch (IllegalArgumentException expected) {
      return;
    } catch (Throwable other) {
      throw new AssertionError(label + ": wrong exception " + other, other);
    }
    throw new AssertionError(label + ": accepted");
  }

  private static void authenticationRefusalPreservesPending(
      long handle, String label, ThrowingCall call) throws Exception {
    DfcNative.readerBegin(handle, ISO, 0x60, new byte[0], 0, -1);
    refused(label, call);
    check(DfcNative.readerStep(handle, null) != null, label + ": changed reader state");
  }

  private interface ThrowingCall {
    void run() throws Exception;
  }

  public static void main(String[] arguments) throws Exception {
    check(arguments.length == 1, "credential path required");
    DfcCredential credential = DfcCredentialCodec.load(Files.readAllBytes(Path.of(arguments[0])));
    long picc = DfcNative.piccCreate(credential.encode(), new byte[64]);
    try {
      DfcNative.piccActivate(picc);
      DfcNative.piccAdvanceTime(picc, 0xffff_ffffL);
      for (long bad : new long[] {-1, 1L << 32, Long.MIN_VALUE, Long.MAX_VALUE}) {
        refused("milliseconds " + bad, () -> DfcNative.piccAdvanceTime(picc, bad));
      }
      DfcNative.piccAdvanceTime(picc, 0);
      check(DfcNative.piccSnapshot(picc) != null, "PICC usable after refusals");
    } finally {
      DfcNative.piccFree(picc);
    }

    try (DfcVirtualPicc publicPicc = DfcVirtualPicc.create(credential)) {
      publicPicc.activate();
      publicPicc.advanceTime(0xffff_ffffL);
      DfcPiccSnapshot.Selection selected = publicPicc.snapshot().selection();
      for (long bad : new long[] {-1, 1L << 32, Long.MIN_VALUE, Long.MAX_VALUE}) {
        publiclyRefused("public milliseconds " + bad, () -> publicPicc.advanceTime(bad));
      }
      check(publicPicc.snapshot().selection() == selected,
          "public PICC usable after elapsed-time refusals");
    }

    long handle = DfcNative.readerCreate();
    try {
      byte[] none = new byte[0];
      refused("oversized diversification key",
          () -> DfcNative.an10922Diversify(0, new byte[25], new byte[1]));
      refused("oversized diversification input",
          () -> DfcNative.an10922Diversify(0, new byte[16], new byte[32]));
      refused("oversized fixed response", () -> DfcNative.responseDecodeVersion(new byte[29]));
      refused(
          "oversized key-version response", () -> DfcNative.responseDecodeKeyVersion(new byte[2]));
      refused("oversized SDM metadata key",
          ()
              -> DfcNative.sdmVerify(
                  none, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, new byte[17], new byte[16]));
      refused("oversized SDM file key",
          () -> DfcNative.sdmVerify(none, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, null, new byte[17]));
      refused("short transaction MAC key",
          () -> DfcNative.transactionMacCreate(1, new byte[15], new byte[7], 0));
      refused("oversized transaction MAC key",
          () -> DfcNative.transactionMacCreate(1, new byte[17], new byte[7], 0));
      refused("oversized transaction MAC UID",
          () -> DfcNative.transactionMacCreate(1, new byte[16], new byte[8], 0));
      long verifier = DfcNative.transactionMacCreate(64, new byte[16], new byte[7], 1);
      try {
        refused("oversized current reader ID",
            () -> DfcNative.transactionMacAddReaderId(verifier, new byte[17], new byte[16]));
        refused("oversized previous reader ID",
            () -> DfcNative.transactionMacAddReaderId(verifier, new byte[16], new byte[17]));
        refused("oversized transaction MAC",
            () -> DfcNative.transactionMacVerify(verifier, new byte[9]));
      } finally {
        DfcNative.transactionMacFree(verifier);
      }
      for (int bad : new int[] {256, -1, Integer.MIN_VALUE, Integer.MAX_VALUE}) {
        refused("instruction " + bad, () -> DfcNative.readerBegin(handle, ISO, bad, none, 0, -1));
        refused(
            "communication " + bad, () -> DfcNative.readerBegin(handle, ISO, 0x60, none, bad, -1));
      }
      DfcNative.readerBegin(handle, ISO, 255, none, 0, -1);
      check(DfcNative.readerStep(handle, null) != null, "maximum instruction accepted");
      DfcNative.readerBegin(handle, ISO, 0x60, none, 0, -1);
      check(DfcNative.readerStep(handle, null) != null, "reader usable after refusals");

      byte[] key = new byte[16];
      byte[] random8 = new byte[8];
      byte[] random16 = new byte[16];
      DfcNative.readerAuthenticateEv2(handle, ISO, true, 0, key, random16, none);
      check(DfcNative.readerStep(handle, null) != null, "empty EV2 capabilities accepted");
      authenticationRefusalPreservesPending(handle, "oversized authentication key",
          () -> DfcNative.readerAuthenticate(handle, ISO, 0x1A, 0, new byte[25], random8));
      authenticationRefusalPreservesPending(handle, "oversized authentication challenge",
          () -> DfcNative.readerAuthenticate(handle, ISO, 0x1A, 0, key, new byte[17]));
      authenticationRefusalPreservesPending(handle, "oversized ISO authentication key",
          ()
              -> DfcNative.readerAuthenticateIso7816(
                  handle, 0, 0x02, new byte[25], random8, random8));
      authenticationRefusalPreservesPending(handle, "oversized ISO authentication challenge",
          () -> DfcNative.readerAuthenticateIso7816(handle, 0, 0x02, key, new byte[17], random8));
      authenticationRefusalPreservesPending(handle, "oversized ISO second challenge",
          () -> DfcNative.readerAuthenticateIso7816(handle, 0, 0x02, key, random8, new byte[17]));
      authenticationRefusalPreservesPending(handle, "oversized EV2 key",
          ()
              -> DfcNative.readerAuthenticateEv2(
                  handle, ISO, true, 0, new byte[17], random16, none));
      authenticationRefusalPreservesPending(handle, "oversized EV2 challenge",
          () -> DfcNative.readerAuthenticateEv2(handle, ISO, true, 0, key, new byte[17], none));
      authenticationRefusalPreservesPending(handle, "oversized EV2 capabilities",
          () -> DfcNative.readerAuthenticateEv2(handle, ISO, true, 0, key, random16, new byte[7]));
      authenticationRefusalPreservesPending(handle, "short EV2 key",
          ()
              -> DfcNative.readerAuthenticateEv2(
                  handle, ISO, true, 0, new byte[15], random16, none));
      authenticationRefusalPreservesPending(handle, "short EV2 challenge",
          () -> DfcNative.readerAuthenticateEv2(handle, ISO, true, 0, key, new byte[15], none));
      for (int bad : new int[] {-1, 256, Integer.MIN_VALUE, Integer.MAX_VALUE}) {
        refused(
            "cipher " + bad, () -> DfcNative.readerAuthenticate(handle, ISO, bad, 0, key, random8));
        refused("key number " + bad,
            () -> DfcNative.readerAuthenticate(handle, ISO, 0x1A, bad, key, random8));
        refused("key reference " + bad,
            () -> DfcNative.readerAuthenticateIso7816(handle, bad, 0x02, key, random8, random8));
        refused("algorithm " + bad,
            () -> DfcNative.readerAuthenticateIso7816(handle, 0, bad, key, random8, random8));
        refused("EV2 key number " + bad,
            () -> DfcNative.readerAuthenticateEv2(handle, ISO, true, bad, key, random16, none));
      }
      for (int badFraming : new int[] {-1, Integer.MIN_VALUE}) {
        DfcNative.readerBegin(handle, ISO, 0x60, none, 0, -1);
        refused("exchange framing " + badFraming,
            () -> DfcNative.readerBegin(handle, badFraming, 0x60, none, 0, -1));
        check(DfcNative.readerStep(handle, null) != null,
            "exchange framing refusal preserved pending command");

        DfcNative.readerBegin(handle, ISO, 0x60, none, 0, -1);
        refused("authentication framing " + badFraming,
            () -> DfcNative.readerAuthenticate(handle, badFraming, 0x1A, 0, key, random8));
        check(DfcNative.readerStep(handle, null) != null,
            "authentication framing refusal preserved pending command");

        DfcNative.readerBegin(handle, ISO, 0x60, none, 0, -1);
        refused("EV2 framing " + badFraming,
            ()
                -> DfcNative.readerAuthenticateEv2(
                    handle, badFraming, true, 0, key, random16, none));
        check(DfcNative.readerStep(handle, null) != null,
            "EV2 framing refusal preserved pending command");
      }
      DfcNative.readerBegin(handle, ISO, 0x60, none, 0, -1);
      check(DfcNative.readerStep(handle, null) != null,
          "reader usable after authentication refusals");
    } finally {
      DfcNative.readerFree(handle);
    }
  }
}
