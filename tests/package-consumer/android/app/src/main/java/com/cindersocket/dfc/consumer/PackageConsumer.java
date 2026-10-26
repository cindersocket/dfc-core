package com.cindersocket.dfc.consumer;

import com.cindersocket.dfc.DfcLibrary;

/** Forces the packaged Java API and JNI entry point to resolve at compile time. */
final class PackageConsumer {
  private PackageConsumer() {}

  static int abiVersion() {
    return DfcLibrary.abiVersion();
  }
}
