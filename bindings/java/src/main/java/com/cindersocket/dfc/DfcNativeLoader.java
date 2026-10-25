package com.cindersocket.dfc;

import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Locale;

/** Loads the JNI library from the platform-classifier jar when it is not installed system-wide. */
final class DfcNativeLoader {
  private DfcNativeLoader() {}

  static void load() {
    try {
      System.loadLibrary("dfc_jni");
      return;
    } catch (UnsatisfiedLinkError systemFailure) {
      String classifier = classifier();
      String library = System.mapLibraryName("dfc_jni");
      String resource = "/META-INF/native/" + classifier + "/" + library;
      try (InputStream input = DfcNativeLoader.class.getResourceAsStream(resource)) {
        if (input == null)
          throw systemFailure;
        Path directory = Files.createTempDirectory("dfc-jni-");
        Path extracted = directory.resolve(library);
        Files.copy(input, extracted, StandardCopyOption.REPLACE_EXISTING);
        extracted.toFile().deleteOnExit();
        directory.toFile().deleteOnExit();
        System.load(extracted.toAbsolutePath().toString());
      } catch (IOException failure) {
        systemFailure.addSuppressed(failure);
        throw systemFailure;
      }
    }
  }

  static String classifier() {
    String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
    String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
    String platform = os.contains("win") ? "windows" : os.contains("mac") ? "osx" : "linux";
    String machine = switch (arch) {
      case "amd64", "x86_64" -> "x86_64";
      case "aarch64", "arm64" -> "aarch64";
      default -> throw new UnsatisfiedLinkError("unsupported dfc JNI architecture: " + arch);
    };
    return platform + "-" + machine;
  }
}
