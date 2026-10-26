package com.cindersocket.dfc;

import java.nio.file.Files;
import java.nio.file.Path;

/** Checks Java's native-authentication validation against the shared binding contract. */
public final class DfcAuthenticationBoundaryTest {
  public static void main(String[] arguments) throws Exception {
    for (String line : Files.readAllLines(Path.of("tests", "authentication-boundaries.txt"))) {
      if (line.isBlank() || line.startsWith("#"))
        continue;
      String[] fields = line.split("\\|");
      DfcReader.Cipher cipher = switch (fields[0]) {
        case "legacy" -> DfcReader.Cipher.LEGACY;
        case "iso" -> DfcReader.Cipher.ISO;
        case "aes" -> DfcReader.Cipher.AES;
        default -> throw new AssertionError("unknown cipher " + fields[0]);
      };
      boolean accepted = false;
      try {
        accepted = DfcReader.challengeLength(cipher, Integer.parseInt(fields[1]))
            == Integer.parseInt(fields[2]);
      } catch (IllegalArgumentException expected) {
        // Rejected by the public binding before any native call.
      }
      if (accepted != fields[3].equals("yes"))
        throw new AssertionError(line);
    }
  }
}
