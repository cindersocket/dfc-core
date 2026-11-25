import com.cindersocket.dfc.DfcActivation;
import com.cindersocket.dfc.DfcCredential;
import com.cindersocket.dfc.DfcCredentialCodec;
import com.cindersocket.dfc.DfcException;
import com.cindersocket.dfc.DfcVirtualPicc;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.stream.Stream;

/**
 * Replays every DESFire conformance vector through the Java binding.
 *
 * <p>The plans under tests/replay-plans come from the C conformance runner (make -C tests
 * replay-plans): the initial credential in the library's own encoding, then explicit steps. This
 * test only replays them, so the binding is held to the same expectations as the C engine.
 */
public final class DfcReplayPlanTest {
  private static final class Plan {
    String name;
    byte[] credential = new byte[0];
    boolean finiteRandom;
    String skip;
    final List<String[]> steps = new ArrayList<>();
    byte[] last = new byte[0];
  }

  private static byte[] hex(String text) {
    if (text.equals("-"))
      return new byte[0];
    byte[] out = new byte[text.length() / 2];
    for (int i = 0; i < out.length; i++)
      out[i] = (byte) Integer.parseInt(text.substring(2 * i, 2 * i + 2), 16);
    return out;
  }

  private static String hexString(byte[] bytes) {
    StringBuilder out = new StringBuilder();
    for (byte value : bytes) out.append(String.format("%02X", value));
    return out.toString();
  }

  private static Plan parse(Path path) throws IOException {
    Plan plan = new Plan();
    String file = path.getFileName().toString();
    plan.name = file.substring(0, file.length() - ".plan".length());
    for (String line : Files.readAllLines(path)) {
      int split = line.indexOf(' ');
      String key = split < 0 ? line : line.substring(0, split);
      String rest = split < 0 ? "" : line.substring(split + 1);
      switch (key) {
        case "credential" -> plan.credential = hex(rest);
        case "random" -> plan.finiteRandom = rest.equals("finite");
        case "skip" -> plan.skip = rest;
        case "step" -> plan.steps.add(rest.split(" "));
        case "final" -> plan.last = hex(rest);
        case "plan", "source" -> {
        }
        default -> throw new IllegalStateException(plan.name + ": unknown plan line " + line);
      }
    }
    return plan;
  }

  private static long littleEndian(byte[] bytes, int offset, int length) {
    long value = 0;
    for (int i = length - 1; i >= 0; i--) value = (value << 8) | (bytes[offset + i] & 0xffL);
    return value;
  }

  /** Compares with ?? wildcards and tol=offset+length:delta clauses. */
  private static boolean matches(byte[] actual, String expected, List<String> tolerances) {
    byte[] want = hex(expected.equals("-") ? "-" : expected.replace("??", "00"));
    if (actual.length != want.length)
      return false;
    List<long[]> ranges = new ArrayList<>();
    for (String clause : tolerances) {
      String[] parts = clause.substring("tol=".length()).split("[+:]");
      ranges.add(new long[] {
          Long.parseLong(parts[0]), Long.parseLong(parts[1]), Long.parseLong(parts[2])});
    }
    for (int i = 0; i < want.length; i++) {
      boolean wildcard = expected.startsWith("??", 2 * i);
      boolean tolerated = false;
      for (long[] range : ranges) tolerated |= i >= range[0] && i < range[0] + range[1];
      if (!wildcard && !tolerated && actual[i] != want[i])
        return false;
    }
    for (long[] range : ranges) {
      long got = littleEndian(actual, (int) range[0], (int) range[1]);
      long expect = littleEndian(want, (int) range[0], (int) range[1]);
      if (Math.abs(got - expect) > range[2])
        return false;
    }
    return true;
  }

  private interface Action {
    byte[] run() throws DfcException;
  }

  /** Returns the failure the action raised, or null when it completed. */
  private static DfcException failureOf(Action action) {
    try {
      action.run();
      return null;
    } catch (DfcException error) {
      return error;
    }
  }

  private static int remaining(DfcVirtualPicc picc, Plan plan) throws DfcException {
    return plan.finiteRandom ? picc.replayRandomRemaining() : 0;
  }

  private static final class Outcome {
    final List<String> failures = new ArrayList<>();
    int evaluated;
    int deferred;
  }

  private static Outcome replay(Plan plan) throws Exception {
    Outcome outcome = new Outcome();
    DfcCredential credential = DfcCredentialCodec.decode(plan.credential);
    try (DfcVirtualPicc picc = plan.finiteRandom
            ? DfcVirtualPicc.createForReplay(credential, new byte[0])
            : DfcVirtualPicc.create(credential)) {
      DfcActivation activation = null;
      for (int index = 0; index < plan.steps.size(); index++) {
        String[] step = plan.steps.get(index);
        String where = plan.name + " step " + (index + 1) + " (" + step[0] + ")";
        List<String> args = Arrays.asList(step).subList(1, step.length);
        try {
          switch (step[0]) {
            case "scan" -> activation = picc.activate();
            case "field-off" -> {
              picc.fieldOff();
              activation = null;
            }
            case "clear-dirty" -> picc.markPersisted();
            case "random-clear" -> picc.clearReplayRandom();
            case "random-inject" -> picc.appendReplayRandom(hex(args.get(0)));
            case "advance-time" -> picc.advanceTime(Long.parseLong(args.get(0)));
            case "exchange", "frame" -> {
              byte[] request = hex(args.get(0));
              byte[] actual =
                  step[0].equals("exchange") ? picc.exchange(request) : picc.exchangeFrame(request);
              if (!matches(actual, args.get(1), args.subList(2, args.size())))
                outcome.failures.add(
                    where + ": expected " + args.get(1) + " got " + hexString(actual));
            }
            case "error" -> {
              boolean random = args.get(0).equals("random-source");
              int before = remaining(picc, plan);
              DfcException error = switch (args.get(1)) {
                case "scan" ->
                  failureOf(() -> {
                    picc.activate();
                    return null;
                  });
                case "exchange" -> failureOf(() -> picc.exchange(hex(args.get(2))));
                default -> failureOf(() -> picc.exchangeFrame(hex(args.get(2))));
              };
              if (error == null)
                outcome.failures.add(where + ": expected an error");
              else if ((error.status() == -5) != random)
                outcome.failures.add(where + ": wrong error class, status " + error.status());
              if (random && remaining(picc, plan) != before)
                outcome.failures.add(where + ": failed draw consumed random bytes");
              if (random && args.get(1).equals("scan"))
                activation = null;
            }
            case "assert" -> {
              String path = args.get(0);
              String value = args.get(1);
              if (path.equals("credential.dirty")) {
                outcome.evaluated++;
                if (picc.snapshot().dirty() != !value.equals("0"))
                  outcome.failures.add(where + ": " + path + " expected " + value);
              } else if (path.startsWith("activation.") && activation != null) {
                outcome.evaluated++;
                String field = path.substring("activation.".length());
                String actual = switch (field) {
                  case "uid" -> hexString(activation.uid());
                  case "atqa" -> hexString(activation.atqa());
                  case "ats" -> hexString(activation.ats());
                  case "uid_len" -> Integer.toString(activation.uid().length);
                  case "sak" -> Integer.toString(activation.sak());
                  default -> "unsupported";
                };
                String want = field.equals("uid_len") || field.equals("sak")
                    ? Long.toString(Long.decode(value))
                    : value;
                if (!actual.equalsIgnoreCase(want))
                  outcome.failures.add(
                      where + ": " + path + " expected " + value + " got " + actual);
              } else {
                outcome.deferred++;
              }
            }
            default -> outcome.failures.add(where + ": unknown plan step");
          }
        } catch (DfcException error) {
          outcome.failures.add(where + ": unexpected status " + error.status());
        }
      }
      try (DfcCredential exported = picc.exportCredential()) {
        if (!Arrays.equals(exported.encode(), plan.last))
          outcome.failures.add(plan.name + ": final credential differs from the C engine");
      }
    }
    return outcome;
  }

  public static void main(String[] arguments) throws Exception {
    if (arguments.length != 1)
      throw new AssertionError("replay plan directory required");
    List<Path> paths;
    try (Stream<Path> listing = Files.list(Path.of(arguments[0]))) {
      paths = listing.filter(path -> path.toString().endsWith(".plan")).sorted().toList();
    }
    if (paths.isEmpty())
      throw new AssertionError("no replay plans found; run make -C tests replay-plans");
    List<String> failures = new ArrayList<>();
    Map<String, List<String>> skipped = new TreeMap<>();
    int replayed = 0;
    int evaluated = 0;
    int deferred = 0;
    for (Path path : paths) {
      Plan plan = parse(path);
      if (plan.skip != null) {
        skipped.computeIfAbsent(plan.skip, key -> new ArrayList<>()).add(plan.name);
        continue;
      }
      Outcome outcome = replay(plan);
      failures.addAll(outcome.failures);
      replayed++;
      evaluated += outcome.evaluated;
      deferred += outcome.deferred;
    }
    int skippedCount = skipped.values().stream().mapToInt(List::size).sum();
    System.out.println("java replay: " + replayed + " vectors replayed, " + skippedCount
        + " skipped, " + failures.size() + " failures; " + evaluated + " assertions evaluated, "
        + deferred + " left to the final credential comparison");
    skipped.forEach((reason, names)
                        -> System.out.println("  skipped " + names.size() + ": " + reason + ": "
                            + String.join(", ", names)));
    if (!failures.isEmpty()) {
      failures.stream().limit(20).forEach(System.err::println);
      throw new AssertionError(failures.size() + " replay failures");
    }
    // Exactly these plans are skipped (the plan files carry the reason), and every other plan
    // is replayed: a regression that skips more would otherwise pass.
    List<String> expectedSkips = List.of("v4-emulator-model_key_set_invariants",
        "v4-emulator-model_sdm_encrypted_range_overflow",
        "v4-emulator-vecb-ev1-create-file-full-pool");
    List<String> actualSkips = skipped.values().stream().flatMap(List::stream).sorted().toList();
    if (!actualSkips.equals(expectedSkips))
      throw new AssertionError("unexpected skips: " + actualSkips);
    if (replayed != paths.size() - expectedSkips.size())
      throw new AssertionError("replayed " + replayed + " of " + paths.size() + " plans");
  }
}
