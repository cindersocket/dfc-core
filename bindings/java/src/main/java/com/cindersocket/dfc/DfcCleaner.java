package com.cindersocket.dfc;

import java.lang.ref.PhantomReference;
import java.lang.ref.ReferenceQueue;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/** API-26-compatible native-resource reaper. */
final class DfcCleaner {
  interface Cleanable {
    void clean();
  }
  private static final ReferenceQueue<Object> QUEUE = new ReferenceQueue<>();
  private static final Set<Entry> ENTRIES = ConcurrentHashMap.newKeySet();
  static {
    Thread thread = new Thread(() -> {
      for (;;) {
        try {
          ((Entry) QUEUE.remove()).clean();
        } catch (InterruptedException ignored) {
          Thread.currentThread().interrupt();
          return;
        }
      }
    }, "dfc-native-cleaner");
    thread.setDaemon(true);
    thread.start();
  }
  private DfcCleaner() {}
  static Cleanable register(Object owner, Runnable cleanup) {
    Entry entry = new Entry(owner, cleanup);
    ENTRIES.add(entry);
    return entry;
  }
  private static final class Entry extends PhantomReference<Object> implements Cleanable {
    private Runnable cleanup;
    Entry(Object owner, Runnable cleanup) {
      super(owner, QUEUE);
      this.cleanup = cleanup;
    }
    @Override
    public synchronized void clean() {
      if (cleanup == null)
        return;
      cleanup.run();
      cleanup = null;
      clear();
      ENTRIES.remove(this);
    }
  }
}
