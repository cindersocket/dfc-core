package com.cindersocket.dfc;

/** A validation, protocol, transport, or native-library failure. */
public final class DfcException extends Exception {
    private final int status;
    private final int line;
    private final int cardStatus;
    public DfcException(String message, int status, int line, int cardStatus) {
        super(message); this.status = status; this.line = line; this.cardStatus = cardStatus;
    }
    public int status() { return status; }
    public int line() { return line; }
    public int cardStatus() { return cardStatus; }
}
