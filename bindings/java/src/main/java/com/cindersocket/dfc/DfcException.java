package com.cindersocket.dfc;

/** A validation, protocol, transport, or native-library failure. */
public final class DfcException extends Exception {
  /** Native binding status. */
  private final int status;
  /** Source line for text-format failures. */
  private final int line;
  /** Card status, or a negative value when unavailable. */
  private final int cardStatus;
  /**
   * Creates a failure with native, source-line, and card-status detail.
   *
   * @param message human-readable failure description
   * @param status native binding status
   * @param line source line reported for text-format failures, or zero
   * @param cardStatus unsigned card status, or a negative value when unavailable
   */
  public DfcException(String message, int status, int line, int cardStatus) {
    super(message);
    this.status = status;
    this.line = line;
    this.cardStatus = cardStatus;
  }
  /**
   * Returns the binding status.
   * @return native status value
   */
  public int status() {
    return status;
  }
  /**
   * Returns text error location.
   * @return source line, or zero
   */
  public int line() {
    return line;
  }
  /**
   * Returns the card status.
   * @return unsigned value, or a negative value when unavailable
   */
  public int cardStatus() {
    return cardStatus;
  }
}
