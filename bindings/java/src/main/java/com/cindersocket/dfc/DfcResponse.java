package com.cindersocket.dfc;

/** The unwrapped response data and card status from one completed exchange. */
public record DfcResponse(byte[] data, int status) {
    public DfcResponse {
        data = data.clone();
        if ((status & ~0xff) != 0) throw new IllegalArgumentException("status");
    }
    @Override public byte[] data() { return data.clone(); }
    public boolean successful() { return status == 0; }
}
