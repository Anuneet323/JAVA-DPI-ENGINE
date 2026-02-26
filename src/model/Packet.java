package model;

public class Packet {

    private final byte[] raw;
    private final int payloadOffset;
    private final int payloadLength;
    private final FiveTuple tuple;

    public Packet(byte[] raw,
                  int payloadOffset,
                  int payloadLength,
                  FiveTuple tuple) {

        this.raw = raw;
        this.payloadOffset = payloadOffset;
        this.payloadLength = payloadLength;
        this.tuple = tuple;
    }

    public byte[] getRaw() { return raw; }
    public int getPayloadOffset() { return payloadOffset; }
    public int getPayloadLength() { return payloadLength; }
    public FiveTuple getTuple() { return tuple; }
}