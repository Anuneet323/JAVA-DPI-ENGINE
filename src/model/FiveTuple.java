package model;

public class FiveTuple {

    private final int srcIp;
    private final int dstIp;
    private final int srcPort;
    private final int dstPort;
    private final byte protocol;

    public FiveTuple(int srcIp, int dstIp,
                     int srcPort, int dstPort,
                     byte protocol) {
        this.srcIp = srcIp;
        this.dstIp = dstIp;
        this.srcPort = srcPort;
        this.dstPort = dstPort;
        this.protocol = protocol;
    }

    public int getSrcIp() { return srcIp; }
    public int getDstIp() { return dstIp; }
    public int getSrcPort() { return srcPort; }
    public int getDstPort() { return dstPort; }
    public byte getProtocol() { return protocol; }

    @Override
    public int hashCode() {
        int result = srcIp;
        result = 31 * result + dstIp;
        result = 31 * result + srcPort;
        result = 31 * result + dstPort;
        result = 31 * result + protocol;
        return result;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof FiveTuple)) return false;
        FiveTuple t = (FiveTuple) o;
        return srcIp == t.srcIp &&
                dstIp == t.dstIp &&
                srcPort == t.srcPort &&
                dstPort == t.dstPort &&
                protocol == t.protocol;
    }
}