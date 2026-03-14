package parser;

import model.*;

public class PacketParser {

    private static final int ETH_HEADER = 14;
    private static final int ETH_IPV4 = 0x0800;
    private static final int ETH_VLAN = 0x8100;
    private static final int ETH_QINQ = 0x88A8;

    public static Packet parse(byte[] raw) {

        if (raw == null || raw.length < ETH_HEADER + 20)
            return null;

        int etherType = ((raw[12] & 0xFF) << 8)
                | (raw[13] & 0xFF);
        int ipOffset = ETH_HEADER;

        // Handle one or more VLAN tags before IPv4 EtherType.
        while (etherType == ETH_VLAN || etherType == ETH_QINQ) {
            if (raw.length < ipOffset + 4 + 20) {
                return null;
            }
            etherType = ((raw[ipOffset + 2] & 0xFF) << 8)
                    | (raw[ipOffset + 3] & 0xFF);
            ipOffset += 4;
        }

        if (etherType != ETH_IPV4)
            return null;

        if (raw.length < ipOffset + 20)
            return null;

        int version = (raw[ipOffset] >> 4) & 0xF;
        if (version != 4)
            return null;

        int ihl = (raw[ipOffset] & 0x0F) * 4;
        if (ihl < 20)
            return null;

        if (raw.length < ipOffset + ihl)
            return null;

        int l4Offset = ipOffset + ihl;

        byte protocol = raw[ipOffset + 9];

        if (protocol != 6 && protocol != 17)
            return null;

        if (raw.length < l4Offset + 4)
            return null;

        int srcIp =
                ((raw[ipOffset+12] & 0xFF) << 24) |
                        ((raw[ipOffset+13] & 0xFF) << 16) |
                        ((raw[ipOffset+14] & 0xFF) << 8) |
                        (raw[ipOffset+15] & 0xFF);

        int dstIp =
                ((raw[ipOffset+16] & 0xFF) << 24) |
                        ((raw[ipOffset+17] & 0xFF) << 16) |
                        ((raw[ipOffset+18] & 0xFF) << 8) |
                        (raw[ipOffset+19] & 0xFF);

        int srcPort =
                ((raw[l4Offset] & 0xFF) << 8) |
                        (raw[l4Offset+1] & 0xFF);

        int dstPort =
                ((raw[l4Offset+2] & 0xFF) << 8) |
                        (raw[l4Offset+3] & 0xFF);

        int payloadOffset;

        if (protocol == 6) {
            if (raw.length < l4Offset + 13)
                return null;

            int tcpHeaderLen =
                    ((raw[l4Offset+12] >> 4) & 0xF) * 4;

            if (tcpHeaderLen < 20)
                return null;

            payloadOffset = l4Offset + tcpHeaderLen;
        } else {
            if (raw.length < l4Offset + 8)
                return null;

            payloadOffset = l4Offset + 8;
        }

        if (payloadOffset > raw.length)
            return null;

        int payloadLength = raw.length - payloadOffset;

        FiveTuple tuple = new FiveTuple(
                srcIp, dstIp, srcPort, dstPort, protocol
        );

        return new Packet(raw, payloadOffset,
                payloadLength, tuple);
    }
}