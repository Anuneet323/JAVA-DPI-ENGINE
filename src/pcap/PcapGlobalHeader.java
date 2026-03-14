package pcap;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapGlobalHeader {

    public static ByteOrder detect(byte[] header) {

        int magic =
                (header[0] & 0xFF) |
                        ((header[1] & 0xFF) << 8) |
                        ((header[2] & 0xFF) << 16) |
                        ((header[3] & 0xFF) << 24);

        // In this integer construction, little-endian files (bytes d4 c3 b2 a1)
        // produce 0xa1b2c3d4, and big-endian files produce 0xd4c3b2a1.
        if (magic == 0xa1b2c3d4)
            return ByteOrder.LITTLE_ENDIAN;

        if (magic == 0xd4c3b2a1)
            return ByteOrder.BIG_ENDIAN;

        throw new IllegalArgumentException("Invalid PCAP magic");
    }

    public static int getSnapLen(byte[] header,
                                 ByteOrder order) {

        ByteBuffer bb = ByteBuffer.wrap(header);
        bb.order(order);

        bb.getInt();   // magic
        bb.getShort(); // major
        bb.getShort(); // minor
        bb.getInt();   // thiszone
        bb.getInt();   // sigfigs

        return bb.getInt(); // snaplen
    }
}