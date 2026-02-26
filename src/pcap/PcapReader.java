package pcap;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapReader {

    private FileInputStream fis;
    private ByteOrder byteOrder;
    private int snapLen;

    private static final int GLOBAL_HEADER_SIZE = 24;
    private static final int PACKET_HEADER_SIZE = 16;

    public void open(String file) throws IOException {

        fis = new FileInputStream(file);

        byte[] globalHeader = new byte[GLOBAL_HEADER_SIZE];

        if (readFully(globalHeader) != GLOBAL_HEADER_SIZE) {
            throw new IOException("Invalid PCAP global header");
        }

        byteOrder = PcapGlobalHeader.detect(globalHeader);
        snapLen = PcapGlobalHeader.getSnapLen(globalHeader, byteOrder);

        if (snapLen <= 0)
            snapLen = 1_000_000; // fallback safety
    }

    public byte[] readPacket() throws IOException {

        while (true) {

            byte[] header = new byte[PACKET_HEADER_SIZE];

            if (readFully(header) < PACKET_HEADER_SIZE) {
                return null; // EOF
            }

            ByteBuffer bb = ByteBuffer.wrap(header);
            bb.order(byteOrder);

            bb.getInt(); // ts_sec
            bb.getInt(); // ts_usec
            int inclLen = bb.getInt();
            bb.getInt(); // orig_len

            if (inclLen <= 0 || inclLen > snapLen) {
                continue; // skip invalid packet
            }

            byte[] data = new byte[inclLen];

            if (readFully(data) < inclLen) {
                return null;
            }

            return data;
        }
    }

    private int readFully(byte[] buffer) throws IOException {

        int totalRead = 0;

        while (totalRead < buffer.length) {
            int r = fis.read(buffer, totalRead,
                    buffer.length - totalRead);

            if (r == -1)
                break;

            totalRead += r;
        }

        return totalRead;
    }

    public void close() throws IOException {
        if (fis != null)
            fis.close();
    }
}