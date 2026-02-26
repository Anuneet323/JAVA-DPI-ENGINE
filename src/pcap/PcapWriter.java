package pcap;

import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

public class PcapWriter {

    private FileOutputStream fos;
    private final ByteOrder order = ByteOrder.LITTLE_ENDIAN;

    private static final int GLOBAL_HEADER_SIZE = 24;
    private static final int PACKET_HEADER_SIZE = 16;

    public void open(String file) throws IOException {

        fos = new FileOutputStream(file);

        ByteBuffer bb = ByteBuffer.allocate(GLOBAL_HEADER_SIZE);
        bb.order(order);

        // Magic number for little-endian PCAP
        bb.putInt(0xd4c3b2a1);
        bb.putShort((short) 2);
        bb.putShort((short) 4);
        bb.putInt(0);
        bb.putInt(0);
        bb.putInt(65535); // safer snaplen
        bb.putInt(1);     // Ethernet

        fos.write(bb.array());
    }

    public synchronized void write(byte[] packetData) throws IOException {

        if (packetData == null || packetData.length == 0)
            return;

        ByteBuffer bb = ByteBuffer.allocate(PACKET_HEADER_SIZE);
        bb.order(order);

        long now = System.currentTimeMillis();
        int tsSec = (int) (now / 1000);
        int tsUsec = (int) ((now % 1000) * 1000);

        bb.putInt(tsSec);
        bb.putInt(tsUsec);
        bb.putInt(packetData.length);
        bb.putInt(packetData.length);

        fos.write(bb.array());
        fos.write(packetData);
    }

    public void close() throws IOException {
        if (fos != null)
            fos.close();
    }
}