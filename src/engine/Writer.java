package engine;

import pcap.PcapWriter;

public class Writer implements Runnable {

    private final ThreadSafeQueue<byte[]> outputQueue;
    private final String outputFile;

    public Writer(ThreadSafeQueue<byte[]> outputQueue, String outputFile) {
        this.outputQueue = outputQueue;
        this.outputFile = outputFile;
    }

    @Override
    public void run() {

        try {
            PcapWriter writer = new PcapWriter();
            writer.open(outputFile);

            while (true) {

                byte[] raw = outputQueue.pop();

                if (raw == null)
                    break;

                writer.write(raw);
            }

            writer.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}