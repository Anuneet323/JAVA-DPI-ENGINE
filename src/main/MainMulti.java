package main;

import pcap.PcapReader;
import parser.PacketParser;
import engine.FlowTracker;
import engine.RuleManager;
import engine.Statistics;
import model.Packet;
import model.FiveTuple;
import model.Flow;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class MainMulti {

    private static final int WORKER_COUNT = 4;
    private static final Packet POISON_PACKET =
        new Packet(new byte[0], 0, 0,
            new FiveTuple(0, 0, 0, 0, (byte) 0));

    public static void main(String[] args) throws Exception {

        String inputFile = args.length > 0 ? args[0] : "test_dpi.pcap";

        PcapReader reader = new PcapReader();
        reader.open(inputFile);

        FlowTracker tracker = new FlowTracker();
        RuleManager rules = new RuleManager();
        Statistics stats = new Statistics();

        BlockingQueue<Packet> queue =
                new LinkedBlockingQueue<>(10000);

        ExecutorService workers =
                Executors.newFixedThreadPool(WORKER_COUNT);

        for (int i = 0; i < WORKER_COUNT; i++) {
            workers.submit(() -> {
                try {
                    while (true) {
                        Packet pkt = queue.take();
                        if (pkt == POISON_PACKET) {
                            break;
                        }
                        process(pkt, tracker, rules, stats);
                    }
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                }
            });
        }

        try {
            byte[] raw;

            while ((raw = reader.readPacket()) != null) {

                Packet pkt = PacketParser.parse(raw);
                if (pkt == null) {
                    continue;
                }

                stats.incrementTotal();
                queue.put(pkt);
            }
        } finally {
            reader.close();
        }

        for (int i = 0; i < WORKER_COUNT; i++) {
            queue.put(POISON_PACKET);
        }

        workers.shutdown();
        if (!workers.awaitTermination(1, TimeUnit.MINUTES)) {
            workers.shutdownNow();
        }

        stats.print();
    }

    private static void process(Packet pkt,
                                FlowTracker tracker,
                                RuleManager rules,
                                Statistics stats) {

        Flow flow = tracker.get(pkt.getTuple());

        if (rules.isBlocked(
                flow.getAppType(),
                flow.getDomain())) {

            flow.setBlocked(true);
            stats.incrementDropped();
            return;
        }

        stats.incrementForwarded();
    }
}