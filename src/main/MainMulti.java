package main;

import pcap.PcapReader;
import parser.PacketParser;
import engine.Flow;
import engine.FlowTracker;
import engine.RuleManager;
import engine.Statistics;
import model.Packet;

import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

public class MainMulti {

    public static void main(String[] args) throws Exception {

        PcapReader reader = new PcapReader();
        reader.open("test_dpi.pcap");

        FlowTracker tracker = new FlowTracker();
        RuleManager rules = new RuleManager();
        Statistics stats = new Statistics();

        BlockingQueue<Packet> queue =
                new LinkedBlockingQueue<>(10000);

        ExecutorService workers =
                Executors.newFixedThreadPool(4);

        for (int i = 0; i < 4; i++) {
            workers.submit(() -> {
                try {
                    while (true) {
                        Packet pkt = queue.take();
                        process(pkt, tracker, rules, stats);
                    }
                } catch (InterruptedException ignored) {}
            });
        }

        byte[] raw;

        while ((raw = reader.readPacket()) != null) {

            Packet pkt = PacketParser.parse(raw);
            if (pkt == null) continue;

            stats.incrementTotal();
            queue.put(pkt);
        }

        workers.shutdown();
        workers.awaitTermination(1, TimeUnit.MINUTES);

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