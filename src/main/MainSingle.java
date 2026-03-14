package main;

import pcap.PcapReader;
import parser.PacketParser;
import parser.SNIExtractor;
import parser.HTTPExtractor;
import parser.DNSDetector;

import engine.FlowTracker;
import engine.RuleManager;
import engine.Statistics;

import model.Packet;
import model.FiveTuple;
import model.AppType;
import model.Flow;

public class MainSingle {

    public static void main(String[] args) throws Exception {

        String inputFile = args.length > 0 ? args[0] : "test_dpi.pcap";

        PcapReader reader = new PcapReader();
        reader.open(inputFile);

        FlowTracker tracker = new FlowTracker();
        RuleManager rules = new RuleManager();
        Statistics stats = new Statistics();

        // Example rules
        rules.blockApp(AppType.YOUTUBE);
        rules.blockDomain("facebook");

        try {
            byte[] raw;

            while ((raw = reader.readPacket()) != null) {

                Packet pkt = PacketParser.parse(raw);
                if (pkt == null)
                    continue;

                stats.incrementTotal();

                FiveTuple tuple = pkt.getTuple();
                Flow flow = tracker.get(tuple);

                byte protocol = tuple.getProtocol();
                int srcPort = tuple.getSrcPort();
                int dstPort = tuple.getDstPort();

                // ---------------- DNS ----------------
                if (DNSDetector.isDNS(protocol, srcPort, dstPort)) {
                    flow.setAppType(AppType.DNS);
                }

                // ---------------- HTTPS (TLS SNI) ----------------
                else if (protocol == 6 && dstPort == 443) {

                    String domain = SNIExtractor.extract(
                            pkt.getRaw(),
                            pkt.getPayloadOffset(),
                            pkt.getPayloadLength()
                    );

                    if (domain != null) {

                        flow.setDomain(domain);

                        if (domain.contains("youtube"))
                            flow.setAppType(AppType.YOUTUBE);
                        else if (domain.contains("facebook"))
                            flow.setAppType(AppType.FACEBOOK);
                        else
                            flow.setAppType(AppType.HTTPS);
                    }
                }

                // ---------------- HTTP ----------------
                else if (protocol == 6 && dstPort == 80) {

                    String domain = HTTPExtractor.extract(
                            pkt.getRaw(),
                            pkt.getPayloadOffset(),
                            pkt.getPayloadLength()
                    );

                    if (domain != null) {
                        flow.setDomain(domain);
                        flow.setAppType(AppType.HTTP);
                    }
                }

                // ---------------- RULE CHECK ----------------
                if (rules.isBlocked(
                        flow.getAppType(),
                        flow.getDomain())) {

                    flow.setBlocked(true);
                    stats.incrementDropped();
                    continue;
                }

                stats.incrementForwarded();
            }
        } finally {
            reader.close();
        }

        // ---------------- FINAL REPORT ----------------
        System.out.println("========== DPI SINGLE THREAD REPORT ==========");
        System.out.println("Total Packets : " + stats.getTotal());
        System.out.println("Forwarded     : " + stats.getForwarded());
        System.out.println("Dropped       : " + stats.getDropped());
        System.out.println("==============================================");
    }
}