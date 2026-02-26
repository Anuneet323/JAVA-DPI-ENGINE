package parser;

public class DNSDetector {

    public static boolean isDNS(byte protocol,
                                int srcPort,
                                int dstPort) {

        // DNS mostly runs on UDP
        if (protocol != 17)
            return false;

        return srcPort == 53 || dstPort == 53;
    }
}