package parser;

import java.nio.charset.StandardCharsets;

public class HTTPExtractor {

    public static String extract(byte[] raw,
                                 int offset,
                                 int length) {

        if (length < 20)
            return null;

        try {

            // Convert only payload region to string
            String data = new String(
                    raw,
                    offset,
                    length,
                    StandardCharsets.US_ASCII
            );

            // Check if it's HTTP request
            if (!data.startsWith("GET") &&
                    !data.startsWith("POST") &&
                    !data.startsWith("HEAD"))
                return null;

            int hostIndex = data.indexOf("Host:");
            if (hostIndex == -1)
                return null;

            int start = hostIndex + 5;
            int end = data.indexOf("\r\n", start);

            if (end == -1)
                return null;

            return data.substring(start, end).trim();

        } catch (Exception e) {
            return null;
        }
    }
}