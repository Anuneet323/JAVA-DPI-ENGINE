package parser;

public class SNIExtractor {

    public static String extract(byte[] raw,
                                 int offset,
                                 int length) {

        if (length < 50) return null;

        try {
            int pos = offset;

            if ((raw[pos] & 0xFF) != 0x16)
                return null;

            pos += 5;

            if ((raw[pos] & 0xFF) != 0x01)
                return null;

            pos += 4;
            pos += 2;
            pos += 32;

            int sessionLen = raw[pos] & 0xFF;
            pos += 1 + sessionLen;

            int cipherLen =
                    ((raw[pos] & 0xFF) << 8)
                            | (raw[pos+1] & 0xFF);
            pos += 2 + cipherLen;

            int compLen = raw[pos] & 0xFF;
            pos += 1 + compLen;

            int extLen =
                    ((raw[pos] & 0xFF) << 8)
                            | (raw[pos+1] & 0xFF);
            pos += 2;

            int end = pos + extLen;

            while (pos + 4 <= end) {

                int type =
                        ((raw[pos] & 0xFF) << 8)
                                | (raw[pos+1] & 0xFF);

                int size =
                        ((raw[pos+2] & 0xFF) << 8)
                                | (raw[pos+3] & 0xFF);

                pos += 4;

                if (type == 0x0000) {

                    pos += 2;
                    pos += 1;

                    int nameLen =
                            ((raw[pos] & 0xFF) << 8)
                                    | (raw[pos+1] & 0xFF);

                    pos += 2;

                    return new String(raw,
                            pos, nameLen);
                }

                pos += size;
            }

        } catch (Exception ignored) {}

        return null;
    }
}