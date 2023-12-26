package de.org.mchahn.crypto.blowfishj;

/**
 * Some helper routines for data conversion. All data is treated in network byte
 * order, as it is the standard for the Blowfish algorithm.
 */
public class BinConverter {

    private BinConverter() {}

    /**
     * Converts bytes from an array into an integer.
     * @param buf The source buffer..
     * @param ofs index From where to start reading the data.
     * @return The 32bit integer value.
     */
    public static final int byteArrayToInt(byte[] buf, int ofs) {
        return (buf[ofs    ]          << 24)
            | ((buf[ofs + 1] & 0x0ff) << 16)
            | ((buf[ofs + 2] & 0x0ff) <<  8)
            | ( buf[ofs + 3] & 0x0ff);
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Stores an integer into a byte array.
     * @param value The 32bit integer to store.
     * @param buf The target buffer.
     * @param ofs Where to start writing in the target buffer.
     */
    public static final void intToByteArray(int value, byte[] buf, int ofs) {
        buf[ofs    ] = (byte)((value >>> 24) & 0x0ff);
        buf[ofs + 1] = (byte)((value >>> 16) & 0x0ff);
        buf[ofs + 2] = (byte)((value >>>  8) & 0x0ff);
        buf[ofs + 3] = (byte)  value;
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Converts bytes from an array into a 64bit integer.
     * @param buf The source buffer.
     * @param ofs From where to start reading in the source buffer.
     * @return The 64bit integer.
     */
    public static final long byteArrayToLong(byte[] buf, int ofs) {
        // (optimized for 32bit platforms)

        return
            ((long)(( buf[ofs    ]           << 24) |
                    ((buf[ofs + 1] & 0x0ff)  << 16) |
                    ((buf[ofs + 2] & 0x0ff)  <<  8) |
                    ( buf[ofs + 3] & 0x0ff)) << 32) |
                  ((( buf[ofs + 4]           << 24) |
                    ((buf[ofs + 5] & 0x0ff)  << 16) |
                    ((buf[ofs + 6] & 0x0ff)  <<  8) |
                    ( buf[ofs + 7] & 0x0ff        )) & 0x0ffffffffL);
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Stores a 64bit integer into a byte array.
     * @param value The 64bit integer to store.
     * @param buf The target buffer.
     * @param ofs Where to start writing in the target buffer.
     */
    public static final void longToByteArray(long value, byte[] buf, int ofs) {
        int tmp = (int)(value >>> 32);

        buf[ofs    ] = (byte) (tmp >>> 24);
        buf[ofs + 1] = (byte)((tmp >>> 16) & 0x0ff);
        buf[ofs + 2] = (byte)((tmp >>>  8) & 0x0ff);
        buf[ofs + 3] = (byte)  tmp;

        tmp = (int)value;

        buf[ofs + 4] = (byte) (tmp >>> 24);
        buf[ofs + 5] = (byte)((tmp >>> 16) & 0x0ff);
        buf[ofs + 6] = (byte)((tmp >>>  8) & 0x0ff);
        buf[ofs + 7] = (byte)  tmp;
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Converts values from a 32bit integer array to 64bit integer.
     * @param buf Buffer to read the 32bit integers from.
     * @param ofs Where to start reading in the buffer.
     * @return The 64bit integer.
     */
    public static final long intArrayToLong(int[] buf, int ofs) {
        return (((long)buf[ofs    ]) << 32) |
               ((      buf[ofs + 1]) & 0x0ffffffffL);
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Stores a 64bit integer into a 32bit integer array.
     * @param value The 64bit integer to store.
     * @param buf The target buffer.
     * @param ofs Where to start writing in the target buffer.
     */
    public static final void longToIntArray(long value, int[] buf, int ofs) {
        buf[ofs    ] = (int)(value >>> 32);
        buf[ofs + 1] = (int) value;
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Makes a 64bit integer out if two 32bit integers.
     * @param lo The lower 32bits.
     * @param hi The higher 32bits.
     * @return The 64bit integer.
     */
    public static final long makeLong(int lo, int hi) {
        return (((long)hi << 32) |
                (     lo & 0x00000000ffffffffL));
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Gets the lower 32 bits of a 64bit integer.
     * @param val The 64bit integer.
     * @return The lower 32 bits.
     */
    public static final int longLo32(long val) {
        return (int)val;
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Gets the higher 32 bits of a 64bit integer.
     * @param val The 64bit integer.
     * @return The higher 32 bits.
     */
    public static final int longHi32(long val) {
        return (int)(val >>> 32);
    }

    ///////////////////////////////////////////////////////////////////////////

    static final char[] HEXTAB = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'
    };

    /**
     * Converts a byte array to a hex-string representation.
     * @param data The byte array.
     * @return The hex string, twice the length of the byte array.
     */
    public static final String bytesToHexStr(byte[] data) {
        return bytesToHexStr(data, 0, data.length);
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Converts parts of a byte array to a hex string.
     * @param data The byte array.
     * @param ofs Where to start reading the bytes.
     * @param len The number of bytes to convert.
     * @return The hex string, twice the length of the len parameter.
     */
    public static final String bytesToHexStr(byte[] data, int ofs, int len) {
        StringBuilder sb = new StringBuilder();
        sb.setLength(len << 1);

        int pos = 0;
        int c = ofs + len;

        while (ofs < c) {
            sb.setCharAt(pos++, HEXTAB[(data[ofs  ] >> 4) & 0x0f]);
            sb.setCharAt(pos++, HEXTAB[ data[ofs++]       & 0x0f]);
        }
        return sb.toString();
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Converts a hex-string into a byte array. Invalid codes will be skipped.
     * If the target buffer is not large enough the data will be truncated.
     * @param hex The hex-string.
     * @param data The target buffer.
     * @param srcofs From which character in the string the conversion should
     * begin. This is usually an even number, but it doesn't have to.
     * @param dstofs Where to start storing the bytes in the target buffer.
     * @param len The number of bytes to extract.
     * @return The number of extracted bytes.
     */
    public static final int hexStrToBytes(
        String hex,
        byte[] data,
        int srcofs,
        int dstofs,
        int len) {
        // check for correct ranges

        final int strlen = hex.length();

        int availBytes = (strlen - srcofs) >> 1;
        if (availBytes < len) {
            len = availBytes;
        }

        final int outputCapacity = data.length - dstofs;
        if (len > outputCapacity) {
            len = outputCapacity;
        }

        // convert now

        final int dstofsBak = dstofs;

        for (int i = 0; i < len; i++) {
            byte abyte = 0;
            boolean convertOK = true;

            for (int j = 0; j < 2; j++) {
                abyte <<= 4;
                char cActChar = hex.charAt(srcofs++);

                if ((cActChar >= 'a') && (cActChar <= 'f')) {
                    abyte |= (byte) (cActChar - 'a') + 10;
                }
                else {
                    if ((cActChar >= '0') && (cActChar <= '9')) {
                        abyte |= (byte) (cActChar - '0');
                    }
                    else {
                        convertOK = false;
                    }
                }
            }
            if (convertOK) {
                data[dstofs++] = abyte;
            }
        }

        return (dstofs - dstofsBak);
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Converts bytes into a string. Two bytes are read in big endian and
     * converted to one Unicode character.
     * @param data The source buffer.
     * @param ofs Where to start reading in the source buffer.
     * @param len Number of bytes to convert. It should be an even number, since
     * two bytes make one character. If odd the last byte is ignored.
     * @return The string.
     */
    public static final String byteArrayToStr(byte[] data, int ofs, int len) {
        // we need two bytes for every character
        len &= ~1;

        // enough bytes in the buffer?
        final int availCapacity = data.length - ofs;

        if (availCapacity < len) {
            len = availCapacity;
        }

        final StringBuilder sb = new StringBuilder();
        sb.setLength(len >> 1);

        int sbufPos = 0;

        while (0 < len) {
            sb.setCharAt(
                sbufPos++,
                (char)((data[ofs    ] << 8)
                    |  (data[ofs + 1] & 0x0ff)));
            ofs += 2;
            len -= 2;
        }

        return sb.toString();
    }
}
