package de.org.mchahn.crypto.blowfishj;

import org.junit.Test;

import de.org.mchahn.crypto.blowfishj.BinConverter;

import static org.junit.Assert.assertEquals;

/**
 * Test cases for the binary converters.
 */
public class BinConverterTest {

    @Test
    public void testByteArrayToInt() {
        byte[] dat = { 0, (byte)0xcc, (byte)0xaf, 0x43, 0x1e };

        assertEquals(0x00ccaf43, BinConverter.byteArrayToInt(dat, 0));
        assertEquals(0xccaf431e, BinConverter.byteArrayToInt(dat, 1));
    }

    ///////////////////////////////////////////////////////////////////////////

    @Test
    public void testIntToByteArray() {
        byte[] testb = new byte[5];

        BinConverter.intToByteArray(0x01234567, testb, 0);

        assertEquals(0x01, testb[0]);
        assertEquals(0x23, testb[1]);
        assertEquals(0x45, testb[2]);
        assertEquals(0x67, testb[3]);

        BinConverter.intToByteArray(0x89abcdef, testb, 1);

        assertEquals((byte)0x89, testb[1]);
        assertEquals((byte)0xab, testb[2]);
        assertEquals((byte)0xcd, testb[3]);
        assertEquals((byte)0xef, testb[4]);
    }

    ///////////////////////////////////////////////////////////////////////////

    @Test
    public void testByteArrayToLong() {
        byte[] dat = {
            (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
            (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
            (byte)0xcc
        };

        assertEquals(0x0123456789abcdefL, BinConverter.byteArrayToLong(dat, 0));
        assertEquals(0x23456789abcdefccL, BinConverter.byteArrayToLong(dat, 1));
    }

    ///////////////////////////////////////////////////////////////////////////

    @Test
    public void testLongToByteArray() {
        byte[] testb = new byte[9];

        BinConverter.longToByteArray(0x0123456789abcdefL, testb, 0);

        assertEquals((byte)0x01, testb[0]);
        assertEquals((byte)0x23, testb[1]);
        assertEquals((byte)0x45, testb[2]);
        assertEquals((byte)0x67, testb[3]);
        assertEquals((byte)0x89, testb[4]);
        assertEquals((byte)0xab, testb[5]);
        assertEquals((byte)0xcd, testb[6]);
        assertEquals((byte)0xef, testb[7]);

        BinConverter.longToByteArray(0x0123456789abcdefL, testb, 1);

        assertEquals((byte)0x01, testb[1]);
        assertEquals((byte)0x23, testb[2]);
        assertEquals((byte)0x45, testb[3]);
        assertEquals((byte)0x67, testb[4]);
        assertEquals((byte)0x89, testb[5]);
        assertEquals((byte)0xab, testb[6]);
        assertEquals((byte)0xcd, testb[7]);
        assertEquals((byte)0xef, testb[8]);
    }

    ///////////////////////////////////////////////////////////////////////////

    @Test
    public void testIntArrayToLong() {
        int[] dat = { 0x01234567, 0x89abcdef, 0xcc01aa02 };

        assertEquals(0x0123456789abcdefL, BinConverter.intArrayToLong(dat, 0));
        assertEquals(0x89abcdefcc01aa02L, BinConverter.intArrayToLong(dat, 1));
    }

    ///////////////////////////////////////////////////////////////////////////

    @Test
    public void testLongToIntArray() {
        int[] testn = new int[3];

        BinConverter.longToIntArray(0x0123456789abcdefL, testn, 0);

        assertEquals(0x01234567, testn[0]);
        assertEquals(0x89abcdef, testn[1]);

        BinConverter.longToIntArray(0x0123456789abcdefL, testn, 1);

        assertEquals(0x01234567, testn[1]);
        assertEquals(0x89abcdef, testn[2]);
    }

    ///////////////////////////////////////////////////////////////////////////

    @Test
    public void testMakeLong() {
        assertEquals(0x0123456789abcdefL, BinConverter.makeLong(0x89abcdef, 0x01234567));
    }

    ///////////////////////////////////////////////////////////////////////////

    @Test
    public void testLongLo32() {
        assertEquals(0x89abcdef, BinConverter.longLo32(0x0123456789abcdefL));
    }

    ///////////////////////////////////////////////////////////////////////////

    @Test
    public void testLongHi32() {
        assertEquals(0x01234567, BinConverter.longHi32(0x0123456789abcdefL));
    }

    ///////////////////////////////////////////////////////////////////////////

    @Test
    public void testBytesToHexStr() {
        byte[] dat = {
            (byte)0x01, (byte)0x23, (byte)0x45, (byte)0x67,
            (byte)0x89, (byte)0xab, (byte)0xcd, (byte)0xef,
        };

        String sHex = "0123456789abcdef";

        assertEquals(sHex, BinConverter.bytesToHexStr(dat));

        sHex = "456789abcd";

        assertEquals(sHex, BinConverter.bytesToHexStr(dat, 2, 5));
    }

    ///////////////////////////////////////////////////////////////////////////

    @Test
    public void testhexStrToBytes() {
        byte[] testb = new byte[9];

        BinConverter.hexStrToBytes("0123456789abcdef", testb, 0, 0, 8);

        assertEquals((byte)0x01, testb[0]);
        assertEquals((byte)0x23, testb[1]);
        assertEquals((byte)0x45, testb[2]);
        assertEquals((byte)0x67, testb[3]);
        assertEquals((byte)0x89, testb[4]);
        assertEquals((byte)0xab, testb[5]);
        assertEquals((byte)0xcd, testb[6]);
        assertEquals((byte)0xef, testb[7]);

        BinConverter.hexStrToBytes("0123456789abcdef", testb, 4, 1, 5);

        assertEquals((byte)0x45, testb[1]);
        assertEquals((byte)0x67, testb[2]);
        assertEquals((byte)0x89, testb[3]);
        assertEquals((byte)0xab, testb[4]);
        assertEquals((byte)0xcd, testb[5]);
    }

    ///////////////////////////////////////////////////////////////////////////

    @Test
    public void testByteArrayToStr() {
        byte[] testb = new byte[52];

        for (int i = 0; i < testb.length; i += 2) {
            testb[i    ] = 0;
            testb[i + 1] = (byte)(0x061 + (i >> 1));
        }

        assertEquals(
            "abcdefghijklmnopqrstuvwxyz",
            BinConverter.byteArrayToStr(testb, 0, testb.length)
        );
    }
}
