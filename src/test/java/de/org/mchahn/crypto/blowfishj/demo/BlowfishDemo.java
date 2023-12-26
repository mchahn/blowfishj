package de.org.mchahn.crypto.blowfishj.demo;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStreamReader;
import java.io.LineNumberReader;
import java.security.SecureRandom;

import de.org.mchahn.crypto.blowfishj.BinConverter;
import de.org.mchahn.crypto.blowfishj.Blowfish;
import de.org.mchahn.crypto.blowfishj.BlowfishCBC;
import de.org.mchahn.crypto.blowfishj.BlowfishCFB;
import de.org.mchahn.crypto.blowfishj.BlowfishECB;
import de.org.mchahn.crypto.blowfishj.BlowfishEasy;
import de.org.mchahn.crypto.blowfishj.BlowfishInputStream;
import de.org.mchahn.crypto.blowfishj.BlowfishOutputStream;

/**
 * Demonstrating the Blowfish encryption algorithm classes.
 */
public class BlowfishDemo {

    // benchmark settings
    static final int TESTBUFSIZE = 100000;
    static final int TESTLOOPS = 10000;

    // some BlowfishEasy test material (also counts to produce reference data)
    static final String BFEASY_REF_PASSW = "secret";
    static final String BFEASY_REF_TEXT = "Protect me.";

    // startup CBC IV
    static final long CBCIV_START = 0x0102030405060708L;

    // things necessary for compatibility testing with Blowfish.NET
    static final byte[] XCHG_KEY = {
        (byte)0xaa, (byte)0xbb, (byte)0xcc, 0x00, 0x42, 0x33
    };
    static final int XCHG_DATA_SIZE = 111;

    ///////////////////////////////////////////////////////////////////////////

    /**
     * The application entry point
     * @param args (command line) parameters
     * @throws Throwable If any kind of unexpected error occurred.
     */
    public static void main(String args[]) throws Throwable {
        // do the self test ...

        System.out.print("running self test...");

        if (!BlowfishECB.selfTest()) {
            System.out.println(", FAILED");
            return;
        }

        System.out.println(", passed.");

        // the classic examples ...

        // create a 40bit test key

        byte[] testKey = new byte[5];
        for (int i = 0; i < testKey.length; i++) {
            testKey[i] = (byte) (i + 1);
        }

        // do the key setup

        System.out.print("setting up Blowfish keys...");

        BlowfishECB bfe = new BlowfishECB(testKey, 0, testKey.length);
        BlowfishCBC bfc = new BlowfishCBC(testKey, 0, testKey.length, CBCIV_START);

        System.out.println(", done.");

        // check for weak keys (the one we use should be fine)

        if (bfe.weakKeyCheck()) {
            System.err.println("ECB key is weak!");
        }
        if (bfc.weakKeyCheck()) {
            System.err.println("CBC key is weak!");
        }

        // get some text from the standard input, convert it to bytes

        System.out.print("something to encrypt please >");
        System.out.flush();

        byte[] tempbuf = (new LineNumberReader(
                new InputStreamReader(System.in))).readLine().getBytes();

        // align the data to the next block border

        byte[] msgbuf;
        int rest = tempbuf.length % Blowfish.BLOCKSIZE;

        msgbuf = new byte[(tempbuf.length - rest) +
                          (0 == rest ? 0 : Blowfish.BLOCKSIZE)];

        System.arraycopy(tempbuf, 0, msgbuf, 0, tempbuf.length);

        for (int i = tempbuf.length; i < msgbuf.length; i++) {
            // pad with spaces; zeros are a better solution when you need to
            // actually strip of the padding data later on (in our case it
            // wouldn't be printable though)
            msgbuf[i] = ' ';
        }

        System.out.println(
            "message with "
                + tempbuf.length
                + " bytes aligned to "
                + msgbuf.length
                + " bytes");

        System.out.println(
            "aligned data : 0x" + BinConverter.bytesToHexStr(msgbuf));

        // ECB encryption and decryption test

        bfe.encrypt(msgbuf, 0, msgbuf, 0, msgbuf.length);

        System.out.println(
            "ECB encrypted: 0x" + BinConverter.bytesToHexStr(msgbuf));

        bfe.decrypt(msgbuf, 0, msgbuf, 0, msgbuf.length);

        System.out.println("ECB decrypted: >>>" + new String(msgbuf) + "<<<");

        // CBC encryption and decryption test

        byte[] showIV = new byte[Blowfish.BLOCKSIZE];
        bfc.getCBCIV(showIV, 0);
        System.out.println("CBC IV: 0x" + BinConverter.bytesToHexStr(showIV));

        bfc.encrypt(msgbuf, 0, msgbuf, 0, msgbuf.length);

        System.out.println(
            "CBC encrypted: 0x" + BinConverter.bytesToHexStr(msgbuf));

        bfc.setCBCIV(CBCIV_START);
        bfc.decrypt(msgbuf, 0, msgbuf, 0, msgbuf.length);

        System.out.println("CBC decrypted: >>>" + new String(msgbuf) + "<<<");

        // show some CFB features (and its byte-per-byte capability) ...

        byte[] iv = new byte[Blowfish.BLOCKSIZE];
        SecureRandom srand = new SecureRandom();
        srand.nextBytes(iv);

        byte[] key = "some key that is".getBytes();

        BlowfishCFB bff = new BlowfishCFB(key, 0, key.length, iv, 0);

        byte[] plainText = "Encrypted with BlowfishJ/CFB.".getBytes();
        byte[] cipherText = new byte[plainText.length];

        // encrypt in two steps, since we don't have to be aligned
        bff.encrypt(plainText, 0, cipherText, 0, 11);
        bff.encrypt(plainText, 11, cipherText, 11, plainText.length - 11);

        bff = new BlowfishCFB(key, 0, key.length, iv, 0);

        byte[] decryptedText = new byte[plainText.length];
        bff.decrypt(cipherText, 0, decryptedText, 0, cipherText.length);

        System.out.println(new String(decryptedText));

        bff.cleanUp();

        // demonstrate easy string encryption ...

        BlowfishEasy bfes = new BlowfishEasy(BFEASY_REF_PASSW.toCharArray());

        // the output is also used a reference to check compatibility with the
        // C# version of Blowfish.NET
        String enc = bfes.encryptString(BFEASY_REF_TEXT);
        System.out.println(enc);
        System.out.println(bfes.decryptString(enc));

        // show stream handling...

        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        BlowfishOutputStream bfos = new BlowfishOutputStream(
            XCHG_KEY,
            0,
            XCHG_KEY.length,
            baos);

        for (int i = 0; i < XCHG_DATA_SIZE; i++) {
            bfos.write(i);
        }
        bfos.close();

        tempbuf = baos.toByteArray();

        System.out.println("0x" + BinConverter.bytesToHexStr(tempbuf));

        BlowfishInputStream bfis = new BlowfishInputStream(
            XCHG_KEY,
            0,
            XCHG_KEY.length,
            new ByteArrayInputStream(tempbuf));

        for (int i = 0; i < XCHG_DATA_SIZE; i++) {
            if ((i & 0x0ff) != bfis.read()) {
                System.err.println(
                    "corrupted data at position " + i + "!?");
            }
        }
        bfis.close();

        // benchmark ...

        System.out.println("\nrunning benchmark (CBC) ...");

        long tm = System.currentTimeMillis();

        tempbuf = new byte[TESTBUFSIZE];

        for (int i = 0; i < TESTLOOPS; i++) {
            bfc.encrypt(tempbuf, 0, tempbuf, 0, tempbuf.length);
            if (0 == (i % (TESTLOOPS / 40))) {
                System.out.print("#");
                System.out.flush();
            }
        }

        tm = System.currentTimeMillis() - tm;

        double amount = TESTBUFSIZE * TESTLOOPS;
        double time = tm;
        double rate = (amount * 1000) / time;

        System.out.println("\n " + String.format("%,d", (long)rate) + " bytes/second");

        bfe.cleanUp();
        bfc.cleanUp();
    }
}
