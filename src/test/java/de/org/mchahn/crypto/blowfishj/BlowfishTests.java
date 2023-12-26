package de.org.mchahn.crypto.blowfishj;

import java.util.Arrays;

import org.junit.Test;

import de.org.mchahn.crypto.blowfishj.Blowfish;
import de.org.mchahn.crypto.blowfishj.BlowfishCBC;
import de.org.mchahn.crypto.blowfishj.BlowfishCFB;
import de.org.mchahn.crypto.blowfishj.BlowfishECB;
import de.org.mchahn.crypto.blowfishj.BlowfishEasy;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

/**
 * All test cases for the BlowfishJ core classes.
 */
public class BlowfishTests {

    @Test
    public void testByteArrayHandling() {
        final byte[] key = {
                0x01, 0x02, 0x03, (byte)0xaa, (byte)0xee, (byte)0xff };

        assertTrue(BlowfishECB.selfTest());

        byte[] ptxt = new byte[256];
        for (int i = 0; i < ptxt.length; i++) {
            ptxt[i] = (byte)i;
        }

        byte[] ptxt2 = new byte[257];

        byte[] ctxt = new byte[257];

        byte[] ctxtRef = null;

        byte[] zeroIV = new byte[8];
        Arrays.fill(zeroIV, 0, zeroIV.length, (byte)0);

        for (int i = 0; i < 6; i++) {
            BlowfishECB bfe = null;
            BlowfishCBC bfc = null;
            BlowfishCFB bff = null;

            // reset to avoid cheats

            Arrays.fill(zeroIV, 0, zeroIV.length, (byte)0);

            Arrays.fill(ctxt, 0, ctxt.length, (byte)0xcc);
            Arrays.fill(ptxt2, 0, ctxt.length, (byte)0xcc);

            switch(i) {
                case 0: {
                    bfe = new BlowfishECB();
                    bfe.initialize(key, 0, key.length);
                    break;
                }
                case 1: {
                    bfe = new BlowfishECB(key, 0, key.length);
                    break;
                }
                case 2: {
                    bfc = new BlowfishCBC(key, 0, key.length);
                    bfc.setCBCIV(zeroIV, 0);
                    break;
                }
                case 3: {
                    bfc = new BlowfishCBC(key, 0, key.length);
                    break;
                }
                case 4: {
                    bff = new BlowfishCFB(key, 0, key.length);
                    bff.setIV(zeroIV, 0);
                    break;
                }
                case 5: {
                    bff = new BlowfishCFB(key, 0, key.length);
                    break;
                }
            }

            // encrypt and decrypt

            if (0 == i || 1 == i) {
                bfe.encrypt(ptxt, 0, ctxt, 0, ptxt.length);
                bfe.decrypt(ctxt, 0, ptxt2, 0, ptxt.length);
            }
            else if (2 == i || 3 == i) {
                ctxtRef = null;

                // first check of the IV was set correctly
                assertEquals(0L, bfc.getCBCIV());

                bfc.encrypt(ptxt, 0, ctxt, 0, ptxt.length);
                bfc.setCBCIV(0L);
                bfc.decrypt(ctxt, 0, ptxt2, 0, ptxt.length);
            }
            else {
                ctxtRef = null;

                byte[] iv = bff.getIV();
                for (int j = 0; j < iv.length; j++) {
                    assertEquals(0, iv[j]);
                }

                bff.encrypt(ptxt, 0, ctxt, 0, ptxt.length);
                bff.setIV(new byte[Blowfish.BLOCKSIZE], 0);
                bff.decrypt(ctxt, 0, ptxt2, 0, ptxt.length);
            }

            // check for overwrites

            assertEquals((byte)0xcc, ctxt[256]);
            assertEquals((byte)0xcc, ptxt2[256]);

            // verify that all encrypted results are equal,with the first one
            // of each kind (ECB/CBC) setting the reference

            if (null == ctxtRef) {
                ctxtRef = new byte[ctxt.length];
                System.arraycopy(ctxt, 0, ctxtRef, 0, ctxt.length);
            }
            else {
                for (int j = 0; j < ctxt.length; j++) {
                    assertEquals(ctxt[j], ctxtRef[j]);
                }
            }

            // make sure that the decrypted value is actually correct (and that
            // we're not doing zero encryption)

            boolean same = true;

            for (int j = 0; j < ptxt.length; j++) {
                assertEquals(ptxt[j], ptxt2[j]);
                if (ctxt[j] != ptxt2[j]) {
                    same = false;
                }
            }
            assertFalse(same);
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    static final byte[] KNOWN_WEAK_KEY = {
        (byte)0xe4, (byte)0x19, (byte)0xbc, (byte)0xec, (byte)0x18, (byte)0x7b,
        (byte)0x27, (byte)0x81, (byte)0x64, (byte)0x51, (byte)0x54, (byte)0xe6,
        (byte)0x0a, (byte)0x42, (byte)0x79, (byte)0x6b, (byte)0x16, (byte)0xc8,
        (byte)0x54, (byte)0x85, (byte)0x3b, (byte)0x64, (byte)0xfa, (byte)0x1e,
        (byte)0x61, (byte)0x29, (byte)0x7e, (byte)0x36, (byte)0xe9, (byte)0xd3,
        (byte)0xcf, (byte)0xe2, (byte)0x2b, (byte)0x69, (byte)0x68, (byte)0x33,
        (byte)0x11, (byte)0xa1, (byte)0x57, (byte)0x83
    };

    @Test
    public void testWeakKey() {
        byte[] key = KNOWN_WEAK_KEY.clone();

        BlowfishECB bfe = new BlowfishECB(key, 0, key.length);
        assertTrue(bfe.weakKeyCheck());

        Arrays.fill(key, 0, key.length, (byte)0);

        bfe = new BlowfishECB(key, 0, key.length);
        assertFalse(bfe.weakKeyCheck());
    }

    ///////////////////////////////////////////////////////////////////////////

    @Test
    public void testBlowfishEasy() {
        // test a growing string with all kinds of exotic characters

        for (int i = 0; i < 513; i++) {
            StringBuffer sbuf = new StringBuffer();

            for (int j = 0; j < i; j++) {
                sbuf.append((char)j);
            }

            String ptxt = sbuf.toString();
            String key = ptxt + "xyz"; // (easy way to get unique keys)

            // test standard encryption/decryption

            BlowfishEasy bfes = new BlowfishEasy(key.toCharArray());

            String ctxt = bfes.encryptString(ptxt);

            String ptxt2 = bfes.decryptString(ctxt);

            assertEquals(ptxt, ptxt2);
            if (0 == i) {
                assertEquals(ptxt,
                        bfes.decryptString("5c52ae029c816642b2d7e99aaa6cf37c"));
            }

            // test with reset instance

            bfes = new BlowfishEasy(key.toCharArray());
            ptxt2 = bfes.decryptString(ctxt);

            assertEquals(ptxt, ptxt2);

            // negative test with wrong key

            bfes = new BlowfishEasy((key + ".").toCharArray());
            ptxt2 = bfes.decryptString(ctxt);

            assertNotEquals(ptxt, ptxt2);
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    static final byte[] KEYSETUPBUG_K0 = { 0, 1, 2 };
    static final byte[] KEYSETUPBUG_K1 = { 1, 2 };

    @Test
    public void testKeySetupBug() {
        // verify a bug in the key setup, which was fixed in 2.13

        BlowfishECB bfe0 = new BlowfishECB(KEYSETUPBUG_K0, 1, 2);
        BlowfishECB bfe1 = new BlowfishECB(KEYSETUPBUG_K1, 0, 2);

        byte[] block0 = new byte[Blowfish.BLOCKSIZE];
        byte[] block1 = new byte[Blowfish.BLOCKSIZE];

        Arrays.fill(block0, 0, block0.length, (byte)0);
        Arrays.fill(block1, 0, block1.length, (byte)0);

        bfe0.encrypt(block0, 0, block0, 0, block0.length);
        bfe1.encrypt(block1, 0, block1, 0, block1.length);

        for (int i = 0; i < block0.length; i++) {
            assertEquals(block0[i], block1[i]);
        }
    }

    ///////////////////////////////////////////////////////////////////////////


    static final byte[] OPENSSL_BFCFB_REFKEY = {
        0x01,0x23,0x45,0x67,
        (byte)0x89,(byte)0xab,(byte)0xcd,(byte)0xef,(byte)0xf0,(byte)0xe1,
        (byte)0xd2,(byte)0xc3,(byte)0xb4,(byte)0xa5,(byte)0x96,(byte)0x87
    };

    static final byte[] OPENSSL_BFCFB_REFDATA =
        "7654321 Now is the time for \0".getBytes();

    static final byte[] OPENSSL_BFCFB_REFIV = {
        (byte)0xfe,(byte)0xdc,(byte)0xba,(byte)0x98,
        (byte)0x76,(byte)0x54,(byte)0x32,(byte)0x10 };

    static final byte[] OPENSSL_BFCFB_REFCTXT = {
        (byte)0xe7,(byte)0x32,(byte)0x14,(byte)0xa2,(byte)0x82,(byte)0x21,
        (byte)0x39,(byte)0xca,(byte)0xf2,(byte)0x6e,(byte)0xcf,(byte)0x6d,
        (byte)0x2e,(byte)0xb9,(byte)0xe7,(byte)0x6e,(byte)0x3d,(byte)0xa3,
        (byte)0xde,(byte)0x04,(byte)0xd1,(byte)0x51,(byte)0x72,(byte)0x00,
        (byte)0x51,(byte)0x9d,(byte)0x57,(byte)0xa6,(byte)0xc3
    };

    @Test
    public void testCFBOpenSSL() {
        BlowfishCFB bfc = new BlowfishCFB(OPENSSL_BFCFB_REFKEY, 0,
                                          OPENSSL_BFCFB_REFKEY.length);

        bfc.setIV(OPENSSL_BFCFB_REFIV, 0);

        int len = OPENSSL_BFCFB_REFDATA.length;

        byte[] buf = new byte[len];

        bfc.encrypt(OPENSSL_BFCFB_REFDATA, 0, buf, 0, 13);
        bfc.encrypt(OPENSSL_BFCFB_REFDATA, 13, buf, 13, len - 13);

        assertEquals(len, OPENSSL_BFCFB_REFCTXT.length);

        for (int i = 0; i < len; i++) {
            assertEquals(OPENSSL_BFCFB_REFCTXT[i], buf[i]);
        }
    }
}
