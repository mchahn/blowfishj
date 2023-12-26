package de.org.mchahn.crypto.blowfishj;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * An output stream that encrypts data using the Blowfish algorithm in CBC mode,
 * padded with PCKS7. Key material is hashed to a 160bit final key, using SHA-1.
 */
public class BlowfishOutputStream extends OutputStream {

    OutputStream os;

    BlowfishCBC bfc;

    byte[] bufIn;
    byte[] bufOut;
    int bytesInBuf;

    ///////////////////////////////////////////////////////////////////////////

    void initialize(
        byte[] key,
        int ofs,
        int len,
        OutputStream os) throws IOException {
        this.os = os;

        this.bytesInBuf = 0;

        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance("SHA-1");
        }
        catch (NoSuchAlgorithmException nse) {
            throw new UnsupportedOperationException();
        }
        md.update(key, ofs, len);

        byte[] ckey = md.digest();
        md.reset();

        this.bfc = new BlowfishCBC(
            ckey,
            0,
            ckey.length);

        Arrays.fill(
            ckey,
            0,
            ckey.length,
            (byte)0);

        this.bufIn = new byte[Blowfish.BLOCKSIZE];
        this.bufOut = new byte[Blowfish.BLOCKSIZE];

        // make sure the IV is written to output stream - these are always the
        // first eight bytes written out

        SecureRandom srnd = new SecureRandom();
        srnd.nextBytes(this.bufIn);

        this.os.write(this.bufIn, 0, this.bufIn.length);
        this.bfc.setCBCIV(this.bufIn, 0);
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Default constructor. The key gets transformed to a final 160bit
     * encryption key using SHA-1.
     * @param key The key buffer.
     * @param ofs Where the key material starts in the buffer.
     * @param len Size of the key material.
     * @param os The output stream to which data will be encrypted to.
     * @exception IOException If the IV couldn't be written.
     */
    public BlowfishOutputStream(
        byte[] key,
        int ofs,
        int len,
        OutputStream os) throws IOException {
        initialize(key, ofs, len, os);
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * @see java.io.OutputStream#write(int)
     */
    public void write(int val) throws IOException {
        ++this.bytesInBuf;
        if (this.bytesInBuf < this.bufIn.length) {
            this.bufIn[this.bytesInBuf - 1] = (byte)val;
            return;
        }

        this.bufIn[this.bytesInBuf - 1] = (byte)val;
        this.bytesInBuf = 0;

        this.bfc.encrypt(
            this.bufIn,
            0,
            this.bufOut,
            0,
            this.bufIn.length);

        this.os.write(
            this.bufOut,
            0,
            this.bufOut.length);
    }

    ///////////////////////////////////////////////////////////////////////////

    /** @see java.io.InputStream#close() */
    @Override
    public void close() throws IOException {
        if (null == this.os) {
            return;
        }

        // This output stream always writes out even blocks of 8 bytes. If it
        // happens that data cannot be aligned to a block boundary, then the
        // last block will be padded. Notice that the padding bytes will always
        // be a number between 1 and Blowfish.BLOCKSIZE. If this means adding an
        // extra block just for the pad count, then so be it.

        byte padVal = (byte)(this.bufIn.length - this.bytesInBuf);

        while (this.bytesInBuf < this.bufIn.length) {
            this.bufIn[this.bytesInBuf] = padVal;
            ++this.bytesInBuf;
        }

        this.bfc.encrypt(
            this.bufIn,
            0,
            this.bufOut,
            0,
            this.bufIn.length);

        this.os.write(
            this.bufOut,
            0,
            this.bufOut.length);

        this.os.close();
        this.os = null;

        this.bfc.cleanUp();
    }

    ///////////////////////////////////////////////////////////////////////////

    /** @see java.io.OutputStream#flush() */
    @Override
    public void flush() throws IOException {
        this.os.flush();
    }
}
