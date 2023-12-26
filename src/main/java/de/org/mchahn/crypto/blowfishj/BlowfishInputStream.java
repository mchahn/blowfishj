package de.org.mchahn.crypto.blowfishj;

import java.io.BufferedInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * To read from a stream created by an instance of the
 * blowfishj.BlowfishOutputStream class.
 */
public class BlowfishInputStream extends InputStream {

    PushbackInputStream is;

    BlowfishCBC bfc;

    byte[] buf;
    int bufPos;
    int bufCount;

    ///////////////////////////////////////////////////////////////////////////

    void init(
        byte[] key,
        int ofs,
        int len,
        InputStream is) throws IOException {
        this.bufPos = this.bufCount = 0;

        this.is = new PushbackInputStream(new BufferedInputStream(is));

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

        this.bfc = new BlowfishCBC(ckey, 0, ckey.length, 0);

        this.buf = new byte[Blowfish.BLOCKSIZE];

        // read the IV
        for (int i = 0, c = this.buf.length; i < c; i++) {
            int val = this.is.read();
            if (-1 == val) {
                throw new IOException("truncated stream, IV is missing");
            }
            this.buf[i] = (byte)val;
        }

        this.bfc.setCBCIV(this.buf, 0);
    }

    ///////////////////////////////////////////////////////////////////////////

    void fillBuffer() throws IOException {
        // fill the whole buffer

        int val;
        for (int i = 0, c = this.buf.length; i < c; i++) {
            if (-1 == (val = this.is.read())) {
                throw new IOException("truncated stream, unexpected end");
            }
            this.buf[i] = (byte)val;
        }

        // decrypt the buffer
        this.bfc.decrypt(this.buf, 0, this.buf, 0, this.buf.length);

        // peek if this is the end of the stream
        val = this.is.read();
        if (-1 == val) {
            // this is the last block, so we can read out how much we actually
            // got left

            int c = this.buf[this.buf.length - 1];

            // validate the padding
            if (c > this.buf.length || 0 > c) {
                throw new IOException("unknown padding value detected");
            }

            this.bufCount = this.buf.length - c;

            for (int i = this.bufCount; i < this.buf.length; i++) {
                if (this.buf[i] != (byte)c) {
                    throw new IOException("invalid padding data detected");
                }
            }

            this.bfc.cleanUp();
            this.bfc = null;
        }
        else {
            this.is.unread(val);
            this.bufCount = this.buf.length;
        }

        this.bufPos = 0;
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Default constructor. The key material gets transformed to a final 160bit
     * key using SHA-1.
     * @param key The buffer with the key material.
     * @param ofs Where the key material starts in the buffer.
     * @param len Size of the key material.
     * @param is The input stream from which data will be read.
     * @exception IOException If the IV couldn't be read out
     */
    public BlowfishInputStream(
        byte[] key,
        int ofs,
        int len,
        InputStream is) throws IOException {
        init(key, ofs, len, is);
    }

    ///////////////////////////////////////////////////////////////////////////

    /** @see java.io.InputStream#read() */
    public int read() throws IOException {
        for (;;) {
            // out of buffered data?
            if  (this.bufCount <= this.bufPos) {
                // end of stream?
                if (null == this.bfc) {
                    return -1;
                }
                fillBuffer();
            }
            else {
                return (this.buf[this.bufPos++]) & 0x0ff;
            }
        }
    }

    ///////////////////////////////////////////////////////////////////////////

    /** @see java.io.InputStream#close() */
    @Override
    public void close() throws IOException {
        if (null != this.is) {
            this.is.close();
            this.is = null;
        }
    }
}
