package de.org.mchahn.crypto.blowfishj;

import java.util.Arrays;

/**
 * Implementation of the Blowfish encryption algorithm in CFB mode. An
 * initialization vector (IV) makes every encryption unique, thus it needs to
 * be chosen randomly and stored together with the encrypted data. <p>
 * Notice that in comparison to ECB and CBC data can be processed byte-per-byte,
 * so it does not have to be aligned to block boundaries.</p>
 */
public final class BlowfishCFB extends BlowfishECB {

    // the initialization vector (IV) for CFB mode
    byte[] iv = new byte[BLOCKSIZE];
    int ivBytesLeft;

    ///////////////////////////////////////////////////////////////////////////

    /** @return The current IV. */
    public byte[] getIV() {
        return this.iv;
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Gets a copy of the current IV.
     * @param dest The buffer where to put the IV material.
     * @param ofs Where to start writing in the buffer.
     */
    public void getIV(byte[] dest, int ofs) {
        System.arraycopy(this.iv, 0, dest, ofs, this.iv.length);
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Sets the current IV. Useful for cipher resets in the middle of operation.
     * This however needs to be carefully correlated with the encrypted data,
     * since the new IV must be stored as well.
     * @param newIV The new IV.
     * @param ofs Where to start reading the IV.
     */
    public void setIV(byte[] newIV, int ofs) {
        System.arraycopy(newIV, ofs, this.iv, 0, this.iv.length);
        this.ivBytesLeft = 0;
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Constructor, uses a zero initialization vector (IV).
     * @param key Key material, up to MAXKEYLENGTH bytes.
     * @param ofs Where to start reading the key.
     * @param len Size of the key in bytes.
     */
    public BlowfishCFB(byte[] key, int ofs, int len) {
        super(key, ofs, len);
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Constructor to define key and initialization vector (IV).
     * @param key Key material, up to MAXKEYLENGTH bytes.
     * @param ofs Where to start reading the key.
     * @param len Size of the key in bytes.
     * @param initIV The IV.
     * @param ivOfs Where to start reading the IV.
     */
    public BlowfishCFB(byte[] key, int ofs, int len, byte[] initIV, int ivOfs) {
        super(key, ofs, len);
        setIV(initIV, ivOfs);
    }

    ///////////////////////////////////////////////////////////////////////////

    /** @see de.org.mchahn.crypto.blowfishj.BlowfishECB#cleanUp() */
    @Override
    public void cleanUp() {
        Arrays.fill(this.iv, (byte)0);
        super.cleanUp();
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * @param len The number of bytes to encrypt. Does <b>not</b> have to be
     * aligned on a block size boundary.
     * @see de.org.mchahn.crypto.blowfishj.BlowfishECB#encrypt(byte[], int, byte[], int, int)
     */
    @Override
    public int encrypt(
            byte[] inbuf, int inpos, byte[] outbuf, int outpos, int len) {
        int end = inpos + len;

        final byte[] iv = this.iv;

        final int ivBytesLeft = this.ivBytesLeft;
        int ivpos = iv.length - ivBytesLeft;

        if (ivBytesLeft >= len) {
            for (; inpos < end; inpos++, outpos++, ivpos++) {
                iv[ivpos] = outbuf[outpos] = (byte)(inbuf[inpos] ^ iv[ivpos]);
            }
            this.ivBytesLeft = iv.length - ivpos;
            return len;
        }
        for (; ivpos < BLOCKSIZE; inpos++, outpos++, ivpos++) {
            iv[ivpos] = outbuf[outpos] = (byte)(inbuf[inpos] ^ iv[ivpos]);
        }
        len -= ivBytesLeft;

        final int[] sbox1 = this.sbox1;
        final int[] sbox2 = this.sbox2;
        final int[] sbox3 = this.sbox3;
        final int[] sbox4 = this.sbox4;

        final int[] pbox = this.pbox;
        final int pbox00 = pbox[0];
        final int pbox01 = pbox[1];
        final int pbox02 = pbox[2];
        final int pbox03 = pbox[3];
        final int pbox04 = pbox[4];
        final int pbox05 = pbox[5];
        final int pbox06 = pbox[6];
        final int pbox07 = pbox[7];
        final int pbox08 = pbox[8];
        final int pbox09 = pbox[9];
        final int pbox10 = pbox[10];
        final int pbox11 = pbox[11];
        final int pbox12 = pbox[12];
        final int pbox13 = pbox[13];
        final int pbox14 = pbox[14];
        final int pbox15 = pbox[15];
        final int pbox16 = pbox[16];
        final int pbox17 = pbox[17];

        int hi =  (iv[0] << 24)               |
                 ((iv[1] << 16) & 0x00ff0000) |
                 ((iv[2] <<  8) & 0x0000ff00) |
                  (iv[3]        & 0x000000ff);

        int lo =  (iv[4] << 24)               |
                 ((iv[5] << 16) & 0x00ff0000) |
                 ((iv[6] <<  8) & 0x0000ff00) |
                  (iv[7]        & 0x000000ff);

        final int rest = len % BLOCKSIZE;
        end -= rest;

        for (;;) {
            hi ^= pbox00;
            lo ^= (((sbox1[hi >>> 24] + sbox2[(hi >>> 16) & 0x0ff]) ^ sbox3[(hi >>> 8) & 0x0ff]) + sbox4[hi & 0x0ff]) ^ pbox01;
            hi ^= (((sbox1[lo >>> 24] + sbox2[(lo >>> 16) & 0x0ff]) ^ sbox3[(lo >>> 8) & 0x0ff]) + sbox4[lo & 0x0ff]) ^ pbox02;
            lo ^= (((sbox1[hi >>> 24] + sbox2[(hi >>> 16) & 0x0ff]) ^ sbox3[(hi >>> 8) & 0x0ff]) + sbox4[hi & 0x0ff]) ^ pbox03;
            hi ^= (((sbox1[lo >>> 24] + sbox2[(lo >>> 16) & 0x0ff]) ^ sbox3[(lo >>> 8) & 0x0ff]) + sbox4[lo & 0x0ff]) ^ pbox04;
            lo ^= (((sbox1[hi >>> 24] + sbox2[(hi >>> 16) & 0x0ff]) ^ sbox3[(hi >>> 8) & 0x0ff]) + sbox4[hi & 0x0ff]) ^ pbox05;
            hi ^= (((sbox1[lo >>> 24] + sbox2[(lo >>> 16) & 0x0ff]) ^ sbox3[(lo >>> 8) & 0x0ff]) + sbox4[lo & 0x0ff]) ^ pbox06;
            lo ^= (((sbox1[hi >>> 24] + sbox2[(hi >>> 16) & 0x0ff]) ^ sbox3[(hi >>> 8) & 0x0ff]) + sbox4[hi & 0x0ff]) ^ pbox07;
            hi ^= (((sbox1[lo >>> 24] + sbox2[(lo >>> 16) & 0x0ff]) ^ sbox3[(lo >>> 8) & 0x0ff]) + sbox4[lo & 0x0ff]) ^ pbox08;
            lo ^= (((sbox1[hi >>> 24] + sbox2[(hi >>> 16) & 0x0ff]) ^ sbox3[(hi >>> 8) & 0x0ff]) + sbox4[hi & 0x0ff]) ^ pbox09;
            hi ^= (((sbox1[lo >>> 24] + sbox2[(lo >>> 16) & 0x0ff]) ^ sbox3[(lo >>> 8) & 0x0ff]) + sbox4[lo & 0x0ff]) ^ pbox10;
            lo ^= (((sbox1[hi >>> 24] + sbox2[(hi >>> 16) & 0x0ff]) ^ sbox3[(hi >>> 8) & 0x0ff]) + sbox4[hi & 0x0ff]) ^ pbox11;
            hi ^= (((sbox1[lo >>> 24] + sbox2[(lo >>> 16) & 0x0ff]) ^ sbox3[(lo >>> 8) & 0x0ff]) + sbox4[lo & 0x0ff]) ^ pbox12;
            lo ^= (((sbox1[hi >>> 24] + sbox2[(hi >>> 16) & 0x0ff]) ^ sbox3[(hi >>> 8) & 0x0ff]) + sbox4[hi & 0x0ff]) ^ pbox13;
            hi ^= (((sbox1[lo >>> 24] + sbox2[(lo >>> 16) & 0x0ff]) ^ sbox3[(lo >>> 8) & 0x0ff]) + sbox4[lo & 0x0ff]) ^ pbox14;
            lo ^= (((sbox1[hi >>> 24] + sbox2[(hi >>> 16) & 0x0ff]) ^ sbox3[(hi >>> 8) & 0x0ff]) + sbox4[hi & 0x0ff]) ^ pbox15;
            hi ^= (((sbox1[lo >>> 24] + sbox2[(lo >>> 16) & 0x0ff]) ^ sbox3[(lo >>> 8) & 0x0ff]) + sbox4[lo & 0x0ff]) ^ pbox16;

            final int swap = lo ^ pbox17;
            lo = hi;
            hi = swap;

            if (inpos >= end) {
                break;
            }

            hi ^=  (inbuf[inpos    ] << 24)               |
                  ((inbuf[inpos + 1] << 16) & 0x00ff0000) |
                  ((inbuf[inpos + 2] <<  8) & 0x0000ff00) |
                   (inbuf[inpos + 3]        & 0x000000ff);

            lo ^=  (inbuf[inpos + 4] << 24)               |
                  ((inbuf[inpos + 5] << 16) & 0x00ff0000) |
                  ((inbuf[inpos + 6] <<  8) & 0x0000ff00) |
                   (inbuf[inpos + 7]        & 0x000000ff);

            inpos += 8;

            outbuf[outpos    ] = (byte)(hi >>> 24);
            outbuf[outpos + 1] = (byte)(hi >>> 16);
            outbuf[outpos + 2] = (byte)(hi >>>  8);
            outbuf[outpos + 3] = (byte) hi;

            outbuf[outpos + 4] = (byte)(lo >>> 24);
            outbuf[outpos + 5] = (byte)(lo >>> 16);
            outbuf[outpos + 6] = (byte)(lo >>>  8);
            outbuf[outpos + 7] = (byte) lo;

            outpos += 8;
        }

        iv[0] = (byte)(hi >>> 24);
        iv[1] = (byte)(hi >>> 16);
        iv[2] = (byte)(hi >>>  8);
        iv[3] = (byte) hi       ;
        iv[4] = (byte)(lo >>> 24);
        iv[5] = (byte)(lo >>> 16);
        iv[6] = (byte)(lo >>>  8);
        iv[7] = (byte) lo       ;

        for (int i = 0; i < rest; i++) {
            iv[i] = outbuf[outpos + i] = (byte)(inbuf[inpos + i] ^ iv[i]);
        }

        this.ivBytesLeft = iv.length - rest;

        return len;
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * @param  len The number of bytes to encrypt. Does <b>not</b> have to be
     * aligned on a block size boundary.
     * @see de.org.mchahn.crypto.blowfishj.BlowfishECB#decrypt(byte[], int, byte[], int, int)
     */
    @Override
    public int decrypt(
        byte[] inbuf, int inpos, byte[] outbuf, int outpos, int len) {
        int end = inpos + len;

        final byte[] iv = this.iv;

        final int ivBytesLeft = this.ivBytesLeft;
        int ivpos = iv.length - ivBytesLeft;

        if (ivBytesLeft >= len) {
            for (; inpos < end; inpos++, outpos++, ivpos++) {
                int b = inbuf[inpos];
                outbuf[outpos] = (byte)(b ^ iv[ivpos]);
                inbuf[inpos] = (byte)b;
            }
            this.ivBytesLeft = iv.length - ivpos;
            return len;
        }
        for (int i = 0; ivpos < BLOCKSIZE; i++, inpos++) {
            iv[ivpos] = outbuf[outpos + i] = (byte)(inbuf[inpos + i] ^ iv[ivpos]);
        }
        len -= ivBytesLeft;

        final int[] sbox1 = this.sbox1;
        final int[] sbox2 = this.sbox2;
        final int[] sbox3 = this.sbox3;
        final int[] sbox4 = this.sbox4;

        final int[] pbox = this.pbox;
        final int pbox00 = pbox[0];
        final int pbox01 = pbox[1];
        final int pbox02 = pbox[2];
        final int pbox03 = pbox[3];
        final int pbox04 = pbox[4];
        final int pbox05 = pbox[5];
        final int pbox06 = pbox[6];
        final int pbox07 = pbox[7];
        final int pbox08 = pbox[8];
        final int pbox09 = pbox[9];
        final int pbox10 = pbox[10];
        final int pbox11 = pbox[11];
        final int pbox12 = pbox[12];
        final int pbox13 = pbox[13];
        final int pbox14 = pbox[14];
        final int pbox15 = pbox[15];
        final int pbox16 = pbox[16];
        final int pbox17 = pbox[17];

        int hi = (iv[0] << 24)               |
                ((iv[1] << 16) & 0x00ff0000) |
                ((iv[2] <<  8) & 0x0000ff00) |
                 (iv[3]        & 0x000000ff);

        int lo = (iv[4] << 24)               |
                ((iv[5] << 16) & 0x00ff0000) |
                ((iv[6] <<  8) & 0x0000ff00) |
                 (iv[7]        & 0x000000ff);

        final int rest = len % BLOCKSIZE;
        end -= rest;

        for (;;) {
            hi ^= pbox00;

            lo ^= (((sbox1[(hi >>> 24)] + sbox2[((hi >>> 16) & 0x0ff)]) ^ sbox3[((hi >>> 8) & 0x0ff)]) + sbox4[(hi & 0x0ff)]) ^ pbox01;
            hi ^= (((sbox1[(lo >>> 24)] + sbox2[((lo >>> 16) & 0x0ff)]) ^ sbox3[((lo >>> 8) & 0x0ff)]) + sbox4[(lo & 0x0ff)]) ^ pbox02;
            lo ^= (((sbox1[(hi >>> 24)] + sbox2[((hi >>> 16) & 0x0ff)]) ^ sbox3[((hi >>> 8) & 0x0ff)]) + sbox4[(hi & 0x0ff)]) ^ pbox03;
            hi ^= (((sbox1[(lo >>> 24)] + sbox2[((lo >>> 16) & 0x0ff)]) ^ sbox3[((lo >>> 8) & 0x0ff)]) + sbox4[(lo & 0x0ff)]) ^ pbox04;
            lo ^= (((sbox1[(hi >>> 24)] + sbox2[((hi >>> 16) & 0x0ff)]) ^ sbox3[((hi >>> 8) & 0x0ff)]) + sbox4[(hi & 0x0ff)]) ^ pbox05;
            hi ^= (((sbox1[(lo >>> 24)] + sbox2[((lo >>> 16) & 0x0ff)]) ^ sbox3[((lo >>> 8) & 0x0ff)]) + sbox4[(lo & 0x0ff)]) ^ pbox06;
            lo ^= (((sbox1[(hi >>> 24)] + sbox2[((hi >>> 16) & 0x0ff)]) ^ sbox3[((hi >>> 8) & 0x0ff)]) + sbox4[(hi & 0x0ff)]) ^ pbox07;
            hi ^= (((sbox1[(lo >>> 24)] + sbox2[((lo >>> 16) & 0x0ff)]) ^ sbox3[((lo >>> 8) & 0x0ff)]) + sbox4[(lo & 0x0ff)]) ^ pbox08;
            lo ^= (((sbox1[(hi >>> 24)] + sbox2[((hi >>> 16) & 0x0ff)]) ^ sbox3[((hi >>> 8) & 0x0ff)]) + sbox4[(hi & 0x0ff)]) ^ pbox09;
            hi ^= (((sbox1[(lo >>> 24)] + sbox2[((lo >>> 16) & 0x0ff)]) ^ sbox3[((lo >>> 8) & 0x0ff)]) + sbox4[(lo & 0x0ff)]) ^ pbox10;
            lo ^= (((sbox1[(hi >>> 24)] + sbox2[((hi >>> 16) & 0x0ff)]) ^ sbox3[((hi >>> 8) & 0x0ff)]) + sbox4[(hi & 0x0ff)]) ^ pbox11;
            hi ^= (((sbox1[(lo >>> 24)] + sbox2[((lo >>> 16) & 0x0ff)]) ^ sbox3[((lo >>> 8) & 0x0ff)]) + sbox4[(lo & 0x0ff)]) ^ pbox12;
            lo ^= (((sbox1[(hi >>> 24)] + sbox2[((hi >>> 16) & 0x0ff)]) ^ sbox3[((hi >>> 8) & 0x0ff)]) + sbox4[(hi & 0x0ff)]) ^ pbox13;
            hi ^= (((sbox1[(lo >>> 24)] + sbox2[((lo >>> 16) & 0x0ff)]) ^ sbox3[((lo >>> 8) & 0x0ff)]) + sbox4[(lo & 0x0ff)]) ^ pbox14;
            lo ^= (((sbox1[(hi >>> 24)] + sbox2[((hi >>> 16) & 0x0ff)]) ^ sbox3[((hi >>> 8) & 0x0ff)]) + sbox4[(hi & 0x0ff)]) ^ pbox15;
            hi ^= (((sbox1[(lo >>> 24)] + sbox2[((lo >>> 16) & 0x0ff)]) ^ sbox3[((lo >>> 8) & 0x0ff)]) + sbox4[(lo & 0x0ff)]) ^ pbox16;

            final int swap = lo ^ pbox17;
            lo = hi;
            hi = swap;

            if (inpos >= end) {
                break;
            }

            int chi = (inbuf[inpos    ] << 24)               |
                     ((inbuf[inpos + 1] << 16) & 0x00ff0000) |
                     ((inbuf[inpos + 2] <<  8) & 0x0000ff00) |
                      (inbuf[inpos + 3]        & 0x000000ff);

            int clo = (inbuf[inpos + 4] << 24)               |
                     ((inbuf[inpos + 5] << 16) & 0x00ff0000) |
                     ((inbuf[inpos + 6] <<  8) & 0x0000ff00) |
                      (inbuf[inpos + 7]        & 0x000000ff);

            inpos += 8;

            hi ^= chi;
            lo ^= clo;

            outbuf[outpos]     = (byte)(hi >>> 24);
            outbuf[outpos + 1] = (byte)(hi >>> 16);
            outbuf[outpos + 2] = (byte)(hi >>>  8);
            outbuf[outpos + 3] = (byte) hi;

            outbuf[outpos + 4] = (byte)(lo >>> 24);
            outbuf[outpos + 5] = (byte)(lo >>> 16);
            outbuf[outpos + 6] = (byte)(lo >>>  8);
            outbuf[outpos + 7] = (byte) lo;

            outpos += 8;

            hi = chi;
            lo = clo;
        }

        iv[0] = (byte)(hi >>> 24);
        iv[1] = (byte)(hi >>> 16);
        iv[2] = (byte)(hi >>>  8);
        iv[3] = (byte) hi;
        iv[4] = (byte)(lo >>> 24);
        iv[5] = (byte)(lo >>> 16);
        iv[6] = (byte)(lo >>>  8);
        iv[7] = (byte) lo;

        for (int i = 0; i < rest; i++) {
            int b = inbuf[inpos + i];
            outbuf[outpos + i] = (byte)(b ^ iv[i]);
            iv[i] = (byte)b;
        }

        this.ivBytesLeft = iv.length - rest;

        return len;
    }
}
