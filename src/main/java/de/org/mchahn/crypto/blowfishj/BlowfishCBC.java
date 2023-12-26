package de.org.mchahn.crypto.blowfishj;

/** Implementation of the Blowfish encryption algorithm in CBC, which is
 * next to CFB the recommended mode of operation. The initialization vector (IV)
 * represents one block of usually random data, making each encrypted stream
 * unique. The IV has to be stored together with the encrypted data externally,
 * usually it marks the beginning of an encrypted stream. Notice that padding is
 * not handling by this class, thus data not aligning to the size of a block
 * must be appended with extra data. Check out schemes like PKCS7. */
public final class BlowfishCBC extends BlowfishECB {

    // the initialization vector (IV)
    int ivLo;
    int ivHi;

    ///////////////////////////////////////////////////////////////////////////

    /** @return The current IV. */
    public long getCBCIV() {
        return BinConverter.makeLong(this.ivLo, this.ivHi);
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Gets a copy of the current IV.
     * @param dest The buffer where to write the IV data to.
     * @param ofs Where to start writing the BLOCKSIZE number of bytes.
     */
    public void getCBCIV(byte[] dest, int ofs) {
        BinConverter.intToByteArray(this.ivHi, dest, ofs);
        BinConverter.intToByteArray(this.ivLo, dest, ofs + 4);
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Sets the current IV from a 64bit integer, which represents one block of
     * data. Useful for resets of the encrypted stream or to start a completely
     * new stream, reusing the current instance.
     * @param newIV The new CBC IV as a 64bit integer.
     */
    public void setCBCIV(long newIV) {
        this.ivHi = BinConverter.longHi32(newIV);
        this.ivLo = BinConverter.longLo32(newIV);
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Sets the current IV. Useful for resets of the encrypted stream or to
     * start a completely new stream, reusing the current instance.
     * @param newIV The buffer with the new IV material.
     * @param ofs Where to start reading BLOCKSIZE bytes as the IV.
     */
    public void setCBCIV(byte[] newIV, int ofs) {
        this.ivHi = BinConverter.byteArrayToInt(newIV, ofs);
        this.ivLo = BinConverter.byteArrayToInt(newIV, ofs + 4);
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Constructor starting with a zero IV.
     * @see de.org.mchahn.crypto.blowfishj.BlowfishECB#BlowfishECB(byte[], int, int)
     */
    public BlowfishCBC(byte[] key, int ofs, int len) {
        super(key, ofs, len);
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Constructor to start with a defined IV as a 64bit integer.
     * @param key The key material buffer, up to MAXKEYLENGTH bytes.
     * @param ofs Where to start reading the key material.
     * @param len The size of the key in bytes, from zero to MAXKEYLENGTH.
     * @param initIV The IV.
     */
    public BlowfishCBC(byte[] key, int ofs, int len, long initIV) {
        super(key, ofs, len);
        setCBCIV(initIV);
    }

    ///////////////////////////////////////////////////////////////////////////

    /**
     * Constructor to start with a defined IV.
     * @param key The key material buffer, up to MAXKEYLENGTH bytes.
     * @param ofs Where to start reading the key material.
     * @param len The size of the key in bytes, from zero to MAXKEYLENGTH.
     * @param initIV The buffer with the IV material.
     * @param ivOfs Where to start reading BLOCKSIZE bytes as the IV.
     */
    public BlowfishCBC(
        byte[] key,
        int ofs,
        int len,
        byte[] initIV,
        int ivOfs) {
        super(key, ofs, len);
        setCBCIV(initIV, ivOfs);
    }

    ///////////////////////////////////////////////////////////////////////////

    /** @see de.org.mchahn.crypto.blowfishj.BlowfishECB#cleanUp() */
    @Override
    public void cleanUp() {
        this.ivHi = this.ivLo = 0;
        super.cleanUp();
    }

    ///////////////////////////////////////////////////////////////////////////

    /** @see de.org.mchahn.crypto.blowfishj.BlowfishECB#encrypt(byte[], int, byte[], int, int) */
    @Override
    public int encrypt(
        byte[] inbuf,
        int inpos,
        byte[] outbuf,
        int outpos,
        int len) {
        len -= len % BLOCKSIZE;

        final int c = inpos + len;

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

        final int[] sbox1 = this.sbox1;
        final int[] sbox2 = this.sbox2;
        final int[] sbox3 = this.sbox3;
        final int[] sbox4 = this.sbox4;

        int ivHi = this.ivHi;
        int ivLo = this.ivLo;

        int hi, lo;

        while (inpos < c) {
            hi  =  (inbuf[inpos    ] << 24)              |
                  ((inbuf[inpos + 1] << 16) & 0x0ff0000) |
                  ((inbuf[inpos + 2] <<  8) & 0x000ff00) |
                   (inbuf[inpos + 3]        & 0x00000ff);

            lo  =  (inbuf[inpos + 4] << 24)              |
                  ((inbuf[inpos + 5] << 16) & 0x0ff0000) |
                  ((inbuf[inpos + 6] <<  8) & 0x000ff00) |
                   (inbuf[inpos + 7]        & 0x00000ff);

            inpos += 8;

            hi ^= ivHi;
            lo ^= ivLo;

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
            lo ^= pbox17;

            outbuf[outpos    ] = (byte)(lo >>> 24);
            outbuf[outpos + 1] = (byte)(lo >>> 16);
            outbuf[outpos + 2] = (byte)(lo >>>  8);
            outbuf[outpos + 3] = (byte) lo;

            outbuf[outpos + 4] = (byte)(hi >>> 24);
            outbuf[outpos + 5] = (byte)(hi >>> 16);
            outbuf[outpos + 6] = (byte)(hi >>>  8);
            outbuf[outpos + 7] = (byte) hi;

            outpos += 8;

            ivHi = lo;
            ivLo = hi;
        }

        this.ivHi = ivHi;
        this.ivLo = ivLo;

        return len;
    }

    ///////////////////////////////////////////////////////////////////////////

    /** @see de.org.mchahn.crypto.blowfishj.BlowfishECB#decrypt(byte[], int, byte[], int, int) */
    @Override
    public int decrypt(
        byte[] inbuf,
        int inpos,
        byte[] outbuf,
        int outpos,
        int len) {
        len -= len % BLOCKSIZE;

        final int c = inpos + len;

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

        final int[] sbox1 = this.sbox1;
        final int[] sbox2 = this.sbox2;
        final int[] sbox3 = this.sbox3;
        final int[] sbox4 = this.sbox4;

        int ivHi = this.ivHi;
        int ivLo = this.ivLo;

        int tmpHi, tmpLo;

        int hi, lo;

        while (inpos < c) {
            hi  =  (inbuf[inpos++] << 24)              |
                  ((inbuf[inpos++] << 16) & 0x0ff0000) |
                  ((inbuf[inpos++] <<  8) & 0x000ff00) |
                   (inbuf[inpos++]        & 0x00000ff);

            lo  =  (inbuf[inpos++] << 24)              |
                  ((inbuf[inpos++] << 16) & 0x0ff0000) |
                  ((inbuf[inpos++] <<  8) & 0x000ff00) |
                   (inbuf[inpos++]        & 0x00000ff);

            // save the current block, it will become the new IV
            tmpHi = hi;
            tmpLo = lo;

            hi ^= pbox17;
            lo ^= (((sbox1[hi >>> 24] + sbox2[(hi >>> 16) & 0x0ff]) ^ sbox3[(hi >>> 8) & 0x0ff]) + sbox4[hi & 0x0ff]) ^ pbox16;
            hi ^= (((sbox1[lo >>> 24] + sbox2[(lo >>> 16) & 0x0ff]) ^ sbox3[(lo >>> 8) & 0x0ff]) + sbox4[lo & 0x0ff]) ^ pbox15;
            lo ^= (((sbox1[hi >>> 24] + sbox2[(hi >>> 16) & 0x0ff]) ^ sbox3[(hi >>> 8) & 0x0ff]) + sbox4[hi & 0x0ff]) ^ pbox14;
            hi ^= (((sbox1[lo >>> 24] + sbox2[(lo >>> 16) & 0x0ff]) ^ sbox3[(lo >>> 8) & 0x0ff]) + sbox4[lo & 0x0ff]) ^ pbox13;
            lo ^= (((sbox1[hi >>> 24] + sbox2[(hi >>> 16) & 0x0ff]) ^ sbox3[(hi >>> 8) & 0x0ff]) + sbox4[hi & 0x0ff]) ^ pbox12;
            hi ^= (((sbox1[lo >>> 24] + sbox2[(lo >>> 16) & 0x0ff]) ^ sbox3[(lo >>> 8) & 0x0ff]) + sbox4[lo & 0x0ff]) ^ pbox11;
            lo ^= (((sbox1[hi >>> 24] + sbox2[(hi >>> 16) & 0x0ff]) ^ sbox3[(hi >>> 8) & 0x0ff]) + sbox4[hi & 0x0ff]) ^ pbox10;
            hi ^= (((sbox1[lo >>> 24] + sbox2[(lo >>> 16) & 0x0ff]) ^ sbox3[(lo >>> 8) & 0x0ff]) + sbox4[lo & 0x0ff]) ^ pbox09;
            lo ^= (((sbox1[hi >>> 24] + sbox2[(hi >>> 16) & 0x0ff]) ^ sbox3[(hi >>> 8) & 0x0ff]) + sbox4[hi & 0x0ff]) ^ pbox08;
            hi ^= (((sbox1[lo >>> 24] + sbox2[(lo >>> 16) & 0x0ff]) ^ sbox3[(lo >>> 8) & 0x0ff]) + sbox4[lo & 0x0ff]) ^ pbox07;
            lo ^= (((sbox1[hi >>> 24] + sbox2[(hi >>> 16) & 0x0ff]) ^ sbox3[(hi >>> 8) & 0x0ff]) + sbox4[hi & 0x0ff]) ^ pbox06;
            hi ^= (((sbox1[lo >>> 24] + sbox2[(lo >>> 16) & 0x0ff]) ^ sbox3[(lo >>> 8) & 0x0ff]) + sbox4[lo & 0x0ff]) ^ pbox05;
            lo ^= (((sbox1[hi >>> 24] + sbox2[(hi >>> 16) & 0x0ff]) ^ sbox3[(hi >>> 8) & 0x0ff]) + sbox4[hi & 0x0ff]) ^ pbox04;
            hi ^= (((sbox1[lo >>> 24] + sbox2[(lo >>> 16) & 0x0ff]) ^ sbox3[(lo >>> 8) & 0x0ff]) + sbox4[lo & 0x0ff]) ^ pbox03;
            lo ^= (((sbox1[hi >>> 24] + sbox2[(hi >>> 16) & 0x0ff]) ^ sbox3[(hi >>> 8) & 0x0ff]) + sbox4[hi & 0x0ff]) ^ pbox02;
            hi ^= (((sbox1[lo >>> 24] + sbox2[(lo >>> 16) & 0x0ff]) ^ sbox3[(lo >>> 8) & 0x0ff]) + sbox4[lo & 0x0ff]) ^ pbox01;
            lo ^= pbox00;

            hi ^= ivLo;
            lo ^= ivHi;

            outbuf[outpos++] = (byte)(lo >>> 24);
            outbuf[outpos++] = (byte)(lo >>> 16);
            outbuf[outpos++] = (byte)(lo >>>  8);
            outbuf[outpos++] = (byte) lo;

            outbuf[outpos++] = (byte)(hi >>> 24);
            outbuf[outpos++] = (byte)(hi >>> 16);
            outbuf[outpos++] = (byte)(hi >>>  8);
            outbuf[outpos++] = (byte) hi;

            ivHi = tmpHi;
            ivLo = tmpLo;
        }

        this.ivHi = ivHi;
        this.ivLo = ivLo;

        return len;
    }
}
