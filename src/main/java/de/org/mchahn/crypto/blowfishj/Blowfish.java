package de.org.mchahn.crypto.blowfishj;

/** The very base class. Just the carrier of some definitions independent of
 * the actual mode of operation. */
public class Blowfish {

    protected Blowfish() {}

    /** The maximum possible key length in bytes. The minimum is zero. */
    public static final int MAXKEYLENGTH = 56;

    /** The block size of the Blowfish cipher in bytes. */
    public static final int BLOCKSIZE = 8;
}
