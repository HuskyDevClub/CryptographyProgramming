public class Shake extends Glossary {

    /**
     * Switch from absorbing to extensible squeezing.
     */
    public void xof() {

        if (kmac) {
            // mandatory padding as per the NIST specification
            update(right_encode_0, right_encode_0.length);
        }
        // the (binary) cSHAKE suffix is 00, while the (binary) SHAKE suffix is 1111
        this.b[this.pt] ^= (byte) (this.ext ? 0x04 : 0x1F);
        // big-endian interpretation (right-to-left):
        // 0x04 = 00000100 = suffix 00, right-padded with 1, right-padded with 0*
        // 0x1F = 00011111 = suffix 1111, right-padded with 1, right-padded with 0*
        this.b[this.rsiz - 1] ^= (byte) 0x80;
        // little-endian interpretation (left-to-right):
        // 1000 0000 = suffix 1, left-padded with 0*
        sha3_keccakf(b);
        this.pt = 0;
    }

    public void kinit256(byte[] K, byte[] S) {
    }

    public void update(byte[] X, int length) {
    }

    public void out(byte[] val, int i) {
    }
}