public class cShake {

    static byte[] cSHAKE256(byte[] X, int length, String N, String S) {
        assert N.length() <= Math.pow(2, 2040) && S.length() <= Math.pow(2, 2040);
        if (N.equals("") && S.equals("")) {
            return SHAKE.SHAKE256(X, length);
        } else {
            byte[] bytePadBytes = Glossary.bytepad(Glossary.array_concatenation(Glossary.encode_string(N), Glossary.encode_string(S)), 136);
            byte[] after = Glossary.array_concatenation(X, new byte[]{(byte) 0x00});
            return KECCAK.KECCAK512(Glossary.array_concatenation(bytePadBytes, after), length);
        }
    }

    /*
     // Switch from absorbing to extensible squeezing.
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
    */
}