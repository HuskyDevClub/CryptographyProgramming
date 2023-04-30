import java.util.Arrays;

public class SHAKE {

    public static void main(String[] args) {
        assert Arrays.equals(encode_string(""), new byte[]{(byte) 0x8, (byte) 0x0, (byte) 0x0, (byte) 0x0});
    }

    private static byte[] array_concatenation(byte[] a1, byte[] a2) {
        byte[] result = new byte[a1.length + a2.length];
        System.arraycopy(a1, 0, result, 0, a1.length);
        System.arraycopy(a2, 0, result, a1.length, a2.length);
        return result;
    }

    private static byte[] encode_string(String plaintText) {
        assert plaintText.length() <= Math.pow(2, 2040);
        return array_concatenation(left_encode(plaintText.length()), plaintText.getBytes());
    }

    private static byte[] left_encode(int x) {
        assert x >= 0 && x <= Math.pow(2, 2040);
        return new byte[1];
    }

    private static byte[] right_encode(int x) {
        assert x >= 0 && x <= Math.pow(2, 2040);
        int n = (int) Math.ceil(Math.log(x) / Math.log(2) / 8);
        return new byte[1];
    }

    /**
     * Apply the NIST bytepad primitive to a byte array X with encoding factor w.
     *
     * @param X the byte array to bytepad
     * @param w the encoding factor (the output length must be a multiple of w)
     * @return the byte-padded byte array X with encoding factor w.
     */
    private static byte[] bytepad(byte[] X, int w) {
        // Validity Conditions: w > 0
        assert w > 0;
        // 1. z = left_encode(w) || X.
        byte[] wenc = left_encode(w);
        byte[] z = new byte[w * ((wenc.length + X.length + w - 1) / w)];
        // NB: z.length is the smallest multiple of w that fits wenc.length + X.length
        System.arraycopy(wenc, 0, z, 0, wenc.length);
        System.arraycopy(X, 0, z, wenc.length, X.length);
        // 2. (nothing to do: len(z) mod 8 = 0 in this byte-oriented implementation)
        // 3. while (len(z)/8) mod w ≠ 0: z = z || 00000000
        for (int i = wenc.length + X.length; i < z.length; i++) {
            z[i] = (byte) 0;
        }
        // 4. return z
        return z;
    }

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