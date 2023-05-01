import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

class Glossary {
    public static void main(String[] args) {
        test();
    }

    @Test
    private static void test() {
        assertArrayEquals(encode_string(""), new byte[]{(byte) 0x1, (byte) 0x0});
        assertArrayEquals(left_encode(0), new byte[]{(byte) 0x1, (byte) 0x0});
        assertArrayEquals(right_encode(0), new byte[]{(byte) 0x0, (byte) 0x1});
    }

    private static int getSmallestPositiveN(long x) {
        assert x >= 0 && x <= Math.pow(2, 2040);
        return Math.max((int) Math.ceil(Math.log(x) / Math.log(2) / 8), 1);
    }

    private static byte[] left_encode(long x) {
        int n = getSmallestPositiveN(x);
        byte[] O = new byte[n + 1];
        O[0] = (byte) n;
        for (int i = 1; i <= n; i++) {
            O[i] = (byte) (x >> (8 * (n - i)));
        }
        return O;
    }

    private static byte[] right_encode(long x) {
        int n = getSmallestPositiveN(x);
        byte[] O = new byte[n + 1];
        O[n] = (byte) n;
        for (int i = 0; i < n; i++) {
            O[i] = (byte) (x >> (8 * (n - i - 1)));
        }
        return O;
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
     * Informally, the substring(X, a, b) function returns a substring from the bit string X containing the
     * values at bit positions a, a+1, ..., b−1, inclusive. More precisely, the substring function operates
     * as defined below. Note that all bit positions in the input and output strings are indexed from zero.
     * Thus, the first bit in a string is in position 0, and the last bit in an n-bit string is in position n−1.
     *
     * @param X a string
     * @param a a non-negative integer that denote a specific position in a bit string X
     * @param b a non-negative integer that denote a specific position in a bit string X
     * @return a substring from the bit string X containing the values at bit positions a, a+1, ..., b−1, inclusive
     */
    private static byte[] substring(byte[] X, int a, int b) {
        if (a >= b || a >= X.length) {
            return new byte[0];
        } else if (b <= X.length) {
            return Arrays.copyOfRange(X, a, b);
        } else {
            return Arrays.copyOfRange(X, a, X.length);
        }
    }
}
