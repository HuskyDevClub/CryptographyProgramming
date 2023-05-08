import org.junit.jupiter.api.Test;

import java.security.SecureRandom;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

/**
 * A set of functions implemented according to NIST.SP.800-185 as close as possible
 *
 * @author Yudong Lin
 */
class Glossary {

    @Test
    static void test() {
        assertArrayEquals(
                array_concatenation(
                        new byte[]{(byte) 0x01, (byte) 0x02},
                        new byte[]{(byte) 0x03, (byte) 0x04, (byte) 0x05},
                        new byte[]{(byte) 0x06}
                ),
                new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05, (byte) 0x06}
        );
        assertArrayEquals(new byte[]{(byte) 0x01, (byte) 0x00}, encode_string(""));
        assertArrayEquals(
                new byte[]{
                        (byte) 0x01, (byte) 0x78, (byte) 0x45, (byte) 0x6D, (byte) 0x61, (byte) 0x69, (byte) 0x6C, (byte) 0x20,
                        (byte) 0x53, (byte) 0x69, (byte) 0x67, (byte) 0x6E, (byte) 0x61, (byte) 0x74, (byte) 0x75, (byte) 0x72, (byte) 0x65
                },
                encode_string("Email Signature")
        );
        assertArrayEquals(
                new byte[]{
                        (byte) 0x01, (byte) 0xa8, (byte) 0x4d, (byte) 0x79, (byte) 0x20, (byte) 0x54, (byte) 0x61, (byte) 0x67,
                        (byte) 0x67, (byte) 0x65, (byte) 0x64, (byte) 0x20, (byte) 0x41, (byte) 0x70, (byte) 0x70, (byte) 0x6c,
                        (byte) 0x69, (byte) 0x63, (byte) 0x61, (byte) 0x74, (byte) 0x69, (byte) 0x6f, (byte) 0x6e
                },
                encode_string("My Tagged Application")
        );
        assertArrayEquals(new byte[]{(byte) 0x01, (byte) 0x00}, left_encode(0));
        assertArrayEquals(new byte[]{(byte) 0x01, (byte) 0x7e}, left_encode(126));
        assertArrayEquals(new byte[]{(byte) 0x01, (byte) 0xff}, left_encode(255));
        assertArrayEquals(new byte[]{(byte) 0x02, (byte) 0x00, (byte) 0x01}, left_encode(256));
        assertArrayEquals(new byte[]{(byte) 0x02, (byte) 0x01, (byte) 0x01}, left_encode(257));
        assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x01}, right_encode(0));
        assertArrayEquals(new byte[]{(byte) 0x7e, (byte) 0x01}, right_encode(126));
        assertArrayEquals(new byte[]{(byte) 0xff, (byte) 0x01}, right_encode(255));
        assertArrayEquals(new byte[]{(byte) 0x00, (byte) 0x01, (byte) 0x02}, right_encode(256));
        assertArrayEquals(new byte[]{(byte) 0x01, (byte) 0x01, (byte) 0x02}, right_encode(257));
    }

    private static int getSmallestPositiveN(long x) {
        assert x >= 0 && x <= Math.pow(2, 2040);
        return Math.max((int) Math.ceil(Math.log(x + 1) / Math.log(2) / 8), 1);
    }

    static byte[] left_encode(long x) {
        int n = getSmallestPositiveN(x);
        byte[] O = new byte[n + 1];
        O[0] = (byte) n;
        for (int i = 1; i <= n; i++) {
            O[i] = (byte) (x % 256);
            x /= 256;
        }
        return O;
    }

    static byte[] right_encode(long x) {
        int n = getSmallestPositiveN(x);
        byte[] O = new byte[n + 1];
        O[n] = (byte) n;
        for (int i = 0; i < n; i++) {
            O[i] = (byte) (x % 256);
            x /= 256;
        }
        return O;
    }

    static byte[] array_concatenation(byte[]... arrays) {
        int totalLen = 0;
        for (byte[] theArray : arrays) {
            totalLen += theArray.length;
        }
        byte[] result = new byte[totalLen];
        int copyIndex = 0;
        for (byte[] theArray : arrays) {
            System.arraycopy(theArray, 0, result, copyIndex, theArray.length);
            copyIndex += theArray.length;
        }
        return result;
    }

    /**
     * The encodeString method.
     * @param S Parameter for the bit string to encode (as a byte array).
     * @return Returns the bit string produced by prepending the encoding of S.length to str
     */
    static byte[] encode_string(String S) {
        return encode_string(S.getBytes());
    }

    /**
     * The encodeString method.
     * @param S Parameter for the bit string to encode (as a byte array).
     * @return Returns the bit string produced by prepending the encoding of S.length to str
     */
    static byte[] encode_string(byte[] S) {
        assert S.length <= Math.pow(2, 2040);
        return array_concatenation(left_encode(S.length * 8L), S);
    }

    /**
     * Apply the NIST bytepad primitive to a byte array X with encoding factor w.
     *
     * @param X the byte array to bytepad
     * @param w the encoding factor (the output length must be a multiple of w)
     * @return the byte-padded byte array X with encoding factor w.
     */
    static byte[] bytepad(byte[] X, int w) {
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
    static byte[] substring(byte[] X, int a, int b) {
        if (a >= b || a >= X.length) {
            return new byte[0];
        } else if (b <= X.length) {
            return Arrays.copyOfRange(X, a, b);
        } else {
            return Arrays.copyOfRange(X, a, X.length);
        }
    }

    static void displayBytes(byte[] X) {
        final int itemsPerLine = 16;
        for (int i = 0; i <= X.length / itemsPerLine; i++) {
            for (int a = 0; a < itemsPerLine; a++) {
                int abs_index = i * itemsPerLine + a;
                if (abs_index >= X.length) {
                    System.out.println();
                    return;
                }
                System.out.printf("%02x ", X[abs_index]);
            }
            System.out.println();
        }
    }

    static byte[] random(int l) {
        if (l % 8 != 0) {
            throw new IllegalArgumentException("The length has to be a multiple of 8!");
        }
        SecureRandom theRandom = new SecureRandom();
        byte[] result = new byte[l / 8];
        theRandom.nextBytes(result);
        return result;
    }
}
