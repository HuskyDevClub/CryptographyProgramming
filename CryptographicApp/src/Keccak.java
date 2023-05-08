
import java.util.Arrays;

/**
 * Implements the Keccak[c] algorithm from NIST FIPS 202.
 */
public class Keccak
{
    private enum ENCODE {Left, Right}
    //Round constants reference link: https://keccak.team/keccak_specs_summary.html
    private static final long[] myRoundConstants =
    {
            0x0000000000000001L, 0x0000000000008082L, 0x800000000000808aL,
            0x8000000080008000L, 0x000000000000808BL, 0x0000000080000001L,
            0x8000000080008081L, 0x8000000000008009L, 0x000000000000008aL,
            0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
            0x000000008000808bL, 0x800000000000008bL, 0x8000000000008089L,
            0x8000000000008003L, 0x8000000000008002L, 0x8000000000000080L,
            0x000000000000800aL, 0x800000008000000aL, 0x8000000080008081L,
            0x8000000000008080L, 0x0000000080000001L, 0x8000000080008008L
    };

    //Rotation offsets for the roh function
    //Reference link: https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
    private static final int[] myRotationOffset =
    {
            1,  3,  6,  10, 15, 21, 28, 36, 45, 55, 2,  14,
            27, 41, 56, 8,  25, 43, 62, 18, 39, 61, 20, 44
    };

    //The position for each word with respective to the lane shifting in the pi function
    //Reference link: https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
    private static final int[] myPiLane =
    {
            10, 7,  11, 17, 18, 3, 5, 16, 8,  21, 24, 4,
            15, 23, 19, 13, 12, 2, 20, 14, 22, 9,  6,  1
    };

    /**
     * The SHA-3 hash function.
     * @param input Parameter for the bytes to compute the digest.
     * @param bitLength Parameter for the desired length of the output (must be 224, 256, 384, or 512).
     * @return Returns the message digest from the Keccak[bitLength*2] permutation.
     */
    public static byte[] SHA3(final byte[] input, final int bitLength)
    {
        if (bitLength != 224 && bitLength != 256 && bitLength != 384 && bitLength != 512)
            throw new IllegalArgumentException("Supported output bit lengths are 224, 256, 384, and 512.");
        byte[] uin = Arrays.copyOf(input, input.length + 1);
        int bytesToPad = (1600 - bitLength*2) / 8 - input.length % (1600 - bitLength*2);
        uin[input.length] = bytesToPad == 1 ? (byte) 0x86 : 0x06;

        return sponge(uin, bitLength, bitLength*2);
    }

    /**
     * Produces a variable length message digest based on the keccak-f permutation over the user input.
     * @param input Parameter for the bytes to compute the digest.
     * @param bitLength Parameter for the desired length of the output.
     * @return Returns the message digest extracted from the keccak-p based sponge.
     */
    public static byte[] SHAKE256(final byte[] input, final int bitLength)
    {
        byte[] uin = Arrays.copyOf(input, input.length + 1);
        int bytesToPad = 136 - input.length % (136); // rate is 136 bytes
        uin[input.length] = bytesToPad == 1 ? (byte) 0x9f : 0x1f; // pad with suffix defined input FIPS 202 sec. 6.2
        return sponge(uin, bitLength, 512);
    }

    /**
     * cSHAKE method.
     * @param input Parameter for the byte array to be hashed.
     * @param bitLength Parameter for the bit length of the desired output.
     * @param methodName Parameter for the name of the method to use.
     * @param customizationStr Parameter for the customization string.
     * @return Returns the message digest based on Keccak[512].
     */
    public static byte[] cSHAKE256(final byte[] input, final int bitLength, final String methodName,
                                   final String customizationStr)
    {
        if (methodName.equals("") && customizationStr.equals("")) return SHAKE256(input, bitLength);

        byte[] fin = mergeByteArrays(encodeString(methodName.getBytes()), encodeString(customizationStr.getBytes()));
        fin = mergeByteArrays(bytepad(fin, 136), input);
        fin = mergeByteArrays(fin, new byte[] {0x04});

        return sponge(fin, bitLength, 512);
    }

    /**
     * The Keccak Message Authentication which also has extensible output.
     * @param key Parameter for the key.
     * @param input Parameter for the input bytes.
     * @param bitLength Parameter for the desired bit length.
     * @param customizationStr Parameter for the customization string.
     * @return Returns the message authentication code derived from the input.
     */
    public static byte[] KMACXOF256(final byte[] key, final byte[] input, final int bitLength,
                                    final String customizationStr)
    {
        byte[] newIn = mergeByteArrays(bytepad(encodeString(key), 136), input);
        newIn = mergeByteArrays(newIn, lrEncode(0, ENCODE.Right));

        return cSHAKE256(newIn, bitLength,  "KMAC", customizationStr);
    }

    /**
     * The sponge method, produces an output of length bitLength based on keccak-p over input.
     * @param input Parameter for the input byte array.
     * @param bitLength Parameter for the length of the desired output.
     * @param capacity Parameter for the capacity.
     * @return Returns a byte array of bitLength bits produced by the keccak-p permutation.
     */
    private static byte[] sponge(final byte[] input, final int bitLength, final int capacity)
    {
        int rate = 1600 - capacity;
        byte[] padded = input.length % (rate / 8) == 0 ? input : padTenOne(rate, input); // one bit of padding already appended
        long[][] states = byteArrayToStates(padded, capacity);
        long[] stcml = new long[25];

        for (long[] st : states)
        {
            stcml = keccakp(xorStates(stcml, st), 1600, 24); // Keccak[c] restricted to bitLength 1600
        }

        long[] out = {};
        int offset = 0;

        do
        {
            out = Arrays.copyOf(out, offset + rate/64);
            System.arraycopy(stcml, 0, out, offset, rate/64);
            offset += rate/64;
            stcml = keccakp(stcml, 1600, 24);
        } while (out.length*64 < bitLength);

        return stateToByteArray(out, bitLength);
    }

    /**
     * Applies the 10 to 1 padding scheme. Assuming padding required is byte wise (bits needed is a multiple of 8).
     * @param input Parameter for the bytes array to pad.
     * @param rate Parameter for the result will be a positive multiple of rate.
     * @return Returns the padded byte array.
     */
    private static byte[] padTenOne(final int rate, final byte[] input)
    {
        int bytesToPad = (rate / 8) - input.length % (rate / 8);
        byte[] padded = new byte[input.length + bytesToPad];

        for (int i = 0; i < input.length + bytesToPad; i++)
        {
            if (i < input.length) padded[i] = input[i];
            else if (i==input.length + bytesToPad - 1) padded[i] = (byte) 0x80; // does not append any domain prefixs
            else padded[i] = 0;
        }

        return padded;
    }

    /**
     * The Keccak-p permutation.
     * @param stateInput Parameter for the input state, an array of 25 longs.
     * @param bitLength Parameter for the length of the desired output.
     * @param rounds Parameter for the number of rounds.
     * @return Returns the state after the Keccak-p permutation has been applied to the input state.
     */
    private static long[] keccakp(final long[] stateInput, final int bitLength, final int rounds)
    {
        long[] stateOut = stateInput;
        int l = floorLog(bitLength/25);

        for (int i = 12 + 2*l - rounds; i < 12 + 2*l; i++)
        {
            stateOut = iota(chi(rhoPhi(theta(stateOut))), i);
        }

        return stateOut;
    }

    /**
     * The theta function. Xors each state bit with the parities of two columns in the array.
     * This was adapted from https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * @param stateInput Parameter for the input state, an array of 25 longs.
     * @return Returns the state after the theta function has been applied (array of longs).
     */
    private static long[] theta(final long[] stateInput)
    {
        long[] stateOut = new long[25];
        long[] C = new long[5];

        for (int i = 0; i < 5; i++)
        {
            C[i] = stateInput[i] ^ stateInput[i + 5] ^ stateInput[i + 10] ^ stateInput[i + 15] ^ stateInput[i + 20];
        }

        for (int i = 0; i < 5; i++)
        {
            long d = C[(i+4) % 5] ^ lRotWord(C[(i+1) % 5], 1);

            for (int j = 0; j < 5; j++)
            {
                stateOut[i + 5*j] = stateInput[i + 5*j] ^ d;
            }
        }

        return stateOut;
    }

    /**
     * The rho and phi function. Which shifts and rearranges words.
     * This was adapted from https://github.com/mjosaarinen/tiny_sha3/blob/master/sha3.c
     * @param stateInput Parameter for the input state, an array of 25 longs.
     * @return Returns the state after applying the rho and phi function.
     */
    private static long[] rhoPhi(final long[] stateInput)
    {
        long[] stateOut = new long[25];
        stateOut[0] = stateInput[0];
        long t = stateInput[1], temp;
        int ind;

        for (int i = 0; i < 24; i++)
        {
            ind = myPiLane[i];
            temp = stateInput[ind];
            stateOut[ind] = lRotWord(t, myRotationOffset[i]);
            t = temp;
        }

        return stateOut;
    }

    /**
     * The chi function. Xors each word with a function of two other words in their row.
     * @param stateInput Parameter for the input state, an array of 25 longs.
     * @return Returns the state after applying the chi function.
     */
    private static long[] chi(final long[] stateInput)
    {
        long[] stateOut = new long[25];

        for (int i = 0; i < 5; i++)
        {
            for (int j = 0; j < 5; j++)
            {
                long tmp = ~stateInput[(i+1) % 5 + 5*j] & stateInput[(i+2) % 5 + 5*j];
                stateOut[i + 5*j] = stateInput[i + 5*j] ^ tmp;
            }
        }

        return stateOut;
    }

    /**
     * Applies the round constant to the word at stateInput[0].
     * @param stateInput Parameter for the input state, an array of 25 longs.
     * @return Returns the state after the round constant has been xored with the first lane (st[0]).
     */
    private static long[] iota(final long[] stateInput, final int round)
    {
        stateInput[0] ^= myRoundConstants[round];

        return stateInput;
    }

    /**
     * Pads a bit string.
     * @param str Parameter for the bit string to pad.
     * @param desiredFactor Parameter for the desired factor of the padding.
     * @return Returns a byte array prepended by lrEncode(desiredFactor)
     * such that it's length is an even multiple of desiredFactor.
     */
    private static byte[] bytepad(final byte[] str, final int desiredFactor)
    {
        byte[] lEnc = lrEncode(desiredFactor, ENCODE.Left);
        int len = lEnc.length + str.length + (desiredFactor - (lEnc.length + str.length) % desiredFactor);
        byte[] out = Arrays.copyOf(lEnc, len);
        System.arraycopy(str, 0, out, lEnc.length, str.length);

        return out;
    }

    /**
     * The encodeString method.
     * @param str Parameter for the bit string to encode (as a byte array).
     * @return Returns the bit string produced by prepending the encoding of str.length to str
     */
    private static byte[] encodeString(final byte[] str)
    {
        //Bitwise encoding
        byte[] lEnc = lrEncode(str.length*8, ENCODE.Left);
        byte[] out = Arrays.copyOf(lEnc, lEnc.length + str.length);
        System.arraycopy(str, 0, out, lEnc.length, str.length);

        return out;
    }

    /**
     * The left/right encode method.
     * @param size Parameter for the integer to encode.
     * @param direction Parameter for the desired direction of the encoding.
     * @return Returns a byte array.
     */
    private static byte[] lrEncode(final long size, final ENCODE direction)
    {
        if (size==0) return direction == ENCODE.Left ? new byte[] {1, 0} : new byte[] {0, 1};
        byte[] buf = new byte[8];
        long l = size;
        int cnt = 0;

        while (l > 0)
        {
            byte b = (byte) (l & 0xffL);
            l = l>>>(8);
            buf[7 - cnt++] = b;
        }

        byte[] out = new byte[cnt + 1];
        System.arraycopy(buf, 8 - cnt, out, direction == ENCODE.Left ? 1 : 0, cnt);
        out[direction == ENCODE.Left ? 0 : out.length - 1] = (byte) cnt;

        return out;
    }

    /**
     * Converts an extended state array to an array of bytes of bit length bitLength (equivalent to Trunc_r).
     * @param state Parameter for the state to convert to a byte array.
     * @param bitLength Parameter for the bit length of the desired output.
     * @return Returns a byte array of length bitLength/8 corresponding to bytes of the state: state[0:bitLength/8].
     */
    private static byte[] stateToByteArray(final long[] state, final int bitLength)
    {
        if (state.length*64 < bitLength) throw new IllegalArgumentException("State is of insufficient length to produced desired bit length.");
        byte[] out = new byte[bitLength/8];
        int wrdInd = 0;

        while (wrdInd*64 < bitLength)
        {
            long word = state[wrdInd++];
            int fill = wrdInd*64 > bitLength ? (bitLength - (wrdInd - 1) * 64) / 8 : 8;

            for (int b = 0; b < fill; b++)
            {
                byte ubt = (byte) (word>>>(8*b) & 0xFF);
                out[(wrdInd - 1)*8 + b] = ubt;
            }
        }

        return out;
    }

    /**
     * Converts a byte array to series of state arrays. Assumes input array is
     * evenly divisible by the rate (1600-capacity).
     * @param input Parameter for the input bytes.
     * @param capacity Parameter for the capacity.
     * @return Returns a two dimensional array corresponding to an array of input.length/(1600-capacity) state arrays.
     */
    private static long[][] byteArrayToStates(final byte[] input, final int capacity)
    {
        long[][] states = new long[(input.length*8)/(1600-capacity)][25];
        int offset = 0;

        for (int i = 0; i < states.length; i++)
        {
            long[] state = new long[25];

            for (int j = 0; j < (1600-capacity)/64; j++)
            {
                long word = bytesToWord(offset, input);
                state[j] = word;
                offset += 8;
            }
            //Remaining (capacity/64) words will be 0
            states[i] = state;
        }

        return states;
    }

    /**
     * Converts the bytes from in[l,r] into a 64 bit word (which is a long)
     * @param offset Parameter for the position in the array to read the eight bytes from.
     * @param input Parameter for the byte array to read from.
     * @return Returns a long that is the result of concatenating the eight bytes beginning at offset.
     */
    private static long bytesToWord(final int offset, final byte[] input)
    {
        if (input.length < offset+8) throw new IllegalArgumentException("Byte range unreachable, index out of range.");
        long word = 0L;

        for (int i = 0; i < 8; i++)
        {
            word += (((long)input[offset + i]) & 0xff)<<(8*i);
        }

        return word;
    }

    private static long[] xorStates(final long[] s1, final long[] s2)
    {
        long[] out = new long[25];

        for (int i = 0; i < s1.length; i++)
        {
            out[i] = s1[i] ^ s2[i];
        }

        return out;
    }

    private static int floorLog(int num)
    {
        if (num < 0) throw new IllegalArgumentException("Log is undefined for negative numbers.");
        int exp = -1;

        while (num > 0)
        {
            num = num>>>1;
            exp++;
        }

        return exp;
    }

    private static long lRotWord(final long w, final int offset)
    {
        int ofs = offset % 64;

        return w << ofs | (w >>>(Long.SIZE - ofs));
    }

    private static byte[] mergeByteArrays(final byte[] byteOne, final byte[] byteTwo)
    {
        byte[] mrg = Arrays.copyOf(byteOne, byteOne.length + byteTwo.length);
        System.arraycopy(byteTwo, 0, mrg, byteOne.length, byteTwo.length);

        return mrg;
    }
}
