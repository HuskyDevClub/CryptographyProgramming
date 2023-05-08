import java.util.Arrays;

/**
 * Implementation of ECDHIES encryption and decryption
 *
 * @author Yudong Lin
 */
final class ECDHIES {
    final static int Z_LEN = 64;
    final static int T_LEN = 64;

    /**
     * @param data the date that will be encrypted
     * @param pw   the passphrase used for encryption
     * @return the data that is encrypted
     */
    static byte[] encrypt(final byte[] data, final byte[] pw) {
        final byte[] z = Glossary.random(Z_LEN * 8);
        final byte[] ke_ka = Keccak.KMACXOF256(Glossary.array_concatenation(z, pw), new byte[]{}, 1024, "S");
        final byte[] ke = Glossary.substring(ke_ka, 0, ke_ka.length / 2);
        final byte[] ka = Glossary.substring(ke_ka, ke_ka.length / 2, ke_ka.length);
        final byte[] c = Keccak.KMACXOF256(ke, new byte[]{}, data.length * 8, "SKE");
        // xor c with m
        for (int i = 0; i < c.length; i++) {
            c[i] = (byte) (c[i] ^ data[i]);
        }
        final byte[] t = Keccak.KMACXOF256(ka, data, T_LEN * 8, "SKA");
        return Glossary.array_concatenation(z, c, t);
    }

    /**
     * @param data the date that will be decrypted
     * @param pw   the passphrase used for decryption
     * @return the data that is decrypted
     */
    static byte[] decrypt(final byte[] data, final byte[] pw) {
        // obtain z, c and t from data
        final byte[] z = Arrays.copyOfRange(data, 0, Z_LEN);
        final byte[] c = Arrays.copyOfRange(data, z.length, data.length - T_LEN);
        final byte[] t = Arrays.copyOfRange(data, z.length + c.length, data.length);

        final byte[] ke_ka = Keccak.KMACXOF256(Glossary.array_concatenation(z, pw), new byte[]{}, 1024, "S");
        final byte[] ke = Glossary.substring(ke_ka, 0, ke_ka.length / 2);
        final byte[] ka = Glossary.substring(ke_ka, ke_ka.length / 2, ke_ka.length);
        final byte[] m = Keccak.KMACXOF256(ke, new byte[]{}, c.length * 8, "SKE");
        // xor m with c
        for (int i = 0; i < m.length; i++) {
            m[i] = (byte) (m[i] ^ c[i]);
        }
        final byte[] t_inv = Keccak.KMACXOF256(ka, m, 512, "SKA");
        if (!Arrays.equals(t_inv, t)) {
            throw new IllegalArgumentException("Invalid z potentially due to incorrect passphrase!");
        }
        return m;
    }
}
