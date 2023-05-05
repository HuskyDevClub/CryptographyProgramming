import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class ECDHIES {
    final static int Z_LEN = 64;
    final static int T_LEN = 64;

    static byte[] encrypt(byte[] data, byte[] pw) throws NoSuchAlgorithmException {
        byte[] z = Glossary.random(Z_LEN * 8);
        var ke_ka = KMACX.KMACXOF256(Glossary.array_concatenation(z, pw), new byte[]{}, 1024, "S");
        byte[] ke = Glossary.substring(ke_ka, 0, ke_ka.length / 2);
        byte[] ka = Glossary.substring(ke_ka, ke_ka.length / 2, ke_ka.length);
        assert ke.length == ka.length;
        byte[] c = KMACX.KMACXOF256(ke, new byte[]{}, data.length, "SKE");
        // xor c with m
        for (int i = 0; i < c.length; i++) {
            c[i] = (byte) (c[i] ^ data[i]);
        }
        var t = KMACX.KMACXOF256(ka, data, T_LEN * 8, "SKA");
        return Glossary.array_concatenation(z, c, t);
    }

    static byte[] decrypt(byte[] data, byte[] pw) throws NoSuchAlgorithmException {
        byte[] z = new byte[Z_LEN];
        System.arraycopy(data, 0, z, 0, z.length);
        byte[] c = new byte[data.length - Z_LEN - T_LEN];
        System.arraycopy(data, z.length, c, 0, c.length);
        byte[] t = new byte[T_LEN];
        System.arraycopy(data, z.length + c.length, t, 0, t.length);

        byte[] ke_ka = KMACX.KMACXOF256(Glossary.array_concatenation(z, pw), new byte[]{}, 1024, "S");
        byte[] ke = Glossary.substring(ke_ka, 0, ke_ka.length / 2);
        byte[] ka = Glossary.substring(ke_ka, ke_ka.length / 2, ke_ka.length);
        var m = KMACX.KMACXOF256(ke, new byte[]{}, c.length, "SKE");
        // xor m with c
        for (int i = 0; i < m.length; i++) {
            m[i] = (byte) (m[i] ^ c[i]);
        }
        var t_inv = KMACX.KMACXOF256(ka, m, 512, "SKA");
        if (!Arrays.equals(t_inv, t)) {
            throw new IllegalArgumentException("Invalid z!");
        }
        return m;
    }
}
