import java.util.Arrays;

public class EllipticCurves {

    final static int Z_LEN = 64;
    final static int T_LEN = 64;

    static EllipticCurveKeyPair getSchnorrKeyPair(final byte[] pw) {
        return new EllipticCurveKeyPair(pw);
    }

    static byte[] encrypt(final byte[] m, final byte[] V) {
        var k = Glossary.random(512);
        k = Glossary.array_concatenation(k, k, k, k);
        final var W = EllipticCurves.multiplicationByScalar(k, V);
        final var Z = EllipticCurves.multiplicationByScalar(k, G);
        final byte[] ke_ka = Keccak.KMACXOF256(W, new byte[]{}, 1024, "PK");
        final byte[] ke = Glossary.substring(ke_ka, 0, ke_ka.length / 2);
        final byte[] ka = Glossary.substring(ke_ka, ke_ka.length / 2, ke_ka.length);
        final var c = Keccak.KMACXOF256(ke, new byte[]{}, m.length * 8, "PKE");
        // xor c with m
        for (int i = 0; i < c.length; i++) {
            c[i] = (byte) (c[i] ^ m[i]);
        }
        final byte[] t = Keccak.KMACXOF256(ka, m, T_LEN * 8, "PKA");
        return Glossary.array_concatenation(Z, c, t);
    }

    static byte[] decrypt(final byte[] data, final byte[] pw) {
        // obtain z, c and t from data
        final byte[] Z = Arrays.copyOfRange(data, 0, Z_LEN);
        final byte[] c = Arrays.copyOfRange(data, Z.length, data.length - T_LEN);
        final byte[] t = Arrays.copyOfRange(data, Z.length + c.length, data.length);

        var s = Keccak.KMACXOF256(pw, new byte[]{}, 512, "SK");
        s = Glossary.array_concatenation(s, s, s, s);
        final var W = EllipticCurves.multiplicationByScalar(s, Z);
        final byte[] ke_ka = Keccak.KMACXOF256(W, new byte[]{}, 1024, "PK");
        final byte[] ke = Glossary.substring(ke_ka, 0, ke_ka.length / 2);
        final byte[] ka = Glossary.substring(ke_ka, ke_ka.length / 2, ke_ka.length);
        final var m = Keccak.KMACXOF256(ke, new byte[]{}, c.length * 8, "PKE");
        // xor m with c
        for (int i = 0; i < m.length; i++) {
            m[i] = (byte) (m[i] ^ c[i]);
        }
        final var t_inv = Keccak.KMACXOF256(ka, m, 512, "PKA");
        if (!Arrays.equals(t_inv, t)) {
            throw new IllegalArgumentException("Invalid z potentially due to incorrect passphrase!");
        }
        return m;
    }

    static byte[][] getSignature(final byte[] m, final byte[] pw) {
        var s = Keccak.KMACXOF256(pw, new byte[]{}, 512, "SK");
        s = Glossary.array_concatenation(s, s, s, s);
        var k = Keccak.KMACXOF256(s, m, 512, "N");
        k = Glossary.array_concatenation(k, k, k, k);
        final var U = EllipticCurves.multiplicationByScalar(k, G);
        final var h = Keccak.KMACXOF256(U, m, 512, "T");

        final var z = k;
        // z  (k – hs) mod r

        return new byte[][]{h, z};
    }

    static boolean verifySignature(final byte[] signature, final byte[] m, final byte[] V) {
        final var h = signature[0];
        final var z = signature[1];
        final var U = Glossary.array_concatenation(multiplicationByScalar(z, G), multiplicationByScalar(h, V));
        return Arrays.equals(Keccak.KMACXOF256(U, m, 512, "T"), h);
    }
}
