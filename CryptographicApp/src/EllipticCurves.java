import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

public class EllipticCurves {

    final static int Z_LEN = 64;
    final static int T_LEN = 64;
    private final static BigInteger BIG_INT_FOUR = BigInteger.valueOf(4L);
    private static final EllipticCurvePoint G = new EllipticCurvePoint(BigInteger.valueOf(4L), false);

    public static void main(final String[] args) {
        // 0*G = O
        assertEquals(G.scalarMultiply(BigInteger.ZERO), EllipticCurvePoint.ZERO);
        // 1*G = G
        assertEquals(G.scalarMultiply(BigInteger.ONE), G);
        // 2*G = G + G
        assertEquals(G.scalarMultiply(BigInteger.TWO), G.add(G));
        // 4*G = 2*(2*G)
        assertEquals(G.scalarMultiply(BIG_INT_FOUR), G.scalarMultiply(BigInteger.TWO).scalarMultiply(BigInteger.TWO));
        // 4*G ≠ O
        assertNotEquals(G.scalarMultiply(BIG_INT_FOUR), EllipticCurvePoint.ZERO);
        // r*G = O
        assertEquals(G.scalarMultiply(EllipticCurvePoint.R), EllipticCurvePoint.ZERO);
        for (int i = 0; i < 100; i++) {
            final var k = new BigInteger(Glossary.random(512));
            final var t = new BigInteger(Glossary.random(512));
            assertEquals(G.scalarMultiply(k), G.scalarMultiply(k.mod(EllipticCurvePoint.R)));
            assertEquals(G.scalarMultiply(k.add(BigInteger.ONE)), G.scalarMultiply(k).add(G));
            assertEquals(G.scalarMultiply(k.add(t)), G.scalarMultiply(k).add(G.scalarMultiply(t)));
            assertEquals(G.scalarMultiply(k).scalarMultiply(t), G.scalarMultiply(k.multiply(t).mod(EllipticCurvePoint.R)));
        }
    }

    static EllipticCurveKeyPair getSchnorrKeyPair(final byte[] pw) {
        BigInteger s = new BigInteger(Keccak.KMACXOF256(pw, new byte[]{}, 512, "SK"));
        s = s.multiply(BIG_INT_FOUR).mod(EllipticCurvePoint.R);
        final var thePublicKey = G.scalarMultiply(s);
        final var thePrivateBytes = s.toByteArray();
        return new EllipticCurveKeyPair(thePublicKey.toByteArray(), thePrivateBytes);
    }

    static byte[] encrypt(final byte[] m, final byte[] V) {
        var k = new BigInteger(Glossary.random(Z_LEN * 8));
        k = k.multiply(BIG_INT_FOUR).mod(EllipticCurvePoint.R);
        final var W = EllipticCurvePoint.fromByteArray(V).scalarMultiply(k);
        final var Z = G.scalarMultiply(k);
        final byte[] ke_ka = Keccak.KMACXOF256(W.toByteArray(), new byte[]{}, 1024, "PK");
        final byte[] ke = Glossary.substring(ke_ka, 0, ke_ka.length / 2);
        final byte[] ka = Glossary.substring(ke_ka, ke_ka.length / 2, ke_ka.length);
        final var c = Keccak.KMACXOF256(ke, new byte[]{}, m.length * 8, "PKE");
        // xor c with m
        for (int i = 0; i < c.length; i++) {
            c[i] = (byte) (c[i] ^ m[i]);
        }
        final byte[] t = Keccak.KMACXOF256(ka, m, T_LEN * 8, "PKA");
        return Glossary.array_concatenation(Z.toByteArray(), c, t);
    }

    static byte[] decrypt(final byte[] data, final byte[] pw) {
        // obtain z, c and t from data
        final byte[] Z = Arrays.copyOfRange(data, 0, Z_LEN);
        final byte[] c = Arrays.copyOfRange(data, Z.length, data.length - T_LEN);
        final byte[] t = Arrays.copyOfRange(data, Z.length + c.length, data.length);

        var s = new BigInteger(Keccak.KMACXOF256(pw, new byte[]{}, 512, "SK"));
        s = s.multiply(BIG_INT_FOUR).mod(EllipticCurvePoint.R);
        final var W = EllipticCurvePoint.fromByteArray(Z).scalarMultiply(s);
        final byte[] ke_ka = Keccak.KMACXOF256(W.toByteArray(), new byte[]{}, 1024, "PK");
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

    static EllipticCurveKeyPair getSignature(final byte[] m, final byte[] pw) {
        var s = new BigInteger(Keccak.KMACXOF256(pw, new byte[]{}, 512, "SK"));
        s = s.multiply(BIG_INT_FOUR).mod(EllipticCurvePoint.R);
        var k = new BigInteger(Keccak.KMACXOF256(s.toByteArray(), m, 512, "N"));
        k = k.multiply(BIG_INT_FOUR).mod(EllipticCurvePoint.R);
        final var U = G.scalarMultiply(k);
        final var h = new BigInteger(Keccak.KMACXOF256(U.toByteArray(), m, 512, "T"));
        final var z = k.subtract(h.multiply(s)).mod(EllipticCurvePoint.R);
        return new EllipticCurveKeyPair(h.toByteArray(), z.toByteArray());
    }

    static boolean verifySignature(final byte[] signature, final byte[] m, final byte[] V) throws IOException, ClassNotFoundException {
        final EllipticCurveKeyPair theSignature = EllipticCurveKeyPair.fromByteArray(signature);
        final var h = new BigInteger(theSignature.getPublicKey());
        final var z = new BigInteger(theSignature.getPrivateKey());
        final var U = G.scalarMultiply(z).add(EllipticCurvePoint.fromByteArray(V).scalarMultiply(h));
        return new BigInteger(Keccak.KMACXOF256(U.toByteArray(), m, 512, "T")).equals(h);
    }
}
