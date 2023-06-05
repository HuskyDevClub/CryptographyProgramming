import java.io.IOException;
import java.math.BigInteger;
import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * The Elliptic Curve based function, takes input and arguments according to the instruction listed in the report.
 * Then do whatever it supposes to do (hopefully)
 *
 * @author Yudong Lin
 */
public class EllipticCurves {

    public static final BigInteger R = BigInteger.valueOf(2L).pow(446)
            .subtract(new BigInteger("13818066809895115352007386748515426880336692474882178609894547503885"));
    private final static BigInteger BIG_INT_FOUR = BigInteger.valueOf(4L);
    private static final EllipticCurvePoint G = new EllipticCurvePoint(
            new BigInteger("181709681073901722637330951972001133588410340"), false
    );

    public static void main(final String[] args) {
        // 0*G = O
        assertEquals(G.scalarMultiply(BigInteger.ZERO), new EllipticCurvePoint());
        // 1*G = G
        assertEquals(G.scalarMultiply(BigInteger.ONE), G);
        // 2*G = G + G
        assertEquals(G.scalarMultiply(BigInteger.TWO), G.add(G));
        // 4*G = 2*(2*G)
        assertEquals(G.scalarMultiply(BIG_INT_FOUR), G.scalarMultiply(BigInteger.TWO).scalarMultiply(BigInteger.TWO));
        // 4*G ≠ O
        assertNotEquals(G.scalarMultiply(BIG_INT_FOUR), new EllipticCurvePoint());
        // r*G = O
        assertEquals(G.scalarMultiply(R), new EllipticCurvePoint());
        for (int i = 0; i < 100; i++) {
            final BigInteger k = new BigInteger(Glossary.random(512)).multiply(BIG_INT_FOUR).mod(R);
            final BigInteger t = new BigInteger(Glossary.random(512)).multiply(BIG_INT_FOUR).mod(R);
            assertEquals(G.scalarMultiply(k), G.scalarMultiply(k.mod(R)));
            assertEquals(G.scalarMultiply(k.add(BigInteger.ONE)), G.scalarMultiply(k).add(G));
            assertEquals(G.scalarMultiply(k.add(t)), G.scalarMultiply(k).add(G.scalarMultiply(t)));
            assertEquals(G.scalarMultiply(k).scalarMultiply(t), G.scalarMultiply(k.multiply(t).mod(R)));
        }
    }

    /**
     * Generating a (Schnorr/DHIES) key pair from passphrase
     *
     * @param pw passphrase
     * @return a (Schnorr/DHIES) key pair
     */
    static EllipticCurveKeyPair getSchnorrKeyPair(final byte[] pw) {
        BigInteger s = new BigInteger(Keccak.KMACXOF256(pw, new byte[]{}, 512, "SK"));
        s = s.multiply(BIG_INT_FOUR).mod(R);
        final EllipticCurvePoint V = G.scalarMultiply(s);
        return new EllipticCurveKeyPair(s.toByteArray(), V.toByteArray());
    }

    /**
     * Encrypting a byte array m under the (Schnorr/DHIES) public key V
     *
     * @param m message to be encrypted
     * @param V public key to be used
     * @return cryptogram
     */
    static byte[] encrypt(final byte[] m, final byte[] V) {
        BigInteger k = new BigInteger(Glossary.random(512));
        k = k.multiply(BIG_INT_FOUR).mod(R);
        final EllipticCurvePoint W = EllipticCurvePoint.fromByteArray(V).scalarMultiply(k);
        final EllipticCurvePoint Z = G.scalarMultiply(k);
        final byte[] ke_ka = Keccak.KMACXOF256(W.getX().toByteArray(), new byte[]{}, 1024, "PK");
        final byte[] ke = Glossary.substring(ke_ka, 0, ke_ka.length / 2);
        final byte[] ka = Glossary.substring(ke_ka, ke_ka.length / 2, ke_ka.length);
        final byte[] c = Keccak.KMACXOF256(ke, new byte[]{}, m.length * 8, "PKE");
        // xor c with m
        for (int i = 0; i < c.length; i++) {
            c[i] = (byte) (c[i] ^ m[i]);
        }
        final byte[] t = Keccak.KMACXOF256(ka, m, 512, "PKA");
        return Glossary.array_concatenation(Z.toByteArray(), c, t);
    }

    /**
     * Decrypting a cryptogram (Z, c, t) under passphrase pw
     *
     * @param data cryptogram
     * @param pw   passphrase
     * @return decrypted data
     */
    static byte[] decrypt(final byte[] data, final byte[] pw) {
        // obtain z, c and t from data
        final byte[] Z = Arrays.copyOfRange(data, 0, EllipticCurvePoint.STANDARD_BYTE_LENGTH);
        final byte[] c = Arrays.copyOfRange(data, Z.length, data.length - 64);
        final byte[] t = Arrays.copyOfRange(data, Z.length + c.length, data.length);
        BigInteger s = new BigInteger(Keccak.KMACXOF256(pw, new byte[]{}, 512, "SK"));
        s = s.multiply(BIG_INT_FOUR).mod(R);
        final EllipticCurvePoint W = EllipticCurvePoint.fromByteArray(Z).scalarMultiply(s);
        final byte[] ke_ka = Keccak.KMACXOF256(W.getX().toByteArray(), new byte[]{}, 1024, "PK");
        final byte[] ke = Glossary.substring(ke_ka, 0, ke_ka.length / 2);
        final byte[] ka = Glossary.substring(ke_ka, ke_ka.length / 2, ke_ka.length);
        final byte[] m = Keccak.KMACXOF256(ke, new byte[]{}, c.length * 8, "PKE");
        // xor m with c
        for (int i = 0; i < m.length; i++) {
            m[i] = (byte) (m[i] ^ c[i]);
        }
        final byte[] t_inv = Keccak.KMACXOF256(ka, m, 512, "PKA");
        if (!Arrays.equals(t_inv, t)) {
            throw new IllegalArgumentException("Invalid z potentially due to incorrect passphrase!");
        }
        return m;
    }

    /**
     * Generating a signature for a byte array m under passphrase pw
     *
     * @param m  the data to be signed
     * @param pw passphrase
     * @return a signature
     */
    static EllipticCurveKeyPair getSignature(final byte[] m, final byte[] pw) {
        BigInteger s = new BigInteger(Keccak.KMACXOF256(pw, new byte[]{}, 512, "SK"));
        s = s.multiply(BIG_INT_FOUR).mod(R);
        BigInteger k = new BigInteger(Keccak.KMACXOF256(s.toByteArray(), m, 512, "N"));
        k = k.multiply(BIG_INT_FOUR).mod(R);
        final EllipticCurvePoint U = G.scalarMultiply(k);
        final BigInteger h = new BigInteger(Keccak.KMACXOF256(U.getX().toByteArray(), m, 512, "T"));
        final BigInteger z = k.subtract(h.multiply(s)).mod(R);
        return new EllipticCurveKeyPair(h.toByteArray(), z.toByteArray());
    }

    /**
     * Verifying a signature (h, z) for a byte array m under the (Schnorr/ DHIES) public key V
     *
     * @param signature the signature to be verified
     * @param m         the data to be verified
     * @param V         public key
     * @return whether signature can verify data
     * @throws IOException            something went wrong
     * @throws ClassNotFoundException something went wrong
     */
    static boolean verifySignature(final byte[] signature, final byte[] m, final byte[] V) throws IOException, ClassNotFoundException {
        final EllipticCurveKeyPair theSignature = EllipticCurveKeyPair.fromByteArray(signature);
        final BigInteger h = new BigInteger(theSignature.getPrivateKey());
        final BigInteger z = new BigInteger(theSignature.getPublicKey());
        final EllipticCurvePoint U = G.scalarMultiply(z).add(EllipticCurvePoint.fromByteArray(V).scalarMultiply(h));
        return new BigInteger(Keccak.KMACXOF256(U.getX().toByteArray(), m, 512, "T")).equals(h);
    }
}
