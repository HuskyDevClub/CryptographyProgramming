import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.util.Arrays;

public class EllipticCurves {

    final static int Z_LEN = 64;
    final static int T_LEN = 64;

    static EllipticCurveKeyPair getSchnorrKeyPair(final byte[] pw) {
        return new EllipticCurveKeyPair(pw);
    }

    static byte[] encrypt(final byte[] m, final byte[] V) {
        var k = new BigInteger(Glossary.random(512));
        k = k.multiply(BigInteger.valueOf(4L));
        final var W = EllipticCurvePoint.fromByteArray(V).scalarMultiply(k);
        final var Z = EllipticCurveKeyPair.PUBLIC_KEY_POINT.scalarMultiply(k);
        final byte[] ke_ka = Keccak.KMACXOF256(W.getX().toByteArray(), new byte[]{}, 1024, "PK");
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
        s = s.multiply(BigInteger.valueOf(4L));
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
        s = s.multiply(BigInteger.valueOf(4L));
        var k = new BigInteger(Keccak.KMACXOF256(s.toByteArray(), m, 512, "N"));
        k = k.multiply(BigInteger.valueOf(4L));
        final var U = EllipticCurveKeyPair.PUBLIC_KEY_POINT.scalarMultiply(k);
        final var h = new BigInteger(Keccak.KMACXOF256(U.toByteArray(), m, 512, "T"));
        final var z = k.subtract(h.multiply(s)).mod(EllipticCurvePoint.SCHNORR_COMPUTE_R);
        return new EllipticCurveKeyPair(h.toByteArray(), z.toByteArray());
    }

    static boolean verifySignature(final byte[] signature, final byte[] m, final byte[] V) throws IOException, ClassNotFoundException {
        final ByteArrayInputStream theInputStream = new ByteArrayInputStream(signature);
        final ObjectInput objectInput = new ObjectInputStream(theInputStream);
        final EllipticCurveKeyPair theSignature = (EllipticCurveKeyPair) objectInput.readObject();
        final var h = new BigInteger(theSignature.getPublicKey());
        final var z = new BigInteger(theSignature.getPrivateKey());
        final var U = EllipticCurveKeyPair.PUBLIC_KEY_POINT.scalarMultiply(z).add(EllipticCurvePoint.fromByteArray(V).scalarMultiply(h));
        return new BigInteger(Keccak.KMACXOF256(U.toByteArray(), m, 512, "T")).equals(h);
    }
}
