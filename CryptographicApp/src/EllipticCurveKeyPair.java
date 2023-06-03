import java.math.BigInteger;
import java.util.Arrays;

/**
 * This class is for encapsulating an ECDHIES key pair.
 * The public key is two EllipticCurvePoints,
 * the private key is a BigInteger which is created using
 * a user given password.
 */
public class EllipticCurveKeyPair {
    /**
     * The static point of the public key.
     */
    public static final EllipticCurvePoint PUBLIC_KEY_POINT = new EllipticCurvePoint(BigInteger.valueOf(4L), false);
    private final EllipticCurvePoint myPublicKey;
    private final byte[] myPrivateBytes;

    /**
     * Generates a new key pair using the byte array parameter.
     *
     * @param thePassword Parameter for the password.
     */
    public EllipticCurveKeyPair(final byte[] thePassword) {
        BigInteger s = new BigInteger(Keccak.KMACXOF256(thePassword, new byte[]{}, 512, "SK"));
        s = s.multiply(BigInteger.valueOf(4L));
        this.myPublicKey = PUBLIC_KEY_POINT.scalarMultiply(s);
        this.myPrivateBytes = s.toByteArray();
    }

    /**
     * Generates a new key pair using the byte array parameter.
     *
     * @param publicKeys  public key
     * @param privateKeys private keys
     */
    public EllipticCurveKeyPair(final byte[] publicKeys, final byte[] privateKeys) {
        this.myPublicKey = EllipticCurvePoint.fromByteArray(publicKeys);
        this.myPrivateBytes = privateKeys;
    }

    /**
     * Getter for the byte array form of the public key.
     *
     * @return Returns the public key as a byte array.
     */
    public byte[] getPublicKey() {
        return this.myPublicKey.toByteArray();
    }

    /**
     * Getter for the byte array form of the private key.
     *
     * @return Returns the private key as a byte array.
     */
    public byte[] getPrivateKey() {
        return this.myPrivateBytes;
    }

    /**
     * Overriding the equals() method to compare two
     * EllipticKeyPair objects.
     *
     * @param theOther Parameter for the other keyPair to compare to.
     * @return Returns true if this equals theOther, false if not.
     */
    @Override
    public boolean equals(final Object theOther) {
        if (this == theOther) {
            return true;
        }

        if (theOther == null || getClass() != theOther.getClass()) {
            return false;
        }

        final EllipticCurveKeyPair ok = (EllipticCurveKeyPair) theOther;

        return Arrays.equals(myPrivateBytes, ok.myPrivateBytes) && myPublicKey.equals(ok.myPublicKey);
    }
}
