import java.math.BigInteger;
import java.util.Arrays;

/**
 * This class is for encapsulating an ECDHIES key pair.
 * The public key is two EllipticCurvePoints,
 * the private key is a BigInteger which is created using
 * a user given password.
 */
public class EllipticCurveKeyPair {
    public static final EllipticCurvePoint PUBLIC_KEY_POINT = new EllipticCurvePoint(BigInteger.valueOf(4L), false);
    private final EllipticCurvePoint myPublicKey;
    private final byte[] myPrivateBytes;
    private final BigInteger myPrivateScalar;

    /**
     * Generates a new key pair using the byte array parameter.
     *
     * @param thePassword Parameter for the password.
     */
    public EllipticCurveKeyPair(final byte[] thePassword) {
        final BigInteger s = new BigInteger(Keccak.KMACXOF256(thePassword, new byte[]{}, 512, "SK"));
        this.myPrivateScalar = s.multiply(BigInteger.valueOf(4L));
        this.myPublicKey = PUBLIC_KEY_POINT.scalarMultiply(myPrivateScalar);
        this.myPrivateBytes = myPrivateScalar.toByteArray();
    }

    /**
     * Constructs a new key pair using the private key parameter.
     *
     * @param thePrivateKey Parameter for the private key.
     */
    public EllipticCurveKeyPair(final BigInteger thePrivateKey) {
        this.myPrivateScalar = thePrivateKey;
        this.myPrivateBytes = myPrivateScalar.toByteArray();
        this.myPublicKey = PUBLIC_KEY_POINT.scalarMultiply(myPrivateScalar);
    }

    /**
     * Generates a new key pair with the provided password parameter.
     *
     * @param thePassword Parameter for the password.
     */
    public EllipticCurveKeyPair(final String thePassword) {
        this(thePassword.getBytes());
    }

    /**
     * Reads the private key and returns a new EllipticCurveKeyPair with
     * a private and a public key.
     *
     * @param theURL      Parameter for the file name containing the private key.
     * @param thePassword Parameter for the password.
     * @return Returns a new EllipticCurveKeyPair object.
     */
    public static EllipticCurveKeyPair readPrivateKeyFile(final String theURL, final byte[] thePassword) {
        final ValidData prvBytes = KeccakCrypt.keccakDecrypt(thePassword, ReaderWriter.readFileBytes(theURL));

        if (!prvBytes.isValid()) {
            System.out.println("Authentication the private key failed.");
            System.out.println("Stored key could corrupted, using password to reinitialize recommended.");
            System.exit(1);
        }

        return new EllipticCurveKeyPair(new BigInteger(prvBytes.getBytes()));
    }

    /**
     * Reads a private key file with the password provided as a String.
     *
     * @param theURL      Parameter for the file name.
     * @param thePassword Parameter for the password.
     */
    public static EllipticCurveKeyPair readPrivateKeyFile(final String theURL, final String thePassword) {
        return readPrivateKeyFile(theURL, thePassword.getBytes());
    }

    /**
     * Reads the specified public key file, returns EllipticCurvePoint.
     *
     * @param theURL Parameter for the URL of the file.
     * @return Returns an EllipticCurvePoint.
     */
    public static EllipticCurvePoint readPubKeyFile(final String theURL) {
        return EllipticCurvePoint.fromByteArray(ReaderWriter.readFileBytes(theURL));
    }

    /**
     * Writes the public key to a file by using PUBLIC_KEY_POINT.
     * PUBLIC_KEY_POINT is not written to a file.
     *
     * @param theURL Parameter for the file name.
     */
    public void writePubToFile(final String theURL) {
        ReaderWriter.writeBytesToFile(myPublicKey.toByteArray(), theURL);
    }

    /**
     * This method will encrypt the private key under the provided password,
     * then writes it to a file name that is provided.
     *
     * @param theURL      Parameter for the file url.
     * @param thePassword Parameter for the password the private key is encrypted under.
     */
    public void writePrivateKeyToFile(final String theURL, final byte[] thePassword) {
        ReaderWriter.writeBytesToFile(KeccakCrypt.keccakEncrypt(thePassword, myPrivateBytes), theURL);
    }

    /**
     * Reads the provided string as a byte[] then uses it as a password for
     * writing to an output for writing the private key to a given file name.
     *
     * @param theURL      Parameter for the file name.
     * @param thePassword Parameter for the password.
     */
    public void writePrivateKeyToFile(final String theURL, final String thePassword) {
        writePrivateKeyToFile(theURL, thePassword.getBytes());
    }

    /**
     * Returns the dynamic public key as an EllipticCurvePoint.
     *
     * @return Returns the EllipticCurvePoint that complements PUBLIC_KEY_POINT.
     */
    public EllipticCurvePoint getPublicCurvePoint() {
        return this.myPublicKey;
    }

    /**
     * Returns the scalar derived from the private key.
     *
     * @return a BigInteger s, the scalar derived from the user provided password
     */
    public BigInteger getPrivateScalar() {
        return this.myPrivateScalar;
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

    public byte[] getPublicKey() {
        return new byte[];
    }

    public byte[] getPrivateKey() {
        return new byte[];
    }
}
