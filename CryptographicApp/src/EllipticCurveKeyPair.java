import java.io.*;

/**
 * This class is for storing Elliptic Curve key pair.
 *
 * @author Brian LeSmith
 * @author Yudong Lin
 */
final class EllipticCurveKeyPair implements Serializable {
    private final byte[] myPublicKey;
    private final byte[] myPrivateBytes;

    /**
     * Create a new key pair
     *
     * @param publicKeys  public key
     * @param privateKeys private key
     */
    EllipticCurveKeyPair(final byte[] privateKeys, final byte[] publicKeys) {
        this.myPublicKey = publicKeys;
        this.myPrivateBytes = privateKeys;
    }

    /**
     * Serialize a EllipticCurveKeyPair into a byte array
     *
     * @param theKeyPair the key pair that will be serialized
     * @return the serialized key pair
     * @throws IOException something went wrong during the process
     */
    static byte[] toByteArray(final EllipticCurveKeyPair theKeyPair) throws IOException {
        final ByteArrayOutputStream streamOut = new ByteArrayOutputStream();
        final ObjectOutputStream objectOut = new ObjectOutputStream(streamOut);
        objectOut.writeObject(theKeyPair);
        objectOut.flush();
        return streamOut.toByteArray();
    }

    /**
     * Recreate a EllipticCurveKeyPair from a byte array
     *
     * @param theKeyPair the serialized key in byte array from
     * @return the Recreated EllipticCurveKeyPair
     * @throws IOException            something went wrong during the process
     * @throws ClassNotFoundException something went wrong during the process
     */
    static EllipticCurveKeyPair fromByteArray(final byte[] theKeyPair) throws IOException, ClassNotFoundException {
        final ByteArrayInputStream theInputStream = new ByteArrayInputStream(theKeyPair);
        final ObjectInput objectInput = new ObjectInputStream(theInputStream);
        return (EllipticCurveKeyPair) objectInput.readObject();
    }

    /**
     * Getter for the byte array form of the public key.
     *
     * @return Returns the byte array public key.
     */
    byte[] getPublicKey() {
        return this.myPublicKey;
    }

    /**
     * Getter for the byte array form of the private key.
     *
     * @return Returns the byte array private key.
     */
    byte[] getPrivateKey() {
        return this.myPrivateBytes;
    }
}
