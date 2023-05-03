import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHAKE {

    static byte[] SHAKE256(byte[] X, int length) throws NoSuchAlgorithmException {
        return Glossary.substring(MessageDigest.getInstance("Shake-256").digest(X), 0, length);
    }
}
