import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class KECCAK {

    public static byte[] KECCAK512(byte[] X, int length) throws NoSuchAlgorithmException {
        return Glossary.substring(MessageDigest.getInstance("Keccak-512").digest(X), 0, length);
    }
}
