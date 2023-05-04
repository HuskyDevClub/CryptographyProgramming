import java.security.NoSuchAlgorithmException;

public class KMACX {

    /**
     * @param K key
     * @param X authenticated data
     * @param L output bits' length
     * @param S diversification string
     * @return Keccak message authentication code
     * @throws NoSuchAlgorithmException
     */
    static byte[] KMACXOF256(byte[] K, byte[] X, int L, String S) throws NoSuchAlgorithmException {
        var newX = Glossary.array_concatenation(Glossary.bytepad(Glossary.encode_string(K), 136), X, Glossary.right_encode(0));
        return cShake.cSHAKE256(newX, L, "KMAC", S);
    }
}