import java.security.NoSuchAlgorithmException;

public class KMACX {

    static byte[] KMACXOF256(String K, byte[] X, int L, String S) throws NoSuchAlgorithmException {
        var newX = Glossary.array_concatenation(Glossary.bytepad(Glossary.encode_string(K), 136), X, Glossary.right_encode(0));
        return cShake.cSHAKE256(newX, L, "KMAC", S);
    }
}