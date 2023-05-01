public class KMACX {

    static byte[] KMACXOF256(String K, String X, int L, String S) {
        var newX = Glossary.array_concatenation(Glossary.bytepad(Glossary.encode_string(K), 136), X.getBytes(), Glossary.right_encode(0));
        return cShake.cSHAKE256(newX, L, "KMAC", S);
    }
}