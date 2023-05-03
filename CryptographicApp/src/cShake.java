import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class cShake {

    static byte[] cSHAKE256(byte[] X, int length, String N, String S) throws NoSuchAlgorithmException {
        assert N.length() <= Math.pow(2, 2040) && S.length() <= Math.pow(2, 2040);
        if (N.equals("") && S.equals("")) {
            return SHAKE.SHAKE256(X, length);
        } else {
            Security.addProvider(new BouncyCastleProvider());
            byte[] bytePadBytes = Glossary.bytepad(Glossary.array_concatenation(Glossary.encode_string(N), Glossary.encode_string(S)), 136);
            byte[] after = Glossary.array_concatenation(bytePadBytes, X, new byte[]{(byte) 0x00});
            return KECCAK.KECCAK512(after, length);
        }
    }
}