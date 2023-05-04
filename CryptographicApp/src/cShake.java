import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.NoSuchAlgorithmException;
import java.security.Security;

public class cShake {

    static void test() throws NoSuchAlgorithmException {
        var result1 = cSHAKE256(new byte[]{(byte) 0x00, (byte) 0x01, (byte) 0x02, (byte) 0x03}, 512, "", "Email Signature");
        Glossary.displayBytes(result1);
    }

    private static byte[] bytePadData(byte[] X, String N, String S) {
        return Glossary.array_concatenation(
                Glossary.bytepad(Glossary.array_concatenation(Glossary.encode_string(N), Glossary.encode_string(S)), 136),
                X,
                new byte[]{(byte) 0x00}
        );
    }

    static byte[] cSHAKE256(byte[] X, int length, String N, String S) throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
        assert N.length() <= Math.pow(2, 2040) && S.length() <= Math.pow(2, 2040);
        if (N.equals("") && S.equals("")) {
            return SHAKE.SHAKE256(X, length);
        } else {
            return KECCAK.KECCAK512(bytePadData(X, N, S), length);
        }
    }
}