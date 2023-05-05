import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        testAll();
        if (args.length < 1) {
            Scanner _SCANNER = new Scanner(System.in);
            System.out.print("Please enter a string: ");
            String strIn = _SCANNER.nextLine();
            System.out.println("string S: " + strIn);
            process(strIn.getBytes());
        } else if (args.length < 2) {
            System.out.println("Invalid argument format detected, abort.");
        } else if (args[0].startsWith("-f")) {
            process(Files.readAllBytes(Paths.get(args[1])));
        } else if (args[0].startsWith("-s")) {
            process(args[1].getBytes());
        } else {
            System.out.println("Invalid argument detected, abort.");
        }
    }

    static private void process(byte[] data) throws NoSuchAlgorithmException {
        // Computing a cryptographic hash
        var h = KMACX.KMACXOF256("".getBytes(), data, 512, "D");
        System.out.printf("Plain cryptographic hash (length %d):\n", h.length);
        Glossary.displayBytes(h);

        //Compute an authentication tag
        Scanner _SCANNER = new Scanner(System.in);
        System.out.print("Please enter a string as passphrase: ");
        byte[] pw = _SCANNER.nextLine().getBytes();
        var t = KMACX.KMACXOF256(pw, data, 512, "T");
        System.out.printf("Authentication tag (length %d):\n", t.length);
        Glossary.displayBytes(t);

        // Encrypting a byte array
        var enc_data = ECDHIES.encrypt(data, pw);
        System.out.printf("Encrypted data (length %d):\n", enc_data.length);
        Glossary.displayBytes(enc_data);

        // Decrypting a symmetric cryptogram
        var dec_data = ECDHIES.decrypt(enc_data, pw);
        System.out.printf("\nDecrypted data (length %d):\n", dec_data.length);
        Glossary.displayBytes(dec_data);
        System.out.printf("Decrypted message: %s\n", new String(dec_data));
        System.out.printf("Same as previous: %b\n", Arrays.equals(data, ECDHIES.decrypt(enc_data, pw)));
    }

    private static void testAll() throws NoSuchAlgorithmException {
        Glossary.test();
        cShake.test();
    }
}
