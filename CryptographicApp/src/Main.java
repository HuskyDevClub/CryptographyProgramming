import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
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
        var pw = "Email Signature";
        var t = KMACX.KMACXOF256(pw.getBytes(), data, 512, "T");
        System.out.printf("Authentication tag (length %d):\n", t.length);
        Glossary.displayBytes(t);

        // Encrypting a byte array
        var z = Glossary.random(512);
        var ke_ka = KMACX.KMACXOF256(Glossary.array_concatenation(z, pw.getBytes()), "".getBytes(), 1024, "S");
        var ke = Glossary.substring(ke_ka, 0, ke_ka.length / 2);
        var ka = Glossary.substring(ke_ka, ke_ka.length / 2, ke_ka.length);
        assert ke.length == ka.length;
        var c = KMACX.KMACXOF256(ke, "".getBytes(), data.length, "SKE");
        // xor c with m
        for (int i = 0; i < c.length; i++) {
            c[i] = (byte) (c[i] ^ data[i]);
        }
        t = KMACX.KMACXOF256(ka, data, 512, "SKA");
        // symmetric cryptogram: (z, c, t)

        // Decrypting a symmetric cryptogram
        ke_ka = KMACX.KMACXOF256(Glossary.array_concatenation(z, pw.getBytes()), "".getBytes(), 1024, "S");
        ke = Glossary.substring(ke_ka, 0, ke_ka.length / 2);
        ka = Glossary.substring(ke_ka, ke_ka.length / 2, ke_ka.length);
        var m = KMACX.KMACXOF256(ke, "".getBytes(), c.length, "SKE");
        // xor m with c
        for (int i = 0; i < m.length; i++) {
            m[i] = (byte) (m[i] ^ c[i]);
        }
        var t_inv = KMACX.KMACXOF256(ka, m, 512, "SKA");
        if (t_inv != t) {
            System.out.println("T accepted!");
        }
    }

    private static void testAll() throws NoSuchAlgorithmException {
        Glossary.test();
        cShake.test();
    }
}
