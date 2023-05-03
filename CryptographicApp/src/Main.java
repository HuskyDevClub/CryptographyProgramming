import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        if (args.length < 1) {
            System.out.println("No argument detected, abort.");
        } else if (args.length < 2) {
            if (args[0].startsWith("-s")) {
                Scanner _SCANNER = new Scanner(System.in);
                System.out.print("Please enter a string: ");
                String strIn = _SCANNER.nextLine();
                System.out.println("string S: " + strIn);
                var hashBytes = KMACX.KMACXOF256("Email Signature", strIn.getBytes(), 256, "D");
                System.out.printf("encode of S (length %d):\n", hashBytes.length);
                for (byte b : hashBytes) {
                    System.out.printf("%02x ", b);
                }
            } else {
                System.out.println("Invalid argument format detected, abort.");
            }
        } else if (args[0].startsWith("-f")) {
            byte[] data = Files.readAllBytes(Paths.get(args[1]));
            var hashBytes = KMACX.KMACXOF256("Email Signature", data, 256, "D");
            System.out.printf("Plain cryptographic hash of a given file (length %d):\n", hashBytes.length);
            for (byte b : hashBytes) {
                System.out.printf("%02x ", b);
            }
        } else {
            System.out.println("Invalid argument detected, abort.");
        }
    }
}
