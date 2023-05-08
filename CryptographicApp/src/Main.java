import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Scanner;

/**
 * The main function, takes input and arguments according to the instruction listed in the report.
 * Then do whatever it supposes to do (hopefully)
 *
 * @author Yudong Lin
 */
final class Main {

    public static void main(final String[] args) throws IOException {
        if (args.length < 1) {
            System.out.println("Invalid argument format detected, abort.");
        } else if (args[0].equals("-test")) {
            // debugging use only
            Glossary.test();
        } else {
            /* getting the input arguments */
            final byte[] data;
            final List<String> argsL = Arrays.asList(args);
            int data_index = argsL.indexOf("-f");
            if (data_index < 0) {
                data_index = argsL.indexOf("-s");
                if (data_index < 0) {
                    data = input("Please enter a string: ");
                } else {
                    data = args[data_index + 1].getBytes();
                }
                System.out.println("string S: " + new String(data));
            } else {
                data = Files.readAllBytes(Paths.get(args[data_index + 1]));
            }

            /* doing whatever the user is asking for */
            if (args[0].equals("-h")) {
                computeHash(data);
            } else {
                switch (args[0]) {
                    case "-t" -> computeTag(data, getPassphrase(argsL));
                    case "-e" -> encryptData(data, getPassphrase(argsL), getOutputPath(argsL));
                    case "-d" -> decryptData(data, getPassphrase(argsL), getOutputPath(argsL));
                    default -> throw new IllegalArgumentException("Invalid argument, abort.");
                }
            }
        }
    }

    /**
     * ask user to input sth
     *
     * @param message the message used to prompt for user input
     * @return the user input in bytes
     */
    private static byte[] input(final String message) {
        System.out.print(message);
        final Scanner _SCANNER = new Scanner(System.in);
        final String strIn = _SCANNER.nextLine();
        return strIn.getBytes();
    }

    /**
     * get the passphrase
     *
     * @param args the input arguments
     * @return the passphrase
     */
    private static byte[] getPassphrase(final List<String> args) {
        final int _index = args.indexOf("-p");
        return _index < 0 ? input("Please enter a string as passphrase: ") : args.get(_index + 1).getBytes();
    }

    /**
     * get the output path
     *
     * @param args the input arguments
     * @return the output path
     */
    private static Path getOutputPath(final List<String> args) {
        final int _index = args.indexOf("-o");
        return _index < 0 ? null : Path.of(args.get(_index + 1));
    }

    /**
     * Computing a cryptographic hash
     *
     * @param data the data used to compute
     */
    private static void computeHash(final byte[] data) {
        final byte[] h = Keccak.KMACXOF256("".getBytes(), data, 512, "D");
        System.out.printf("Plain cryptographic hash (length %d):\n", h.length);
        Glossary.displayBytes(h);
    }

    /**
     * Compute an authentication tag
     *
     * @param data the data used to compute
     * @param pw   the passphrase that will be used
     */
    private static void computeTag(final byte[] data, final byte[] pw) {
        final byte[] t = Keccak.KMACXOF256(pw, data, 512, "T");
        System.out.printf("Authentication tag (length %d):\n", t.length);
        Glossary.displayBytes(t);
    }

    /**
     * encrypt given byte array data
     *
     * @param data the data that will be encrypted
     * @param pw   the passphrase that will be used
     */
    private static void encryptData(final byte[] data, final byte[] pw, final Path savedTo) throws IOException {
        final byte[] enc_data = ECDHIES.encrypt(data, pw);
        System.out.printf("Encrypted data (length %d):\n", enc_data.length);
        Glossary.displayBytes(enc_data);
        if (savedTo != null) {
            Files.write(savedTo, enc_data);
        }
    }

    /**
     * decrypt a symmetric cryptogram
     *
     * @param enc_data the data that will be decrypted
     * @param pw       the passphrase that will be used
     */
    private static void decryptData(final byte[] enc_data, final byte[] pw, final Path savedTo) throws IOException {
        final byte[] dec_data = ECDHIES.decrypt(enc_data, pw);
        System.out.printf("\nDecrypted data (length %d):\n", dec_data.length);
        Glossary.displayBytes(dec_data);
        System.out.printf("Decrypted message: %s\n", new String(dec_data));
        if (savedTo != null) {
            Files.write(savedTo, dec_data);
        }
    }
}
