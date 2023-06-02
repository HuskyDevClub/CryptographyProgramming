import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
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
            final List<String> argsL = Arrays.asList(args);
            if (argsL.get(0).startsWith("-ec")) {
                switch (args[0]) {
                    case "-eck" ->
                            getEllipticKeyPair(getPassphrase(argsL), getOutputPath(argsL), getSecondaryOutputPath(argsL));
                    case "-ece" ->
                            encryptDataUsingPublicKey(getInputData(argsL), readPublicKeyFile(argsL), getOutputPath(argsL));
                    case "-ecd" ->
                            decryptDataUsingPublicKey(getInputData(argsL, false), getPassphrase(argsL), getOutputPath(argsL));
                    case "-ecs" -> generateSignature(getInputData(argsL), getPassphrase(argsL), getOutputPath(argsL));
                    case "-ecv" ->
                            verifySignature(getInputData(argsL, false), Files.readAllBytes(Objects.requireNonNull(getOutputPath(argsL))), readPublicKeyFile(argsL));
                    default -> throw new IllegalArgumentException("Invalid argument, abort.");
                }
            } else {
                /* doing whatever the user is asking for */
                if (args[0].equals("-h")) {
                    computeHash(getInputData(argsL));
                } else {
                    switch (args[0]) {
                        case "-t" -> computeTag(getInputData(argsL), getPassphrase(argsL));
                        case "-e" -> encryptData(getInputData(argsL), getPassphrase(argsL), getOutputPath(argsL));
                        case "-d" -> decryptData(getInputData(argsL), getPassphrase(argsL), getOutputPath(argsL));
                        default -> throw new IllegalArgumentException("Invalid argument, abort.");
                    }
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
     * try to obtain input data from user
     *
     * @param args the input arguments
     * @return the content in the form of byte array
     * @throws IOException fail to obtain input data
     */
    private static byte[] getInputData(final List<String> args) throws IOException {
        return getInputData(args, true);
    }

    /**
     * obtain input data
     *
     * @param args             the input arguments
     * @param allowManualInput whether it is ok to prompt user to manually input string text as input
     * @return the content in the form of byte array
     * @throws IOException fail to obtain input data
     */
    private static byte[] getInputData(final List<String> args, final boolean allowManualInput) throws IOException {
        // try load data from given path if a path is given
        final int data_index = args.indexOf("-f");
        if (data_index > 0) {
            return Files.readAllBytes(Paths.get(args.get(data_index + 1)));
        } else if (allowManualInput) {
            final byte[] data = input("Please enter a string: ");
            System.out.println("string S: " + new String(data));
            return data;
        } else {
            throw new IOException("You have to specify an input file path using '-f <input file path>'");
        }
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
     * get the secondary output path
     *
     * @param args the input arguments
     * @return the output path
     */
    private static Path getSecondaryOutputPath(final List<String> args) {
        final int _index = args.indexOf("-o2");
        return _index < 0 ? null : Path.of(args.get(_index + 1));
    }

    /**
     * read public key from given file
     *
     * @param args the input arguments
     * @return the public key in byte array
     */
    private static byte[] readPublicKeyFile(final List<String> args) {
        final int _index = args.indexOf("-keyp");
        if (_index < 0) {
            throw new IllegalArgumentException("Missing argument -keyp!");
        }
        try {
            return Files.readAllBytes(Path.of(args.get(_index + 1)));
        } catch (final IOException e) {
            throw new IllegalArgumentException("Unable to read public key due to following error:\n" + e.getMessage());
        }
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
     * Save given byte array to path if path is not null
     *
     * @param savedTo save byte array to path
     * @param theData the byte array that will be saved
     */
    private static void saveByteArray(final Path savedTo, final byte[] theData) {
        if (savedTo != null) {
            try {
                Files.write(savedTo, theData);
            } catch (final IOException e) {
                System.out.println("Warning, cannot save the data!");
                System.out.println(e.getMessage());
            }
        }
    }

    /**
     * encrypt given byte array data
     *
     * @param data    the data that will be encrypted
     * @param pw      the passphrase that will be used
     * @param savedTo save encrypted data to path
     */
    private static void encryptData(final byte[] data, final byte[] pw, final Path savedTo) {
        final byte[] enc_data = ECDHIES.encrypt(data, pw);
        System.out.printf("Encrypted data (length %d):\n", enc_data.length);
        Glossary.displayBytes(enc_data);
        saveByteArray(savedTo, enc_data);
    }

    /**
     * decrypt a symmetric cryptogram
     *
     * @param enc_data the data that will be decrypted
     * @param pw       the passphrase that will be used
     * @param savedTo  save decrypted data to path
     */
    private static void decryptData(final byte[] enc_data, final byte[] pw, final Path savedTo) {
        final byte[] dec_data = ECDHIES.decrypt(enc_data, pw);
        System.out.printf("\nDecrypted data (length %d):\n", dec_data.length);
        Glossary.displayBytes(dec_data);
        System.out.printf("Decrypted message: %s\n", new String(dec_data));
        saveByteArray(savedTo, dec_data);
    }

    /**
     * Generate an elliptic key pair from a given passphrase and write the public key to a file.
     * As well as encrypting the private key from that pair under the given password and write it to a different file
     *
     * @param pw                the passphrase that will be used
     * @param publicKeySavedTo  save public key to path
     * @param privateKeySavedTo save private key to path
     */
    private static void getEllipticKeyPair(final byte[] pw, final Path publicKeySavedTo, final Path privateKeySavedTo) {
        // generate an elliptic key pair from a given passphrase
        final byte[][] key = EllipticCurves.getSchnorrKeyPair(pw);
        final byte[] publicKey = key[0];
        final byte[] privateKey = key[1];
        // print public key to console
        System.out.printf("\nPublic key (length %d):\n", publicKey.length);
        Glossary.displayBytes(publicKey);
        // write the public key to a file
        saveByteArray(publicKeySavedTo, publicKey);
        // print private key to console
        System.out.printf("\nPrivate key (length %d):\n", privateKey.length);
        Glossary.displayBytes(privateKey);
        // Encrypt the private key from that pair under the given password and write it to a different file
        encryptData(privateKey, pw, privateKeySavedTo);
    }

    /**
     * Encrypt a data under a given elliptic public key and write the ciphertext to a file
     *
     * @param data              the data that will be encrypted
     * @param publicKey         the public key that will be used
     * @param ciphertextSavedTo save the ciphertext to path
     */
    private static void encryptDataUsingPublicKey(final byte[] data, final byte[] publicKey, final Path ciphertextSavedTo) {
        final byte[] enc_data = EllipticCurves.encrypt(data, publicKey);
        System.out.printf("Encrypted data using given elliptic public key (length %d):\n", enc_data.length);
        Glossary.displayBytes(enc_data);
        saveByteArray(ciphertextSavedTo, enc_data);
    }

    /**
     * Decrypt a data under a given elliptic public key and write the ciphertext to a file
     *
     * @param data    the data that will be decrypted
     * @param pw      the password that will be used for decryption
     * @param savedTo save the decryption data to path
     */
    private static void decryptDataUsingPublicKey(final byte[] data, final byte[] pw, final Path savedTo) {
        final byte[] dec_data = EllipticCurves.decrypt(data, pw);
        System.out.printf("Decrypted data using given password (length %d):\n", dec_data.length);
        Glossary.displayBytes(dec_data);
        System.out.printf("Decrypted message: %s\n", new String(dec_data));
        saveByteArray(savedTo, dec_data);
    }

    /**
     * Sign a given data from a given password and write the signature to a file.
     *
     * @param data    text input that needs to be signed
     * @param pw      the password that will be used for
     * @param savedTo write the signature to path
     */
    private static void generateSignature(final byte[] data, final byte[] pw, final Path savedTo) {
        final byte[][] theSignatureKeyPair = EllipticCurves.getSignature(data, pw);
        final byte[] theSignature = Glossary.array_concatenation(theSignatureKeyPair[0], theSignatureKeyPair[1]);
        System.out.printf("Decrypted data using given password (length %d):\n", theSignature.length);
        Glossary.displayBytes(theSignature);
        saveByteArray(savedTo, theSignature);
    }


    /**
     * Verify a given data and its signature under a given public key file.
     *
     * @param data         text input that has been signed
     * @param theSignature the signature that needs to be checked
     * @param publicKey    the public key
     */
    private static void verifySignature(final byte[] data, final byte[] theSignature, final byte[] publicKey) {
        if (EllipticCurves.verifySignature(theSignature, data, publicKey)) {
            System.out.println("Valid Signature.");
        } else {
            System.out.println("Signature is not valid!!");
        }
    }
}
