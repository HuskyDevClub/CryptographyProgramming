import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;

public class ReaderWriter {
    public static byte[] readFileBytes(final String theFileName) {
        byte[] outBytes = null;

        try {
            final FileInputStream keyIn = new FileInputStream(theFileName);
            outBytes = keyIn.readAllBytes();
        } catch (final FileNotFoundException fne) {
            System.out.println("Unable to locate the file: " + theFileName);
            System.exit(1);
        } catch (final IOException e) {
            System.out.println("Error occurred while reading this file: " + theFileName);
            e.printStackTrace();
            System.exit(1);
        }

        return outBytes;
    }

    public static void writeBytesToFile(final byte[] theOutput, final String theFileName) {
        try {
            final FileOutputStream out = new FileOutputStream(theFileName);
            out.write(theOutput);
        } catch (final FileNotFoundException e) {
            System.out.println("Cannot access file.");
            System.exit(1);
        } catch (final IOException e) {
            System.out.println("Could not write to output file.");
            e.printStackTrace();
            System.exit(1);
        }
    }
}
