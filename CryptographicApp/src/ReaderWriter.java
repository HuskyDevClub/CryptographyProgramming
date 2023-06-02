
import java.io.*;

public class ReaderWriter
{
    public static byte[] readFileBytes(String theFileName)
    {
        byte[] outBytes = null;

        try
        {
            FileInputStream keyIn = new FileInputStream(theFileName);
            outBytes = keyIn.readAllBytes();
        }
        catch (FileNotFoundException fne)
        {
            System.out.println("Unable to locate file: " + theFileName + ", is the URL correct?");
            System.exit(1);
        }
        catch (IOException e)
        {
            System.out.println("Error occurred while reading file: ." + theFileName);
            e.printStackTrace();
            System.exit(1);
        }

        return outBytes;
    }

    public static void writeBytesToFile(byte[] theOutput, String theFileName)
    {
        try
        {
            FileOutputStream out = new FileOutputStream(theFileName);
            out.write(theOutput);
        }
        catch (FileNotFoundException e)
        {
            System.out.println("Cannot access file.");
            System.exit(1);
        }
        catch (IOException e)
        {
            System.out.println("Could not write to output file.");
            e.printStackTrace();
            System.exit(1);
        }
    }
}
