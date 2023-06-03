
import java.math.BigInteger;
import java.util.Arrays;

/**
 * This class defines a point on the Elliptic Curve.
 */
public class EllipticCurvePoint
{
    private static final String R_COMPUTE = "337554763258501705789107630418782636071904961214051226618635150085779108655765";
    private static final BigInteger MARSENNE_PRIME = BigInteger.valueOf(2L).pow(521).subtract(BigInteger.ONE);
    public static final int STANDARD_BYTE_LENGTH = MARSENNE_PRIME.toByteArray().length * 2;
    public static final EllipticCurvePoint ZERO = new EllipticCurvePoint(BigInteger.ZERO, BigInteger.ONE);
    public static final BigInteger SCHNORR_COMPUTE = BigInteger.valueOf(2L).pow(519).subtract(new BigInteger(R_COMPUTE));
    private static final BigInteger DEFINE_E_521 = BigInteger.valueOf(-376014);

    private final BigInteger myX;
    private final BigInteger myY;

    /**
     * Initializes a point on the curve using parameter given x and y coordinate.
     * @param theX Parameter for the x coordinate.
     * @param theY Parameter for the y coordinate.
     */
    public EllipticCurvePoint(final BigInteger theX, final BigInteger theY)
    {
        if (!isValidPair(theX, theY))
        {
            throw new IllegalArgumentException("The provided X, and Y pair is not a point on E_521");
        }

        this.myX = theX;
        this.myY = theY;
    }

    /**
     * Initializes a point on the curve with the given x coordinate.
     * y coordinate is found based on the current theX with the formula
     * y = sqrt( (1 - theX^2) / ( 1 - d * theX^2) ) mod p
     * @param theX Parameter for the x coordinate.
     * @param theLeastSignificantBit Parameter for the desired least significant bit of the y coordinate.
     */
    public EllipticCurvePoint(final BigInteger theX, final boolean theLeastSignificantBit)
    {
        BigInteger a = BigInteger.ONE.subtract(theX.pow(2)); // 1 - theX^2
        BigInteger b = BigInteger.ONE.subtract(DEFINE_E_521.multiply(theX.pow(2))); // 1 - d * theX^2
        BigInteger sqrt = sqrt(a.multiply(b.modInverse(MARSENNE_PRIME)), theLeastSignificantBit); // sqrt( (1 - theX^2) / (1 - dx^2)) mod p

        if (sqrt == null)
        {
            throw new IllegalArgumentException("No square root of the provided theX exists");
        }

        this.myX = theX;
        this.myY = sqrt.mod(MARSENNE_PRIME);
    }

    /**
     * Negates a provided EllipticCurvePoint.
     * @param theNegatePoint Parameter for the point to be negated.
     * @return Returns a new curve point using the formula (-theNegatePoint.x % p, theNegatePoint.y)
     */
    public static EllipticCurvePoint negate(final EllipticCurvePoint theNegatePoint)
    {
        return new EllipticCurvePoint(theNegatePoint.myX.negate().mod(MARSENNE_PRIME), theNegatePoint.myY);
    }

    /**
     * Multiplies a given point by a scalar and returns that result.
     * @param theScalar Parameter for the scalar to multiply by.
     * @return Returns the given point multiplied by the parameter scalar.
     */
    public EllipticCurvePoint scalarMultiply(final BigInteger theScalar)
    {
        EllipticCurvePoint output = ZERO;
        int counter = theScalar.bitLength();

        while (counter >= 0)
        {
            output = output.add(output);
            if (theScalar.testBit(counter--)) output = output.add(this);
        }

        return output;
    }

    /**
     * Adds this to theAddedPoint and returns the result. The addition is based on this formula:
     * x = ((x_1 * y_2 + y_2 * x_2) / (1 + d * x_1 * x_2 * y_1 * y_2)) mod p
     * y = ((y_1 * y_2 - x_1 * x_2) / (1 - d * x_1 * x_2 * y_1 * y_2)) mod p
     * @param theAddedPoint Parameter for the point to add.
     * @return Returns this + theAddedPoint (based upon the formula described above)
     */
    public EllipticCurvePoint add(final EllipticCurvePoint theAddedPoint)
    {
        BigInteger xy  = myX.multiply(theAddedPoint.myX).multiply(myY.multiply(theAddedPoint.myY)).mod(MARSENNE_PRIME);

        BigInteger a = myX.multiply(theAddedPoint.myY).add(myY.multiply(theAddedPoint.myX)).mod(MARSENNE_PRIME);
        BigInteger b = BigInteger.ONE.add(DEFINE_E_521.multiply(xy)).mod(MARSENNE_PRIME);
        BigInteger c = a.multiply(b.modInverse(MARSENNE_PRIME)).mod(MARSENNE_PRIME);

        a = myY.multiply(theAddedPoint.myY).subtract(myX.multiply(theAddedPoint.myX)).mod(MARSENNE_PRIME);
        b = BigInteger.ONE.subtract(DEFINE_E_521.multiply(xy)).mod(MARSENNE_PRIME);
        BigInteger d = a.multiply(b.modInverse(MARSENNE_PRIME)).mod(MARSENNE_PRIME);

        return new EllipticCurvePoint(c, d);
    }

    /**
     * Converts this CurvePoint to a byte array of a standard fixed size.
     * @return Returns an unambiguous byte array representation of this curve point.
     */
    public byte[] toByteArray()
    {
        byte[] asBytes = new byte[STANDARD_BYTE_LENGTH];
        byte[] xBytes = myX.toByteArray(), yBytes = myY.toByteArray();
        int xPosition = STANDARD_BYTE_LENGTH / 2 - xBytes.length, yPosition = asBytes.length - yBytes.length;

        if (myX.signum() < 0)
        {
            Arrays.fill(asBytes, 0, xPosition, (byte) 0xff);
        }

        if (myY.signum() < 0)
        {
            Arrays.fill(asBytes, STANDARD_BYTE_LENGTH / 2, yPosition, (byte) 0xff);
        }

        System.arraycopy(xBytes, 0, asBytes, xPosition, xBytes.length);
        System.arraycopy(yBytes, 0, asBytes, yPosition, yBytes.length);

        return asBytes;
    }

    /**
     * Generates a CurvePoint from the provided byte array.
     * @param theDesiredCurvePoint Parameter for the byte array representing the desired CurvePoint.
     * @return Returns a CurvePoint parsed from the byte array.
     */
    public static EllipticCurvePoint fromByteArray(final byte[] theDesiredCurvePoint)
    {
        if (theDesiredCurvePoint.length != STANDARD_BYTE_LENGTH)
        {
            throw new IllegalArgumentException("The provided byte array is not formatted properly.");
        }

        BigInteger x = new BigInteger(Arrays.copyOfRange(theDesiredCurvePoint, 0, STANDARD_BYTE_LENGTH / 2));
        BigInteger y = new BigInteger(Arrays.copyOfRange(theDesiredCurvePoint, STANDARD_BYTE_LENGTH / 2, STANDARD_BYTE_LENGTH));

        return new EllipticCurvePoint(x, y);
    }

    /**
     * Getter for the myX variable.
     * @return Returns the myX variable.
     */
    public BigInteger getX()
    {
        return this.myX;
    }

    /**
     * Getter for the myY variable.
     * @return Returns the myY variable.
     */
    public BigInteger getY()
    {
        return this.myY;
    }

    /**
     * Tests two EllipticCurvePoints by comparing x and y values.
     * @param theOther Parameter for the other point to compare to.
     * @return Returns true if this equals theOther, false otherwise.
     */
    @Override
    public boolean equals(final Object theOther)
    {
        if (this == theOther)
        {
            return true;
        }

        if (theOther == null || getClass() != theOther.getClass())
        {
            return false;
        }

        EllipticCurvePoint temp = (EllipticCurvePoint) theOther;

        return myX.equals(temp.myX) && myY.equals(temp.myY);
    }

    /**
     * Computes the square root of the radicand mod p using a least significant
     * bit, if such a root exists. Provided in the lecture notes of Paulo Barreto.
     * @param theRadicand Parameter for the radicand.
     * @param theLeastSignificantBit Parameter for the least significant bit.
     * @return Returns square root of the radicand mod p.
     */
    private BigInteger sqrt(final BigInteger theRadicand, final boolean theLeastSignificantBit)
    {
        assert (MARSENNE_PRIME.testBit(0) && MARSENNE_PRIME.testBit(1));

        if (theRadicand.signum() == 0)
        {
            return BigInteger.ZERO;
        }

        BigInteger squareRoot = theRadicand.modPow(MARSENNE_PRIME.shiftRight(2).add(BigInteger.ONE), MARSENNE_PRIME);

        if (squareRoot.testBit(0) != theLeastSignificantBit)
        {
            squareRoot = MARSENNE_PRIME.subtract(squareRoot);
        }

        return (squareRoot.multiply(squareRoot).subtract(theRadicand).mod(MARSENNE_PRIME).signum() == 0) ? squareRoot : null;
    }

    /**
     * Determines whether the provided X and Y coordinate pair are a point
     * on the curve using the formula:
     * theX^2 + theY^2 = 1 + d * (theX^2) * theY^2 where d = -376014
     * @param theX Parameter for the X coordinate.
     * @param theY Parameter for the Y coordinate.
     * @return Returns a boolean flag for if the pair is on E_521.
     */
    private boolean isValidPair(final BigInteger theX, final BigInteger theY)
    {
        BigInteger left, right;

        if (theX.equals(BigInteger.ZERO) && theY.equals(BigInteger.ONE))
        {
            right = BigInteger.ONE;
            left = BigInteger.ONE;
        }
        else
        {
            left = theX.pow(2).add(theY.pow(2)).mod(MARSENNE_PRIME);
            right = BigInteger.ONE.add(DEFINE_E_521.multiply(theX.pow(2).multiply(theY.pow(2)))).mod(MARSENNE_PRIME);
        }

        return left.equals(right);
    }
}
