import java.math.BigInteger;
import java.util.Arrays;

/**
 * This class defines a point on the Elliptic Curve.
 *
 * @author Brian LeSmith
 * @author Yudong Lin
 */
final class EllipticCurvePoint {
    private static final BigInteger PRIME = BigInteger.valueOf(2L).pow(448)
            .subtract(BigInteger.valueOf(2L).pow(224)).subtract(BigInteger.ONE);
    static final int STANDARD_BYTE_LENGTH = PRIME.toByteArray().length * 2;
    private static final BigInteger DEFINE_E = BigInteger.valueOf(-39081);
    private final BigInteger myX;
    private final BigInteger myY;

    /**
     * Initializes a point for the neutral element.
     */
    EllipticCurvePoint() {
        this.myX = BigInteger.ZERO;
        this.myY = BigInteger.ONE;
    }

    /**
     * Initializes a point on the curve using given x and y coordinate.
     *
     * @param theX Parameter for the x coordinate.
     * @param theY Parameter for the y coordinate.
     */
    EllipticCurvePoint(final BigInteger theX, final BigInteger theY) {
        if (!isValid(theX, theY)) {
            throw new IllegalArgumentException("The provided X, and Y pair is not a point on Ed448");
        }

        this.myX = theX;
        this.myY = theY;
    }

    /**
     * Initializes a point on the curve with the given x coordinate.
     * y coordinate is found based on the current theX with the formula
     * y = sqrt( (1 - theX^2) / ( 1 - d * theX^2) ) mod p
     *
     * @param theX                   Parameter for the x coordinate.
     * @param theLeastSignificantBit Parameter for the desired least significant bit of the y coordinate.
     */
    EllipticCurvePoint(final BigInteger theX, final boolean theLeastSignificantBit) {
        final BigInteger a = BigInteger.ONE.subtract(theX.pow(2)); // 1 - theX^2
        final BigInteger b = BigInteger.ONE.subtract(DEFINE_E.multiply(theX.pow(2))); // 1 - d * theX^2
        final BigInteger y = sqrt(a.multiply(b.modInverse(PRIME)), theLeastSignificantBit); // sqrt( (1 - theX^2) / (1 - dx^2)) mod p

        if (y == null) {
            throw new IllegalArgumentException("No square root of the provided theX exists");
        }

        this.myX = theX;
        this.myY = y.mod(PRIME);
    }

    /**
     * Generates a CurvePoint from the provided byte array.
     *
     * @param theDesiredCurvePoint Parameter for the byte array representing the desired CurvePoint.
     * @return Returns a CurvePoint parsed from the byte array.
     */
    static EllipticCurvePoint fromByteArray(final byte[] theDesiredCurvePoint) {
        if (theDesiredCurvePoint.length != STANDARD_BYTE_LENGTH) {
            throw new IllegalArgumentException("The provided byte array is not formatted properly.");
        }

        final BigInteger x = new BigInteger(Arrays.copyOfRange(theDesiredCurvePoint, 0, STANDARD_BYTE_LENGTH / 2));
        final BigInteger y = new BigInteger(Arrays.copyOfRange(theDesiredCurvePoint, STANDARD_BYTE_LENGTH / 2, STANDARD_BYTE_LENGTH));

        return new EllipticCurvePoint(x, y);
    }

    /**
     * Compute a square root of v mod p with specified the least significant bit, if such a root exists.
     *
     * @param v   the radicand.
     * @param lsb desired least significant bit (true: 1, false: 0).
     * @return a square root r of v mod p with r mod 2 = 1 iff lsb = true
     * if such a root exists, otherwise null.
     */
    private static BigInteger sqrt(final BigInteger v, final boolean lsb) {
        assert (PRIME.testBit(0) && PRIME.testBit(1)); // p = 3 (mod 4)
        if (v.signum() == 0) {
            return BigInteger.ZERO;
        }
        BigInteger r = v.modPow(PRIME.shiftRight(2).add(BigInteger.ONE), PRIME);
        if (r.testBit(0) != lsb) {
            r = PRIME.subtract(r); // correct the lsb
        }
        return (r.multiply(r).subtract(v).mod(PRIME).signum() == 0) ? r : null;
    }

    /**
     * Multiplies a given point by a scalar and returns that result.
     *
     * @param s Parameter for the scalar to multiply by.
     * @return Returns the given point multiplied by the parameter scalar.
     */
    EllipticCurvePoint scalarMultiply(final BigInteger s) {
        EllipticCurvePoint V = new EllipticCurvePoint();
        final int k = s.bitLength();
        for (int i = k - 1; i >= 0; i--) { // scan over the k bits of s
            V = V.add(V); // invoke the Edwards point addition formula
            if (s.testBit(i)) { // test the i-th bit of s
                V = V.add(this); // invoke the Edwards point addition formula
            }
        }
        return V; // now finally V = s*P
    }

    /**
     * Adds this to theAddedPoint and returns the result. The addition is based on this formula:
     * x = ((x_1 * y_2 + y_2 * x_2) / (1 + d * x_1 * x_2 * y_1 * y_2)) mod p
     * y = ((y_1 * y_2 - x_1 * x_2) / (1 - d * x_1 * x_2 * y_1 * y_2)) mod p
     *
     * @param theAddedPoint Parameter for the point to add.
     * @return Returns this + theAddedPoint (based upon the formula described above)
     */
    EllipticCurvePoint add(final EllipticCurvePoint theAddedPoint) {
        final BigInteger xy = myX.multiply(theAddedPoint.myX).multiply(myY.multiply(theAddedPoint.myY));

        BigInteger a = myX.multiply(theAddedPoint.myY).add(myY.multiply(theAddedPoint.myX));
        BigInteger b = BigInteger.ONE.add(DEFINE_E.multiply(xy));
        final BigInteger c = a.multiply(b.modInverse(PRIME)).mod(PRIME);

        a = myY.multiply(theAddedPoint.myY).subtract(myX.multiply(theAddedPoint.myX));
        b = BigInteger.ONE.subtract(DEFINE_E.multiply(xy));
        final BigInteger d = a.multiply(b.modInverse(PRIME)).mod(PRIME);

        return new EllipticCurvePoint(c, d);
    }

    /**
     * Converts this CurvePoint to a byte array of a standard fixed size.
     *
     * @return Returns an unambiguous byte array representation of this curve point.
     */
    byte[] toByteArray() {
        final byte[] asBytes = new byte[STANDARD_BYTE_LENGTH];
        final byte[] xBytes = myX.toByteArray();
        final byte[] yBytes = myY.toByteArray();
        final int xPosition = STANDARD_BYTE_LENGTH / 2 - xBytes.length;
        final int yPosition = asBytes.length - yBytes.length;

        if (myX.signum() < 0) {
            Arrays.fill(asBytes, 0, xPosition, (byte) 0xff);
        }

        if (myY.signum() < 0) {
            Arrays.fill(asBytes, STANDARD_BYTE_LENGTH / 2, yPosition, (byte) 0xff);
        }

        System.arraycopy(xBytes, 0, asBytes, xPosition, xBytes.length);
        System.arraycopy(yBytes, 0, asBytes, yPosition, yBytes.length);

        return asBytes;
    }

    /**
     * Getter for the myX variable.
     *
     * @return Returns the myX variable.
     */
    BigInteger getX() {
        return this.myX;
    }

    /**
     * Getter for the myY variable.
     *
     * @return Returns the myY variable.
     */
    BigInteger getY() {
        return this.myY;
    }

    /**
     * Tests two EllipticCurvePoints by comparing x and y values.
     *
     * @param theOther Parameter for the other point to compare to.
     * @return Returns true if this equals theOther, false otherwise.
     */
    @Override
    public boolean equals(final Object theOther) {
        if (theOther == null || getClass() != theOther.getClass()) {
            return false;
        }
        final EllipticCurvePoint o = (EllipticCurvePoint) theOther;
        return myX.equals(o.getX()) && myY.equals(o.getY());
    }

    /**
     * Determines whether the provided X and Y coordinate pair are a point
     * on the curve using the formula:
     * theX^2 + theY^2 = 1 + d * (theX^2) * theY^2 where d = -39081
     *
     * @param theX Parameter for the X coordinate.
     * @param theY Parameter for the Y coordinate.
     * @return Returns a boolean flag for if the pair is on ED448.
     */
    private boolean isValid(final BigInteger theX, final BigInteger theY) {
        if (theX.equals(BigInteger.ZERO) && theY.equals(BigInteger.ONE)) {
            return true;
        }
        final BigInteger left = theX.pow(2).add(theY.pow(2)).mod(PRIME);
        final BigInteger right = BigInteger.ONE.add(DEFINE_E.multiply(theX.pow(2).multiply(theY.pow(2)))).mod(PRIME);
        return left.equals(right);
    }
}
