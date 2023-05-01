public class KMACX {

    static byte[] KMACXOF256(byte[] K, byte[] X, int L, byte[] S) {
        // Validity Conditions: len(K) < 2^2040 and 0 ≤ L and len(S) < 2^2040
        if ((L & 7) != 0) {
            throw new RuntimeException("Implementation restriction: " +
                    "output length (in bits) must be a multiple of 8");
        }
        byte[] val = new byte[L >>> 3];
        Shake shake = new Shake();
        shake.kinit256(K, S);
        shake.update(X, X.length);
        shake.xof();
        shake.out(val, L >>> 3);
        return val; // SHAKE256(X, L) or KECCAK512(prefix || X || 00, L)
    }
}