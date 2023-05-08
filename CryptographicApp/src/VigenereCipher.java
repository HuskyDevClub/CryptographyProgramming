final class VigenereCipher {
    private static final String KEYS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public static void main(final String[] args) {
        final char[] message1 = "LOTSAMONEY".toCharArray();
        final char[] cipherText1 = "EWWWLUOAOM".toCharArray();
        final int[] theKey = getKey(message1, cipherText1);
        assert String.valueOf(decrypt(encrypt(message1, theKey), theKey)).equals(String.valueOf(message1));

        final char[] cipherText2 = "GWPSCMCNCV".toCharArray();

        assert String.valueOf(decrypt(cipherText2, theKey)).equals("NOMORECASH");
    }

    private static int[] getKey(final char[] message, final char[] cipherText) {
        final int[] _key = new int[message.length];
        for (int i = 0; i < message.length; i++) {
            final int k_i = KEYS.indexOf(cipherText[i]) - KEYS.indexOf(message[i]);
            _key[i] = k_i >= 0 ? k_i : KEYS.length() + k_i;
        }
        return _key;
    }

    private static char[] encrypt(final char[] message, final int[] key) {
        final char[] cipherText = new char[message.length];
        for (int i = 0; i < message.length; i++) {
            cipherText[i] = KEYS.charAt((KEYS.indexOf(message[i]) + key[i]) % 26);
        }
        return cipherText;
    }

    private static char[] decrypt(final char[] cipherText, final int[] key) {
        final char[] message = new char[cipherText.length];
        for (int i = 0; i < cipherText.length; i++) {
            message[i] = KEYS.charAt((KEYS.indexOf(cipherText[i]) - key[i] + 26) % 26);
        }
        return message;
    }
}
