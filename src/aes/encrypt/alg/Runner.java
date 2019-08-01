package aes.encrypt.alg;

public class Runner {

    public static void main(String[] args) {

        String message = "Secret data to encrypt!";

        // Hex encryption key: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F
        int[] key = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}; // decimal representation of hex encryption key

        AES_128 aes = new AES_128();
        aes.encrypt(key, message);
        aes.printEncryptedMessage();
    }
}
