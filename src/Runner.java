public class Runner {

    public static void main(String[] args) {

        String message = "This is a message we will encrypt with AES!";
        //int[] key = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        int[] key = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

        AES_128 aes = new AES_128();
        aes.encrypt(key, message);
        aes.printEncryptedMessage();
    }
}
