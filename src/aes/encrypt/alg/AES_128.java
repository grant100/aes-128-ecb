package aes.encrypt.alg;

import java.util.Arrays;

// TODO Implement decryption algorithm
public class AES_128 {

    private char[] paddedMessage;
    private String encryptedHexValues = "";

    private int lengthOfPaddedMessage;

    /**
     * Perform key expansion, message padding and encryption
     *
     * @param key
     * @param message
     */
    public void encrypt(int[] key, String message) {

        // set padding if necessary
        standardizeMessage(message);

        // expand the keys
        int expandedKey[] = new int[176];
        keyExpansion(key, expandedKey);

        // encrypt
        int cnt = 0;
        for (int i = 0; i < getLengthOfPaddedMessage(); i += AES_DATA.BLOCK_SIZE) {
            int[] state = doAlgorithm(Arrays.copyOfRange(getPaddedMessage(), AES_DATA.BLOCK_SIZE * cnt, (AES_DATA.BLOCK_SIZE * cnt) + AES_DATA.BLOCK_SIZE), expandedKey);
            cnt++;

            for (int k = 0; k < state.length; k++) {
                this.encryptedHexValues += Integer.toHexString(state[k]) + " ";
            }
            this.encryptedHexValues += "\n";
        }


    }

    /**
     * Perform encryption algorithm
     *
     * @param message
     * @param key
     * @return array of 16 encrypted bytes
     */
    private int[] doAlgorithm(char[] message, int[] key) {
        int[] state = copyBlock(message);
        int numberOfRounds = 9;

        addRoundKey(state, key); // whitening
        for (int i = 0; i < numberOfRounds; i++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, Arrays.copyOfRange(key, (AES_DATA.BLOCK_SIZE * (i + 1)), key.length));
        }
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, Arrays.copyOfRange(key, 160, key.length));
        return state;
    }

    /**
     * Polynomial addition with galois fields are simply XORs
     *
     * @param state
     * @param roundKey
     */
    // galois field polynomial addition in base 2 follows XOR truth table
    private void addRoundKey(int[] state, int[] roundKey) {
        for (int i = 0; i < AES_DATA.BLOCK_SIZE; i++) {
            state[i] ^= roundKey[i];
        }
    }

    /**
     * Lookup SBOX values and store in state
     *
     * @param state
     */
    private void subBytes(int[] state) {
        for (int i = 0; i < AES_DATA.BLOCK_SIZE; i++) {
            state[i] = AES_DATA.SBOX[state[i]];
        }
    }

    /**
     * Shift state data:
     * <p>
     * Row 1: No rotation
     * Row 2: Rotate left by 1
     * Row 3: Rotate left by 2
     * Row 4: rotate left by 3
     * <p>
     * 00 04 08 12  --> 00 04 08 12
     * 01 05 09 13  --> 05 09 13 01
     * 02 06 10 14  --> 10 14 02 06
     * 03 07 11 15  --> 15 03 07 11
     *
     * @param state
     */
    private void shiftRows(int[] state) {
        int tmp[] = new int[AES_DATA.BLOCK_SIZE];

        tmp[0] = state[0];
        tmp[1] = state[5];
        tmp[2] = state[10];
        tmp[3] = state[15];

        tmp[4] = state[4];
        tmp[5] = state[9];
        tmp[6] = state[14];
        tmp[7] = state[3];

        tmp[8] = state[8];
        tmp[9] = state[13];
        tmp[10] = state[2];
        tmp[11] = state[7];

        tmp[12] = state[12];
        tmp[13] = state[1];
        tmp[14] = state[6];
        tmp[15] = state[11];

        for (int i = 0; i < AES_DATA.BLOCK_SIZE; i++) {
            state[i] = tmp[i];
        }
    }

    /**
     * MixColumns step
     *
     * @param state
     */
    private void mixColumns(int[] state) {
        int tmp[] = new int[AES_DATA.BLOCK_SIZE];

        tmp[0] = (AES_DATA.MUL2[state[0]] ^ AES_DATA.MUL3[state[1]] ^ state[2] ^ state[3]);
        tmp[1] = (state[0] ^ AES_DATA.MUL2[state[1]] ^ AES_DATA.MUL3[state[2]] ^ state[3]);
        tmp[2] = (state[0] ^ state[1] ^ AES_DATA.MUL2[state[2]] ^ AES_DATA.MUL3[state[3]]);
        tmp[3] = (AES_DATA.MUL3[state[0]] ^ state[1] ^ state[2] ^ AES_DATA.MUL2[state[3]]);

        tmp[4] = (AES_DATA.MUL2[state[4]] ^ AES_DATA.MUL3[state[5]] ^ state[6] ^ state[7]);
        tmp[5] = (state[4] ^ AES_DATA.MUL2[state[5]] ^ AES_DATA.MUL3[state[6]] ^ state[7]);
        tmp[6] = (state[4] ^ state[5] ^ AES_DATA.MUL2[state[6]] ^ AES_DATA.MUL3[state[7]]);
        tmp[7] = (AES_DATA.MUL3[state[4]] ^ state[5] ^ state[6] ^ AES_DATA.MUL2[state[7]]);

        tmp[8] = (AES_DATA.MUL2[state[8]] ^ AES_DATA.MUL3[state[9]] ^ state[10] ^ state[11]);
        tmp[9] = (state[8] ^ AES_DATA.MUL2[state[9]] ^ AES_DATA.MUL3[state[10]] ^ state[11]);
        tmp[10] = (state[8] ^ state[9] ^ AES_DATA.MUL2[state[10]] ^ AES_DATA.MUL3[state[11]]);
        tmp[11] = (AES_DATA.MUL3[state[8]] ^ state[9] ^ state[10] ^ AES_DATA.MUL2[state[11]]);

        tmp[12] = (AES_DATA.MUL2[state[12]] ^ AES_DATA.MUL3[state[13]] ^ state[14] ^ state[15]);
        tmp[13] = (state[12] ^ AES_DATA.MUL2[state[13]] ^ AES_DATA.MUL3[state[14]] ^ state[15]);
        tmp[14] = (state[12] ^ state[13] ^ AES_DATA.MUL2[state[14]] ^ AES_DATA.MUL3[state[15]]);
        tmp[15] = (AES_DATA.MUL3[state[12]] ^ state[13] ^ state[14] ^ AES_DATA.MUL2[state[15]]);

        for (int i = 0; i < AES_DATA.BLOCK_SIZE; i++) {
            state[i] = tmp[i];
        }
    }

    public void printEncryptedMessage() {
        System.out.println("*** Encrypted Message ***");
        System.out.println(this.encryptedHexValues);
    }

    /**
     * Copy characters from message char[] into state[] variable for processing
     *
     * @param message
     * @return Array representing 16 bytes of data to encrypt
     */
    private int[] copyBlock(char[] message) {
        int[] state = new int[AES_DATA.BLOCK_SIZE];
        for (int i = 0; i < AES_DATA.BLOCK_SIZE; i++) {
            state[i] = toHex(message[i]);
        }
        return state;
    }

    /**
     * Expands encryption key from 16 bytes to 176 for 11 rounds
     *
     * @param inputKey
     * @param expandedKeys
     */
    private void keyExpansion(int[] inputKey, int[] expandedKeys) {
        for (int i = 0; i < AES_DATA.BLOCK_SIZE; i++) {
            expandedKeys[i] = inputKey[i];
        }

        int bytesGenerated = AES_DATA.BLOCK_SIZE; // first 16 bytes come from original key
        int rconIteration = 1;
        int[] temp = new int[4];

        while (bytesGenerated < 176) {

            for (int i = 0; i < 4; i++) {
                // find last four bytes
                temp[i] = expandedKeys[i + bytesGenerated - 4];
            }

            // perform expansion core once for each 16 byte key
            if (bytesGenerated % AES_DATA.BLOCK_SIZE == 0) {
                keyExpansionCore(temp, rconIteration++);
            }

            for (int i = 0; i < 4; i++) {
                expandedKeys[bytesGenerated] = expandedKeys[bytesGenerated - AES_DATA.BLOCK_SIZE] ^ temp[i];
                bytesGenerated++;
            }
        }
    }

    /**
     * Rotate 4 bytes then lookup SBOX values and perform XOR on RCON lookup
     *
     * @param in
     * @param i
     */
    private void keyExpansionCore(int[] in, int i) {

        // rotate left
        int tmp = in[0];

        in[0] = in[1];
        in[1] = in[2];
        in[2] = in[3];
        in[3] = tmp;

        // sbox swap
        in[0] = AES_DATA.SBOX[in[0]];
        in[1] = AES_DATA.SBOX[in[1]];
        in[2] = AES_DATA.SBOX[in[2]];
        in[3] = AES_DATA.SBOX[in[3]];

        //RCON
        in[0] ^= AES_DATA.RCON[i];

    }

    // TODO hack!
    /**
     * Convert char (ascii) to hex string and parse to integer
     *
     * @param ch
     * @return integer representing decimal conversion of hex value
     */
    private int toHex(char ch) {
        String sHex = String.format("%040x", (int) ch); // flip ascii to hex string
        return Integer.parseInt(sHex, 16);        // parse hex string to integer
    }

    /**
     * Check message length and add padding to message
     *
     * @param message
     */
    private void standardizeMessage(String message) {
        int mlength = message.length();
        this.lengthOfPaddedMessage = mlength;

        if (this.lengthOfPaddedMessage % AES_DATA.BLOCK_SIZE != 0) {
            this.lengthOfPaddedMessage = (this.lengthOfPaddedMessage / AES_DATA.BLOCK_SIZE + 1) * AES_DATA.BLOCK_SIZE;
        }

        char[] charMessage = message.toCharArray();
        this.paddedMessage = new char[this.lengthOfPaddedMessage];
        for (int i = 0; i < this.lengthOfPaddedMessage; i++) {
            if (i >= mlength) {
                this.paddedMessage[i] = 0;
            } else {
                this.paddedMessage[i] = charMessage[i];
            }
        }
    }


    private int getLengthOfPaddedMessage() {
        return lengthOfPaddedMessage;
    }

    private char[] getPaddedMessage() {
        return paddedMessage;
    }
}
