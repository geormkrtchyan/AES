package ru.macrobit.Parallel;

import ru.macrobit.Tables.AesTables;
import ru.macrobit.Tables.MCTables;

import java.io.*;

@SuppressWarnings("Duplicates")
public class AesThread implements Runnable {

    private final int count;
    private byte[] binary;
    private String process;
    private byte[] key;

    AesThread(int count, byte[] binary, String process, byte[] key) {
        this.count = count;
        this.binary = binary;
        this.process = process;
        this.key = key;
    }


    byte[] getBinary() {
        return binary;
    }

    @Override
    public void run() {
        if (process.equalsIgnoreCase("e")) {
            try {
                encryption();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else if (process.equalsIgnoreCase("d")) //Decryption Mode
        {
            try {
                decryption();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            System.err.println("Usage for Encryption: java AES e keyFile inputFile");
            System.err.println("Usage for Decryption: java AES d keyFile encrypted inputFile");
        }
    }

    private void decryption() throws IOException {
        if (binary != null) {
            process(binary, "dec");
        }
    }

    private void encryption() throws IOException {
        if (binary != null) {
            process(binary, "enc");
        }
    }

    private void process(byte[] binary, String v1) throws IOException {
        int numRounds = 10 + (((key.length * 8 - 128) / 32));
        int[][] keyMatrix = keySchedule(key);
        int[][] state;
        int pointer = 0;
        for (int i = 0; i < count; i++) {
            state = getBlockBytes(pointer, binary, 4);
            if (v1.equals("enc")) {
                encryptionBlock(numRounds, keyMatrix, state);
            } else {
                decryptionBlock(numRounds, keyMatrix, state);
            }
            byte[] stat = matrixToByte(state);
            int index = 0;
            for (int j = pointer; j < 16; j++) {
                this.binary[j] = stat[index];
                index++;
            }
            pointer += 16;
        }
    }

    private static byte[] matrixToByte(int[][] state) {
        byte[] bytes = new byte[16];
        int index = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                bytes[index] = (byte) state[i][j];
                index++;
            }
        }
        return bytes;
    }

    private static void decryptionBlock(int numRounds, int[][] keyMatrix, int[][] state) {
        addRoundKey(state, subKey(keyMatrix, numRounds));
        for (int i = numRounds - 1; i > 0; i--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, subKey(keyMatrix, i));
            invMixColumns(state);
        }
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, subKey(keyMatrix, 0));
    }

    private static void encryptionBlock(int numRounds, int[][] keyMatrix, int[][] state) {

        addRoundKey(state, subKey(keyMatrix, 0)); //Starts the addRoundKey with the first part of Key Expansion
        for (int i = 1; i < numRounds; i++) {
            subBytes(state); //implements the Sub-Bytes subroutine.
            shiftRows(state); //implements Shift-Rows subroutine.
            mixColumns(state);
            addRoundKey(state, subKey(keyMatrix, i));
        }
        subBytes(state); //implements the Sub-Bytes subroutine.
        shiftRows(state); //implements Shift-Rows subroutine.
        addRoundKey(state, subKey(keyMatrix, numRounds));
    }

    /**
     * Pulls out the subkey from the key formed from the keySchedule method
     *
     * @param km    key formed from AES.keySchedule()
     * @param begin index of where to fetch the subkey
     * @return The chunk of the scheduled key based on begin.
     */

    private static int[][] subKey(int[][] km, int begin) {
        int[][] arr = new int[4][4];
        for (int i = 0; i < arr.length; i++) {
            System.arraycopy(km[i], 4 * begin, arr[i], 0, arr.length);
        }
        return arr;
    }

    private static void subBytes(int[][] arr) {
        for (int i = 0; i < arr.length; i++) //Sub-Byte subroutine
        {
            for (int j = 0; j < arr[0].length; j++) {
                int hex = arr[j][i];
                arr[j][i] = AesTables.sbox[hex / 16][hex % 16];
            }
        }
    }

    /**
     * Inverse rendition of the subBytes. The operations of invSubBytes are the reverse operations of subBytes.
     *
     * @param arr the array that is passed.
     */

    private static void invSubBytes(int[][] arr) {
        for (int i = 0; i < arr.length; i++) //Inverse Sub-Byte subroutine
        {
            for (int j = 0; j < arr[0].length; j++) {
                int hex = arr[j][i];
                arr[j][i] = AesTables.invsbox[hex / 16][hex % 16];
            }
        }
    }

    /**
     * Performs a left shift on each row of the matrix.
     * Left shifts the nth row n-1 times.
     *
     * @param arr the reference of the array to perform the rotations.
     */

    private static void shiftRows(int[][] arr) {
        for (int i = 1; i < arr.length; i++) {
            arr[i] = leftRotate(arr[i], i);
        }
    }

    /**
     * Left rotates a given array. The size of the array is assumed to be 4.
     * If the number of times to rotate the array is divisible by 4, return the array
     * as it is.
     *
     * @param arr   The passed array (assumed to be of size 4)
     * @param times The number of times to rotate the array.
     * @return the rotated array.
     */

    private static int[] leftRotate(int[] arr, int times) {
        assert (arr.length == 4);
        if (times % 4 == 0) {
            return arr;
        }
        while (times > 0) {
            int temp = arr[0];
            System.arraycopy(arr, 1, arr, 0, arr.length - 1);
            arr[arr.length - 1] = temp;
            --times;
        }
        return arr;
    }

    /**
     * Inverse rendition of ShiftRows (this time, right rotations are used).
     *
     * @param arr the array to compute right rotations.
     */

    private static void invShiftRows(int[][] arr) {
        for (int i = 1; i < arr.length; i++) {
            arr[i] = rightRotate(arr[i], i);
        }
    }

    private static int[] rightRotate(int[] arr, int times) {
        if (arr.length == 0 || arr.length == 1 || times % 4 == 0) {
            return arr;
        }
        while (times > 0) {
            int temp = arr[arr.length - 1];
            System.arraycopy(arr, 0, arr, 1, arr.length - 1);
            arr[0] = temp;
            --times;
        }
        return arr;
    }

    /**
     * Performed by mapping each element in the current matrix with the value
     * returned by its helper function.
     *
     * @param arr the array with we calculate against the galois field matrix.
     */

    private static void mixColumns(int[][] arr) { //method for mixColumns
        int[][] tarr = new int[4][4];
        for (int i = 0; i < 4; i++) {
            System.arraycopy(arr[i], 0, tarr[i], 0, 4);
        }
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                arr[i][j] = mcHelper(tarr, AesTables.galois, i, j);
            }
        }
    }

    /**
     * Helper method of mixColumns in which compute the mixColumn formula on each element.
     *
     * @param arr passed in current matrix
     * @param g   the galois field
     * @param i   the row position
     * @param j   the column position
     * @return the computed mixColumns value
     */

    private static int mcHelper(int[][] arr, int[][] g, int i, int j) {
        int mcSum = 0;
        for (int k = 0; k < 4; k++) {
            int a = g[i][k];
            int b = arr[k][j];
            mcSum ^= mcCalc(a, b);
        }
        return mcSum;
    }

    private static int mcCalc(int a, int b) {//Helper method for mcHelper
        if (a == 1) {
            return b;
        } else if (a == 2) {
            return MCTables.mc2[b / 16][b % 16];
        } else if (a == 3) {
            return MCTables.mc3[b / 16][b % 16];
        }
        return 0;
    }

    private static void invMixColumns(int[][] arr) {
        int[][] tarr = new int[4][4];
        for (int i = 0; i < 4; i++) {
            System.arraycopy(arr[i], 0, tarr[i], 0, 4);
        }
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                arr[i][j] = invMcHelper(tarr, AesTables.invgalois, i, j);
            }
        }
    }

    private static int invMcHelper(int[][] arr, int[][] iGalois, int i, int j) {//Helper method for invMixColumns
        int mcSum = 0;
        for (int k = 0; k < 4; k++) {
            int a = iGalois[i][k];
            int b = arr[k][j];
            mcSum ^= invMcCalc(a, b);
        }
        return mcSum;
    }

    /**
     * Helper computing method for inverted mixColumns.
     *
     * @param a Row Position of mcX.
     * @param b Column Position of mcX
     * @return the value in the corresponding mcX table based on the a,b coordinates.
     */

    private static int invMcCalc(int a, int b) { //Helper method for invMcHelper
        if (a == 9) {
            return MCTables.mc9[b / 16][b % 16];
        } else if (a == 0xb) {
            return MCTables.mc11[b / 16][b % 16];
        } else if (a == 0xd) {
            return MCTables.mc13[b / 16][b % 16];
        } else if (a == 0xe) {
            return MCTables.mc14[b / 16][b % 16];
        }
        return 0;
    }

    /**
     * The keyScheduling algorithm to expand a short key into a number of separate round keys.
     *
     * @param key the key in which key expansion will be computed upon.
     * @return the fully computed expanded key for the AES encryption/decryption.
     */

    private static int[][] keySchedule(byte[] key) {
        int binKeySize = key.length * 8;
        int colSize = binKeySize + 48 - (32 * ((binKeySize / 64) - 2)); //size of key scheduling will be based on the binary size of the key.
        int[][] keyMatrix; //creates the matrix for key scheduling
        int rConpointer = 1;
        int[] t = new int[4];
        final int keyCounter = binKeySize / 32;
        int k;
        keyMatrix = getBlockBytes(0, key, colSize / 4);
        int keyPoint = keyCounter;
        while (keyPoint < (colSize / 4)) {
            int temp = keyPoint % keyCounter;
            if (temp == 0) {
                for (k = 0; k < 4; k++) {
                    t[k] = keyMatrix[k][keyPoint - 1];
                }
                t = scheduleCore(t, rConpointer++);
                for (k = 0; k < 4; k++) {
                    keyMatrix[k][keyPoint] = t[k] ^ keyMatrix[k][keyPoint - keyCounter];
                }
                keyPoint++;
            } else if (temp == 4) {
                for (k = 0; k < 4; k++) {
                    int hex = keyMatrix[k][keyPoint - 1];
                    keyMatrix[k][keyPoint] = AesTables.sbox[hex / 16][hex % 16] ^ keyMatrix[k][keyPoint - keyCounter];
                }
                keyPoint++;
            } else {
                int kTemp = keyPoint + 3;
                while (keyPoint < kTemp) {
                    for (k = 0; k < 4; k++) {
                        keyMatrix[k][keyPoint] = keyMatrix[k][keyPoint - 1] ^ keyMatrix[k][keyPoint - keyCounter];
                    }
                    keyPoint++;
                }
            }
        }
        return keyMatrix;
    }

    /**
     * For every (binary key size / 32)th column in the expanded key. We compute a special column
     * using sbox and an XOR of the an rcon number with the first element in the passed array.
     *
     * @param in          the array in which we compute the next set of bytes for key expansion
     * @param rConpointer the element in the rcon array with which to XOR the first element in 'in'
     * @return the next column in the key scheduling.
     */

    private static int[] scheduleCore(int[] in, int rConpointer) {
        in = leftRotate(in, 1);
        int hex;
        for (int i = 0; i < in.length; i++) {
            hex = in[i];
            in[i] = AesTables.sbox[hex / 16][hex % 16];
        }
        in[0] ^= AesTables.rcon[rConpointer];
        return in;
    }

    /**
     * In the AddRoundKey step, the subkey is combined with the state. For each round, a chunk of the key scheduled is pulled; each subkey is the same size as the state. Each element in the byte matrix is XOR'd with each element in the chunk of the expanded key.
     *
     * @param keyMatrix chunk of the expanded key
     */

    private static void addRoundKey(int[][] byteMatrix, int[][] keyMatrix) {
        for (int i = 0; i < byteMatrix.length; i++) {
            for (int j = 0; j < byteMatrix[0].length; j++) {
                byteMatrix[j][i] ^= keyMatrix[j][i];
            }
        }
    }

    private static int[][] getBlockBytes(int pointer, byte[] binary, int nColumn) {
        int[][] block = new int[4][nColumn];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                block[i][j] = binary[pointer] & 0xFF;
                pointer++;
            }
        }
        return block;
    }
}
