package ru.macrobit.Sequential;

import ru.macrobit.Tables.AesTables;
import ru.macrobit.Tables.MCTables;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@SuppressWarnings("Duplicates")
public class SequentialAES {

    private static final String newline = System.getProperty("line.separator"); //The newline for whatever system you choose to run in.

    public enum Mode {ECB, CBC}

    private static byte[] key;
    private static byte[] iv;
    private static String fileName = "";
    private static byte[] binary;
    private static String fileExtension = "";
    private static Mode mode;
    private static int keyFileIndex = 1; //Index where the keyFile argument should be. Used to determines the index of other arguments.

    /**
     * args[0] should be either "e" or "d"
     * args[1] and args[2] should correspond to the following:
     * <p>
     * -length => "128" or "256"
     * -mode => "ecb" or "cbc"
     * neither -length nor -mode: args[1] should be the keyFile, and args[2] should be the inputFile
     * <p>
     * args[3] and args[4] should exist only if -length was specified:
     **/

    public static void main(String[] args) throws IOException {

        long start = System.nanoTime();

        getArgumentsFromCommandLine(args);
        if (args[0].equalsIgnoreCase("e")) {
            encryption();
        } else if (args[0].equalsIgnoreCase("d")) //Decryption Mode
        {
            decryption();
        } else {
            System.err.println("Usage for Encryption: java AES e keyFile inputFile");
            System.err.println("Usage for Decryption: java AES d keyFile encrypted inputFile");
        }

        long finish = System.nanoTime();
        long nanoSeconds = finish - start;
        double seconds = nanoSeconds / 1000000000.0;
        System.out.println(String.format("Done: %.3f", seconds));

    }

    private static void decryption() throws IOException {
        int[][] initVector = new int[4][4];
        if (mode == Mode.CBC) {
            initVector(initVector);
        }
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(fileName + "_dec." + fileExtension));
        if (binary != null) {
            process(bufferedOutputStream, binary, initVector, "dec");
        }
        bufferedOutputStream.close();
    }

    private static void encryption() throws IOException {
        int[][] initVector = new int[4][4];
        if (mode == Mode.CBC) {
            initVector(initVector);
        }
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(fileName + "_enc." + fileExtension));
        if (binary != null) {
            process(bufferedOutputStream, binary, initVector, "enc");
        }
        bufferedOutputStream.close();
    }

    private static void process(BufferedOutputStream bufferedOutputStream, byte[] binary, int[][] initVector, String v1) throws IOException {
        int numRounds = 10 + (((key.length * 8 - 128) / 32));
        int[][] nextVector = new int[4][4];
//        int[][] keyMatrix = keySchedule(key);
        int[][] keyMatrix = keySchedule(key);
        int[][] state = new int[4][4];
        int nBlock = binary.length / 16;
        int pointer = 0;
        for (int i = 0; i < nBlock; i++) {
            state = getBlockBytes(pointer, binary, 4);
            if (v1.equals("enc")) {
                if (mode == Mode.CBC) {
                    addRoundKey(state, initVector);
                }
                encryptionBlock(numRounds, keyMatrix, state);
                if (mode == Mode.CBC) {
                    initVector = state;
                }
            } else {
                if (mode == Mode.CBC) {
                    deepCopy2DArray(nextVector, state);
                }
                decryptionBlock(numRounds, keyMatrix, state);
                if (mode == Mode.CBC) {
                    addRoundKey(state, initVector);
                    deepCopy2DArray(initVector, nextVector);
                }
            }
            bufferedOutputStream.write(MatrixToByte(state), 0, 16);
            pointer += 16;
        }
        int left = binary.length - pointer;
        if (left != 0) {
            fillingMissingElements(binary, state, pointer, left);
            if (v1.equals("enc")) {
                encryptionBlock(numRounds, keyMatrix, state);
            } else {
                decryptionBlock(numRounds, keyMatrix, state);
            }
            bufferedOutputStream.write(MatrixToByte(state), 0, 16);
        }
    }

    private static void getArgumentsFromCommandLine(String[] args) {
        try {
            int keySizeCheck = 128; //User's intended key size.
            if (!args[1].equals("-length")) //No optional length argument given.
            {
                if (!args[1].equals("-mode")) //No optional mode given either;
                {
                    //Defaults to 128-bit key size and ECB.
                } else //Mode option was given;
                {
                    mode = args[2].equals("ecb") ? Mode.ECB : Mode.CBC;
                    keyFileIndex += 2;
                }
            } else //-length was explicitly given.
            {
                keyFileIndex += 2;
                keySizeCheck = Integer.parseInt(args[keyFileIndex - 1]);
                if (args[3].equals("-mode")) //Both -length and -mode options were given
                {
                    mode = args[4].equals("ecb") ? Mode.ECB : Mode.CBC;
                    keyFileIndex += 2;
                }
            }
            key = readSmallBinaryFile(args[keyFileIndex]);
            assert key != null;
            if (key.length * 8 != keySizeCheck) //Check to see if user's intended key size matches the size of key in file.
            {
                throw new Exception("Error: Attemping to use a " + key.length * 8 + "-bit key with AES-" + keySizeCheck);
            }
            if (mode == Mode.CBC) {
                iv = key;
//                iv = stringToByte(keyreader.readLine());
                if (iv.length != 32) {
                    throw new Exception("Error: Size of Initialization Vector must be 32 bytes.");
                }
            }

            fileName += args[keyFileIndex + 1];
            int beginIndex = fileName.lastIndexOf(".");
            fileExtension = fileName.substring(beginIndex + 1, fileName.length());
            fileName = fileName.substring(0, beginIndex);

            if (args[0].equalsIgnoreCase("e")) {
                binary = readSmallBinaryFile(fileName + "." + fileExtension);
            } else if (args[0].equalsIgnoreCase("d")) //Decryption Mode
            {
                binary = readSmallBinaryFile(fileName + "_enc." + fileExtension);
            }
        } catch (Exception e) {
            System.err.println(e.getMessage() + newline);
            System.exit(1);
        }
    }

    private static void initVector(int[][] initVector) {
        int index = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                initVector[j][i] = iv[index];
                index++;
            }
        }
    }

    private static byte[] MatrixToByte(int[][] state) {
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

    private static void decryptionBlock(int numRounds, int[][] keymatrix, int[][] state) {
        addRoundKey(state, subKey(keymatrix, numRounds));
        for (int i = numRounds - 1; i > 0; i--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, subKey(keymatrix, i));
            invMixColumns(state);
        }
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, subKey(keymatrix, 0));
    }

    private static void encryptionBlock(int numRounds, int[][] keymatrix, int[][] state) {

        addRoundKey(state, subKey(keymatrix, 0)); //Starts the addRoundKey with the first part of Key Expansion
        for (int i = 1; i < numRounds; i++) {
            subBytes(state); //implements the Sub-Bytes subroutine.
            shiftRows(state); //implements Shift-Rows subroutine.
            mixColumns(state);
            addRoundKey(state, subKey(keymatrix, i));
        }
        subBytes(state); //implements the Sub-Bytes subroutine.
        shiftRows(state); //implements Shift-Rows subroutine.
        addRoundKey(state, subKey(keymatrix, numRounds));
    }

    private static void deepCopy2DArray(int[][] destination, int[][] source) {
        assert destination.length == source.length && destination[0].length == source[0].length;
        for (int i = 0; i < destination.length; i++) {
            System.arraycopy(source[i], 0, destination[i], 0, destination[0].length);
        }
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

    private static int invMcHelper(int[][] arr, int[][] igalois, int i, int j) {//Helper method for invMixColumns
        int mcSum = 0;
        for (int k = 0; k < 4; k++) {
            int a = igalois[i][k];
            int b = arr[k][j];
            mcSum ^= invMcCalc(a, b);
        }
        return mcSum;
    }


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
                t = schedule_core(t, rConpointer++);
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

    private static int[] schedule_core(int[] in, int rConpointer) {
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

    private static byte[] readSmallBinaryFile(String aFileName) throws IOException {
        try {
            Path path = Paths.get(aFileName);
            return Files.readAllBytes(path);
        } catch (FileNotFoundException e) {
            System.err.println("There is no file");
        }
        return null;
    }

    private static void fillingMissingElements(byte[] binary, int[][] state, int pointer, int left) {
        final int spaceCode = 32;
        int index = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                if (index >= left) {
                    state[i][j] = spaceCode;
                } else {
                    state[i][j] = binary[pointer] & 0xFF;
                }
                pointer++;
                index++;
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