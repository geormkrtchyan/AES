package ru.macrobit.Parallel;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class ParallelAES {

    private static final String newline = System.getProperty("line.separator");

    private static byte[] key;
    private static String fileName = "";
    private static byte[] binary;
    private static String fileExtension = "";
    private static int keyFileIndex = 1;
    private static String process;
    private static BufferedOutputStream bufferedOutputStream;

    private static int THREAD_COUNT = 4;

    /**
     * args[0] should be either "e" or "d"
     * args[1] -length => "128" or "256"
     * neither -length:
     * args[1] should be the keyFile
     * args[2] should be the inputFile
     */

    public static void main(String[] args) throws Exception {

        long start = System.nanoTime();

        getArgumentsFromCommandLine(args);

        List<AesThread> aesThreads = initializationList();

        List<Thread> threads = creatingAndStartingThread(aesThreads);

        joinThread(threads);

        writeFile(args[0], aesThreads);

        long finish = System.nanoTime();
        long nanoSeconds = finish - start;
        double seconds = nanoSeconds / 1000000000.0;
        System.out.println(String.format("Done: %.3f", seconds));
    }

    private static void writeFile(String arg, List<AesThread> aesThreads) throws IOException {
        if (arg.equalsIgnoreCase("e")) {
            bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(fileName + "_enc." + fileExtension));
        } else if (arg.equalsIgnoreCase("d")) {
            bufferedOutputStream = new BufferedOutputStream(new FileOutputStream(fileName + "_dec." + fileExtension));
        }

        for (AesThread aesThread : aesThreads) {
            bufferedOutputStream.write(aesThread.getBinary(), 0, aesThread.getBinary().length);
        }
        bufferedOutputStream.flush();
        bufferedOutputStream.close();
    }

    private static void joinThread(List<Thread> threads) throws InterruptedException {
        for (int i = 0; i < THREAD_COUNT; i++) {
            Thread thread = threads.get(i);
            thread.join();
        }
    }

    private static List<Thread> creatingAndStartingThread(List<AesThread> aesThreads) {
        List<Thread> threads = new ArrayList<>();
        for (int i = 0; i < THREAD_COUNT; i++) {
            if (aesThreads.get(i) != null) {
                Thread thread = new Thread(aesThreads.get(i));
                threads.add(thread);
                thread.start();
            }
        }
        return threads;
    }

    private static List<AesThread> initializationList() throws Exception {
        List<AesThread> aesThreads = new ArrayList<>();
        final int sizeFile = binary.length;
        int blockPerThread = sizeFile / 16;
        if (sizeFile % 16 != 0) {
            blockPerThread++;
        }
        int nBlock = blockPerThread;
        THREAD_COUNT = THREAD_COUNT > blockPerThread ? blockPerThread : THREAD_COUNT;
        blockPerThread = blockPerThread / THREAD_COUNT;
        blockDivision(aesThreads, blockPerThread, nBlock);
        return aesThreads;
    }

    private static void blockDivision(List<AesThread> aesThreads, int blockPerThread, int nBlock) {
        int begin;
        byte[] blocks;
        int offset = blockPerThread * 16;
        int number = nBlock - THREAD_COUNT;
        int n = 0, pointer = 0;
        for (int i = 0; i < THREAD_COUNT; i++) {
            if (number != 0 && i < number) {
                begin = (i * offset) * n;
                pointer += offset * blockPerThread;
            } else {
                begin = pointer;
                pointer += offset * blockPerThread;
            }
            blocks = getBlock(begin, offset);
            aesThreads.add(new AesThread(blockPerThread, blocks, process, key));
        }
    }

    private static byte[] getBlock(int begin, int count) {
        final int spaceCode = 32;
        byte[] blocks = new byte[count];
        int index = 0;
        for (int i = begin; i < (count + begin); i++) {
            if (binary.length <= i) {
                blocks[index] = spaceCode;
            } else {
                blocks[index] = binary[i];
            }
            index++;
        }
        return blocks;
    }

    private static void getArgumentsFromCommandLine(String[] args) {
        int keySizeCheck = 128; //User's intended key size.
        try {
            if (args[1].equals("-length")) { //No optional length argument given.
                keyFileIndex += 2;
                keySizeCheck = Integer.parseInt(args[keyFileIndex - 1]);
            }
            key = readSmallBinaryFile(args[keyFileIndex]);
            assert key != null;
            if (key.length * 8 != keySizeCheck) //Check to see if user's intended key size matches the size of key in file.
            {
                throw new Exception("Error: Attempting to use a " + key.length * 8 + "-bit key with AES-" + keySizeCheck);
            }

            fileName += args[keyFileIndex + 1];
            int beginIndex = fileName.lastIndexOf(".");
            fileExtension = fileName.substring(beginIndex + 1, fileName.length());
            fileName = fileName.substring(0, beginIndex);

            if (args[0].equalsIgnoreCase("e")) {
                binary = readSmallBinaryFile(fileName + "." + fileExtension);
                process = "e";
            } else if (args[0].equalsIgnoreCase("d")) {
                binary = readSmallBinaryFile(fileName + "_enc." + fileExtension);
                process = "d";
            }
        } catch (Exception e) {
            System.err.println(e.getMessage() + newline);
            System.exit(1);
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

}
