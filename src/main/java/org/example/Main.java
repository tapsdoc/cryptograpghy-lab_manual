package org.example;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class Main {

    private static final byte[] KEY1 = { 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef };
    private static final byte[] KEY2 = { (byte) 0xfe, (byte) 0xdc, (byte) 0xba, (byte) 0x98, 0x76, 0x54, 0x32, 0x10 };
    private static final byte[] KEY3 = { 0x01, 0x23, 0x45, 0x67, (byte) 0x89, (byte) 0xab, (byte) 0xcd, (byte) 0xef };

    public static void main(String[] args) throws Exception {

        String key = "MySecretKey";
        Path inputFile = Path.of("demodata.txt");
        Path outputFile = Path.of("encryptdata.txt");

        DesEncryption desEncryption = new DesEncryption(key);
        // Read the input file
        String originalText = Files.readString(inputFile);
        // Encrypt the text
        String encryptedText = desEncryption.encrypt(originalText);
        // Write the encrypted text to the output file
        Files.writeString(outputFile, encryptedText);
        System.out.println("Encryption complete.");

        String hello = "Hello, World!";
        DES3Encryption encryption = new DES3Encryption(KEY1, KEY2, KEY3);


        //DES-3 Encryption from a string
        // Encrypt the text
        String encryptedTextHello = encryption.encrypt(hello);
        System.out.println("Encrypted text in DES-3: " + encryptedTextHello);

        // Decrypt the text
        String decryptedText = encryption.decrypt(encryptedTextHello);
        System.out.println("Decrypted text in DES-3: " + decryptedText);


        //DES-3 Encryption from a text file
        // Encrypt a file
        File inputFileDES3 = new File("demodata.txt");
        File encryptedFile = new File("encrypted.bin");
        encryption.encryptFile(inputFileDES3, encryptedFile);

        // Decrypt a file
        File decryptedFile = new File("decrypted.txt");
        encryption.decryptFile(encryptedFile, decryptedFile);


        //RSA Encryption
        RSAEncryption rsaEncryption = new RSAEncryption();
        // Encrypt the text
        byte[] encryptedBytes = rsaEncryption.encrypt(hello);
        String encryptedTextRSA = Base64.getEncoder().encodeToString(encryptedBytes);
        System.out.println("Encrypted text in RSA: " + encryptedTextRSA);

        // Decrypt the text
        byte[] decryptedBytes = rsaEncryption.decrypt(Base64.getDecoder().decode(encryptedTextRSA));
        String decryptedTextRSA = new String(decryptedBytes);
        System.out.println("Decrypted text in RSA: " + decryptedTextRSA);


        //RSA Encryption from a text file
        // Encrypt a file
        rsaEncryption.encryptFile(inputFile, outputFile);

        // Decrypt the encrypted file
        Path decryptedFileRSA = Paths.get("decrypted.txt");
        rsaEncryption.decryptFile(outputFile, decryptedFileRSA);

        //SHA-1 Algorithm
        try {
            byte[] digest = Sha1Calculator.calculateSha1Digest(hello);
            String hexDigest = Sha1Calculator.bytesToHex(digest);
            System.out.println("SHA-1 digest of \"" + hello + "\": " + hexDigest);
        } catch (NoSuchAlgorithmException e) {
            System.err.println("SHA-1 algorithm not available");
        }
    }
}