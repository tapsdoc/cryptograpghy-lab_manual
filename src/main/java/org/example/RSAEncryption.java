package org.example;

import javax.crypto.Cipher;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class RSAEncryption {

    private static final String ALGORITHM = "RSA";

    private final KeyPair keyPair;

    public RSAEncryption() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM);
        keyPairGenerator.initialize(2048);
        this.keyPair = keyPairGenerator.generateKeyPair();
    }

    public byte[] encrypt(String text) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
        return cipher.doFinal(text.getBytes());
    }

    public byte[] decrypt(byte[] encryptedBytes) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
        return cipher.doFinal(encryptedBytes);
    }

    public void encryptFile(Path inputFile, Path outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());

        try (InputStream inputStream = Files.newInputStream(inputFile);
             OutputStream outputStream = new BufferedOutputStream(new FileOutputStream(outputFile.toFile()))) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] encryptedBytes = cipher.doFinal(buffer, 0, bytesRead);
                outputStream.write(encryptedBytes);
            }
        }
    }

    public void decryptFile(Path inputFile, Path outputFile) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());

        try (InputStream inputStream = new BufferedInputStream(new FileInputStream(inputFile.toFile()));
             OutputStream outputStream = Files.newOutputStream(outputFile)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] decryptedBytes = cipher.doFinal(buffer, 0, bytesRead);
                outputStream.write(decryptedBytes);
            }
        }
    }
}