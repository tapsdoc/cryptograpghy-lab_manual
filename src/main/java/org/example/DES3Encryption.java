package org.example;

import javax.crypto.*;
import javax.crypto.spec.DESedeKeySpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;

public class DES3Encryption {

    private static final String ALGORITHM = "DESede";
    private final byte[] keyBytes;

    public DES3Encryption(byte[] key1, byte[] key2, byte[] key3) {
        ByteBuffer buffer = ByteBuffer.allocate(24);
        buffer.put(key1);
        buffer.put(key2);
        buffer.put(key3);
        this.keyBytes = buffer.array();
    }

    public String encrypt(String text) throws Exception {
        DESedeKeySpec keySpec = new DESedeKeySpec(keyBytes);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey secretKey = keyFactory.generateSecret(keySpec);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);

        byte[] encryptedBytes = cipher.doFinal(text.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedText) throws Exception {
        DESedeKeySpec keySpec = new DESedeKeySpec(keyBytes);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey secretKey = keyFactory.generateSecret(keySpec);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedText));
        return new String(decryptedBytes);
    }

    public void encryptFile(File inputFile, File outputFile) throws Exception {
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE);
        processFile(cipher, inputFile, outputFile);
    }

    public void decryptFile(File inputFile, File outputFile) throws Exception {
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE);
        processFile(cipher, inputFile, outputFile);
    }

    private Cipher getCipher(int mode) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException {
        KeySpec keySpec = new DESedeKeySpec(keyBytes);
        SecretKeyFactory keyFactory = SecretKeyFactory.getInstance(ALGORITHM);
        SecretKey secretKey = keyFactory.generateSecret(keySpec);

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(mode, secretKey);
        return cipher;
    }

    private void processFile(Cipher cipher, File inputFile, File outputFile) throws IOException, IllegalBlockSizeException, BadPaddingException {
        try (InputStream inputStream = new FileInputStream(inputFile);
             OutputStream outputStream = new FileOutputStream(outputFile)) {

            byte[] inputBuffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = inputStream.read(inputBuffer)) != -1) {
                byte[] outputBuffer = cipher.update(inputBuffer, 0, bytesRead);
                if (outputBuffer != null) {
                    outputStream.write(outputBuffer);
                }
            }
            byte[] outputBuffer = cipher.doFinal();
            if (outputBuffer != null) {
                outputStream.write(outputBuffer);
            }
        }
    }
}