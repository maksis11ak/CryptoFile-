// cryptographer_java.java — криптограф (шифрование файлов) на Java

import javax.crypto.*;
import javax.crypto.spec.*;
import java.security.*;
import java.io.*;
import java.nio.file.*;

public class Cryptographer {
    private static final int SALT_LEN = 16;
    private static final int NONCE_LEN = 12;
    private static final int TAG_LEN = 16;
    private static final int ITERATIONS = 100000;
    private static final int KEY_LEN = 256;

    public static byte[] deriveKey(String password, byte[] salt) throws Exception {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt, ITERATIONS, KEY_LEN);
        SecretKey tmp = factory.generateSecret(spec);
        return tmp.getEncoded();
    }

    public static void encryptFile(String input, String output, String password) throws Exception {
        byte[] salt = new byte[SALT_LEN];
        byte[] nonce = new byte[NONCE_LEN];
        SecureRandom.getInstanceStrong().nextBytes(salt);
        SecureRandom.getInstanceStrong().nextBytes(nonce);

        byte[] key = deriveKey(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LEN * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), gcmSpec);

        // Читаем весь файл (для больших файлов нужно потоковое шифрование)
        byte[] plaintext = Files.readAllBytes(Paths.get(input));
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Сохраняем соль + nonce + ciphertext
        try (FileOutputStream fos = new FileOutputStream(output)) {
            fos.write(salt);
            fos.write(nonce);
            fos.write(ciphertext);
        }
        System.out.println("Файл зашифрован: " + output);
    }

    public static void decryptFile(String input, String output, String password) throws Exception {
        byte[] salt = new byte[SALT_LEN];
        byte[] nonce = new byte[NONCE_LEN];
        try (FileInputStream fis = new FileInputStream(input)) {
            fis.read(salt);
            fis.read(nonce);
            byte[] rest = fis.readAllBytes();
            if (rest.length < TAG_LEN) {
                throw new Exception("Некорректный зашифрованный файл");
            }
            byte[] ciphertext = java.util.Arrays.copyOfRange(rest, 0, rest.length - TAG_LEN);
            byte[] tag = java.util.Arrays.copyOfRange(rest, rest.length - TAG_LEN, rest.length);

            byte[] key = deriveKey(password, salt);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec gcmSpec = new GCMParameterSpec(TAG_LEN * 8, nonce);
            cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), gcmSpec);

            // Добавляем тег в параметры? В Java GCM использует тег из cipher.doFinal
            // Используем старый способ: cipher.updateAAD и т.д., но проще: объединяем ciphertext + tag
            byte[] combined = new byte[ciphertext.length + tag.length];
            System.arraycopy(ciphertext, 0, combined, 0, ciphertext.length);
            System.arraycopy(tag, 0, combined, ciphertext.length, tag.length);
            byte[] plaintext = cipher.doFinal(combined);

            Files.write(Paths.get(output), plaintext);
            System.out.println("Файл расшифрован: " + output);
        } catch (Exception e) {
            System.err.println("Ошибка дешифрования: " + e.getMessage());
            throw e;
        }
    }

    public static void main(String[] args) {
        if (args.length != 4) {
            System.err.println("Использование: java Cryptographer <encrypt|decrypt> <input> <output> <password>");
            System.exit(1);
        }
        try {
            if (args[0].equals("encrypt")) {
                encryptFile(args[1], args[2], args[3]);
            } else if (args[0].equals("decrypt")) {
                decryptFile(args[1], args[2], args[3]);
            } else {
                System.err.println("Режим должен быть encrypt или decrypt");
                System.exit(1);
            }
        } catch (Exception e) {
            System.err.println("Ошибка: " + e.getMessage());
            System.exit(1);
        }
    }
}
