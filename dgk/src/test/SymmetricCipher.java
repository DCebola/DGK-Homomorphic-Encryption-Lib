import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.HKDFBytesGenerator;
import org.bouncycastle.crypto.params.HKDFParameters;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class SymmetricCipher {
    public static final String ALGORITHM = "CHACHA20";
    public static final String CIPHER_TRANSFORMATION = "ChaCha20-Poly1305/None/NoPadding";
    public static final int KEY_SIZE = 256;
    public static final int IV_SIZE = 12;

    public static byte[] encrypt(byte[] input, SecretKey key, byte[] iv) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(input);
    }

    public static byte[] encrypt(byte[] input, SecretKey key) throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        byte[] iv = generateRandomIV();
        cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));
        byte[] ct = cipher.doFinal(input);
        byte[] result = new byte[ct.length + IV_SIZE];
        System.arraycopy(iv, 0, result, 0, IV_SIZE);
        System.arraycopy(ct, 0, result, IV_SIZE, ct.length);
        return result;
    }

    public static byte[] decrypt(SecretKey key, byte[] cipherText) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(cipherText, 0, IV_SIZE));
        return cipher.doFinal(Arrays.copyOfRange(cipherText, IV_SIZE, cipherText.length));
    }

    public static byte[] decrypt(SecretKey key, byte[] cipherText, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
        return cipher.doFinal(cipherText);
    }

    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGORITHM);
        keyGenerator.init(KEY_SIZE);
        return keyGenerator.generateKey();
    }

    public static SecretKey generateKey(SecretKey masterKey, byte[] info) {
        int keyLength = KEY_SIZE / Byte.SIZE;
        byte[] keyBytes = new byte[keyLength];
        HKDFBytesGenerator hkdf = new HKDFBytesGenerator(new SHA256Digest());
        hkdf.init(HKDFParameters.skipExtractParameters(masterKey.getEncoded(), info));
        hkdf.generateBytes(keyBytes, 0, keyLength);
        return new SecretKeySpec(keyBytes, ALGORITHM);
    }

    public static SecretKey parseKey(byte[] contents) {
        return new SecretKeySpec(contents, 0, contents.length, ALGORITHM);
    }

    public static byte[] generateRandomIV() {
        byte[] iv = new byte[IV_SIZE];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

}
