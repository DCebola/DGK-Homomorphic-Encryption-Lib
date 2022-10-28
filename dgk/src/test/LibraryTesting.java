import misc.HomomorphicException;

import java.math.BigInteger;
import java.security.*;
import java.util.Base64;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import static org.junit.jupiter.api.Assertions.*;

public class LibraryTesting {
    private static int KEY_SIZE = 1024;
    private static KeyPair dgk = null;

    private static DGKPublicKey dgk_pk = null;
    private static DGKEqChecker dgk_eq = null;

    private static SecretKey rnd = null;
    private static SecretKey det = null;
    private static byte[] fixed_iv = null;

    @BeforeAll
    public static void generate_keys() throws NoSuchAlgorithmException {
        DGKKeyPairGenerator p = new DGKKeyPairGenerator();
        dgk = p.generateKeyPair();
        dgk_pk = (DGKPublicKey) dgk.getPublic();
        DGKPrivateKey dgk_sk = (DGKPrivateKey) dgk.getPrivate();
        dgk_eq = new DGKEqChecker(dgk_sk.getP(), dgk_sk.getVp(), dgk_pk.getN(), dgk_pk.getU());

        rnd = generateKey();
        det = generateKey();
        fixed_iv = generateIv();

    }

    private static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        return keyGenerator.generateKey();
    }

    private static byte[] generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return iv;
    }

    public static String encrypt(String input, SecretKey key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, SecretKey key, byte[] iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(128, iv));
        byte[] plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        return new String(plainText);
    }

    @Test
    public void basic_DGK() throws HomomorphicException {
        BigInteger encrypted_zero = dgk_pk.encrypt(BigInteger.ZERO);
        assertNotEquals(encrypted_zero, BigInteger.ONE);

        BigInteger a = dgk_pk.encrypt(BigInteger.TWO);
        BigInteger b = dgk_pk.encrypt(BigInteger.TWO);
        assertNotEquals(a, b);

        BigInteger a_minus_b = dgk_pk.subtract(a, b);
        BigInteger b_minus_a = dgk_pk.subtract(b, a);
        assertNotEquals(a_minus_b, b_minus_a);

        assertTrue(dgk_eq.check(encrypted_zero, encrypted_zero));
        assertTrue(dgk_eq.check(a, a));
        assertTrue(dgk_eq.check(b, b));
        assertTrue(dgk_eq.check(a, b));
        assertTrue(dgk_eq.check(b, a));
        assertTrue(dgk_eq.check(a_minus_b, b_minus_a));
        assertTrue(dgk_eq.check(b_minus_a, a_minus_b));
        assertFalse(dgk_eq.check(encrypted_zero, b));
        assertFalse(dgk_eq.check(encrypted_zero, a));
        assertFalse(dgk_eq.check(b, encrypted_zero));
        assertFalse(dgk_eq.check(a, encrypted_zero));
    }

    @Test
    public void bench_DGK_Equals() throws HomomorphicException {
        BigInteger a = dgk_pk.encrypt(BigInteger.TWO);
        BigInteger b = dgk_pk.encrypt(BigInteger.TWO);
        long startTime = System.nanoTime();
        int numOps = 100000;
        for (int i = 0; i < numOps; i++)
            dgk_eq.check(a, b);
        long endTime = System.nanoTime();
        long duration = (endTime - startTime) / 1000;
        System.out.println("DGK Total: " + duration);
        System.out.println("DGK Average: " + (duration / numOps));
    }

    @Test
    public void bench_RDN_DET_Equals() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String a = "1";
        String b = "1";

        long duration_total = 0;
        long duration_decrypt = 0;
        long duration_equal = 0;
        int numOps = 100000;

        for (int i = 0; i < numOps; i++) {
            byte[] rnd_iv_a = generateIv();
            byte[] rnd_iv_b = generateIv();
            String rnd_a = encrypt(encrypt(a, det, fixed_iv), rnd, rnd_iv_a);
            String rnd_b = encrypt(encrypt(b, det, fixed_iv), rnd, rnd_iv_b);
            long startTime = System.nanoTime();
            String det_a = decrypt(rnd_a, rnd, rnd_iv_a);
            String det_b = decrypt(rnd_b, rnd, rnd_iv_b);
            long endTime_decrypt = System.nanoTime();
            det_a.equals(det_b);
            long endTime_total = System.nanoTime();
            duration_total += endTime_total - startTime;
            duration_decrypt += endTime_decrypt - startTime;
            duration_equal += endTime_total - endTime_decrypt;
        }

        System.out.println("RND/DET Total: " + duration_total / 1000);
        System.out.println("RND/DET Average: " + ((duration_total / 1000) / numOps));

        System.out.println("RND decrypt Total: " + duration_decrypt / 1000);
        System.out.println("RND decrypt Average: " + ((duration_decrypt / 1000) / numOps));

        System.out.println("DET equals Total: " + duration_equal / 1000);
        System.out.println("DET equals Average: " + ((duration_equal / 1000) / numOps));
    }
}
