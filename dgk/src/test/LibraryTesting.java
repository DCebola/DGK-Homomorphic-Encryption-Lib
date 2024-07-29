import misc.HomomorphicException;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

import misc.NTL;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import paillier.PaillierCipher;
import paillier.PaillierKeyPairGenerator;
import paillier.PaillierPrivateKey;
import paillier.PaillierPublicKey;

import javax.crypto.*;

import static org.junit.jupiter.api.Assertions.*;

public class LibraryTesting {
    private static PaillierPublicKey paillier_pk = null;
    private static PaillierPrivateKey paillier_sk = null;
    private static DGKPublicKey dgk_pk = null;
    private static DGKEqChecker dgk_eq = null;
    private static DGKPrivateKey dgk_sk = null;
    private static SecretKey rnd = null;
    private static SecretKey det = null;
    private static byte[] fixed_iv = null;

    public static byte[] ivFromInteger(int integer) {
        byte[] iv = new byte[12];
        byte[] intBytes = new byte[]{(byte) (integer >> 24), (byte) (integer >> 16), (byte) (integer >> 8), (byte) integer};
        System.arraycopy(intBytes, 0, iv, 12 - Integer.BYTES, Integer.BYTES);
        return iv;
    }

    public static int integerFromIV(byte[] iv) {
        int i = 12 - Integer.BYTES;
        return (iv[i] << 24) | ((iv[i + 1] & 0xff) << 16) | ((iv[i + 2] & 0xff) << 8) | (iv[i + 3] & 0xff);
    }

    @BeforeAll
    public static void generate_keys() throws NoSuchAlgorithmException {
        DGKKeyPairGenerator dgk_gen = new DGKKeyPairGenerator();
        KeyPair dgk = dgk_gen.generateKeyPair();
        dgk_pk = (DGKPublicKey) dgk.getPublic();
        dgk_sk = (DGKPrivateKey) dgk.getPrivate();
        dgk_eq = new DGKEqChecker(new DGKEqKey(dgk_sk.getP(), dgk_sk.getVp(), dgk_pk.getN(), dgk_pk.getU()));

        PaillierKeyPairGenerator paillier_gen = new PaillierKeyPairGenerator();
        KeyPair paillier = paillier_gen.generateKeyPair();
        paillier_pk = (PaillierPublicKey) paillier.getPublic();
        paillier_sk = (PaillierPrivateKey) paillier.getPrivate();

        rnd = SymmetricCipher.generateKey();
        det = SymmetricCipher.generateKey();
        fixed_iv = SymmetricCipher.generateRandomIV();

    }

    @Test
    public void basic_DGK() throws HomomorphicException {
        System.out.println("p: " + dgk_sk.getP());
        System.out.println("q: " + dgk_sk.getQ());
        System.out.println("pq: " + dgk_sk.getP().multiply(dgk_sk.getQ()));
        System.out.println("n: " + dgk_pk.getN());
        System.out.println("u: " + dgk_pk.getU());
        System.out.println("g: " + dgk_pk.getG());
        System.out.println("uvpvq: " + dgk_sk.getVq().multiply(dgk_sk.getVp()).multiply(dgk_pk.getBigU()));

        BigInteger encrypted_zero = dgk_pk.encrypt(BigInteger.ZERO);
        assertNotEquals(encrypted_zero, BigInteger.ONE);

        BigInteger a = dgk_pk.encrypt(BigInteger.TWO);
        BigInteger b = dgk_pk.encrypt(BigInteger.TWO);
        System.out.println(a);
        System.out.println(b);
        assertNotEquals(a, b);

        BigInteger a_minus_b = dgk_pk.subtract(a, b);
        BigInteger b_minus_a = dgk_pk.subtract(b, a);

        assertNotEquals(a_minus_b, b_minus_a);

        BigInteger r = NTL.generateXBitRandom(3 * dgk_pk.getT());

        BigInteger rnd = dgk_pk.getH().modPow(r, dgk_pk.getN());
        BigInteger inverseRnd = dgk_pk.getH().modPow(r.negate(), dgk_pk.getN());
        BigInteger a2 = dgk_pk.reencrypt(a, rnd);
        BigInteger b2 = dgk_pk.reencrypt(b, rnd);
        BigInteger a3 = dgk_pk.reencrypt(a, inverseRnd);
        BigInteger b3 = dgk_pk.reencrypt(b, inverseRnd);
        assertTrue(dgk_eq.check(a2, b2));
        assertTrue(dgk_eq.check(a3, b3));
        assertTrue(dgk_eq.check(a, a3));
        assertTrue(dgk_eq.check(b, b3));

        assertNotEquals(a, a2);
        assertNotEquals(a, a3);
        assertNotEquals(b, b2);
        assertNotEquals(b, b3);
        assertEquals(a, dgk_pk.reencrypt(dgk_pk.reencrypt(a, rnd), inverseRnd));
        assertEquals(b, dgk_pk.reencrypt(dgk_pk.reencrypt(b, rnd), inverseRnd));

        assertTrue(dgk_eq.check(encrypted_zero, encrypted_zero));
        assertTrue(dgk_eq.check(a, a));
        assertTrue(dgk_eq.check(b, b));
        assertTrue(dgk_eq.check(a, b));
        assertTrue(dgk_eq.check(b, a));
        assertTrue(dgk_eq.check(a_minus_b, b_minus_a));
        assertTrue(dgk_eq.check(b_minus_a, a_minus_b));

    }

    @Test
    public void bench_Paillier_Equals() throws HomomorphicException {
        BigInteger a = PaillierCipher.encrypt(BigInteger.TWO, paillier_pk);
        BigInteger b = PaillierCipher.encrypt(BigInteger.TWO, paillier_pk);
        BigInteger r = PaillierCipher.encrypt(NTL.generateXBitRandom(paillier_pk.getN().bitCount()), paillier_pk);
        System.out.println(r);
        BigInteger a2;
        BigInteger b2;
        long startTime = System.nanoTime();
        int numOps = 10;
        for (int i = 0; i < numOps; i++) {
            a2 = PaillierCipher.add(a, r, paillier_pk);
            b2 = PaillierCipher.add(b, r, paillier_pk);
            PaillierCipher.decrypt(PaillierCipher.subtract(a2, b2, paillier_pk), paillier_sk).equals(BigInteger.ZERO);
        }
        long duration = System.nanoTime() - startTime;
        long duration_per_op = duration / numOps;
        System.out.println("Paillier Total: " + duration / 1000);
        System.out.println("Paillier Average: " + duration_per_op / 1000);
    }

    @Test
    public void bench_Paillier_Equals2() throws HomomorphicException {
        BigInteger a = PaillierCipher.encrypt(BigInteger.TWO, paillier_pk);
        BigInteger b = PaillierCipher.encrypt(BigInteger.TWO, paillier_pk);
        BigInteger r = PaillierCipher.encrypt(NTL.generateXBitRandom(paillier_pk.getN().bitCount()), paillier_pk);
        System.out.println(r);
        BigInteger a2;
        BigInteger b2;
        long startTime = System.nanoTime();
        int numOps = 10;
        for (int i = 0; i < numOps; i++) {
            a2 = PaillierCipher.decrypt(PaillierCipher.add(a, r, paillier_pk), paillier_sk);
            b2 = PaillierCipher.decrypt(PaillierCipher.add(b, r, paillier_pk), paillier_sk);
            a2.subtract(b2).equals(BigInteger.ZERO);
        }
        long duration = System.nanoTime() - startTime;
        long duration_per_op = duration / numOps;
        System.out.println("Paillier Total: " + duration / 1000);
        System.out.println("Paillier Average: " + duration_per_op / 1000);
    }

    @Test
    public void bench_DGK_Equals() throws HomomorphicException {
        BigInteger a = dgk_pk.encrypt(BigInteger.TWO);
        BigInteger b = dgk_pk.encrypt(BigInteger.TWO);
        BigInteger r = NTL.generateXBitRandom(3 * dgk_pk.getT());
        r = dgk_pk.getH().modPow(r, dgk_pk.getN());
        BigInteger a2;
        BigInteger b2;
        long startTime = System.nanoTime();
        int numOps = 10000;
        for (int i = 0; i < numOps; i++) {
            a2 = dgk_pk.add(a, r);
            b2 = dgk_pk.add(b, r);
            dgk_eq.check(a2, b2);
        }
        long duration = System.nanoTime() - startTime;
        long duration_per_op = duration / numOps;
        System.out.println("DGK Total: " + duration / 1000);
        System.out.println("DGK Average: " + duration_per_op / 1000);
    }

    @Test
    public void bench_DGK_Equals2() throws HomomorphicException {
        BigInteger a = dgk_pk.encrypt(BigInteger.TWO.add(BigInteger.TWO).add(BigInteger.TEN));
        BigInteger b = dgk_pk.encrypt(BigInteger.TWO.add(BigInteger.TWO).add(BigInteger.TEN));
        BigInteger r = NTL.generateXBitRandom(3 * dgk_pk.getT());
        r = dgk_pk.getH().modPow(r, dgk_pk.getN());
        BigInteger a2;
        BigInteger b2;
        long startTime = System.nanoTime();
        int numOps = 10;
        for (int i = 0; i < numOps; i++) {
            a2 = dgk_pk.add(a, r);
            b2 = dgk_pk.add(b, r);
            NTL.POSMOD(a2.modPow(dgk_sk.getVp(), dgk_sk.getP()), dgk_sk.getP()).subtract(NTL.POSMOD(b2.modPow(dgk_sk.getVp(), dgk_sk.getP()), dgk_sk.getP())).equals(BigInteger.ZERO);
        }
        long duration = System.nanoTime() - startTime;
        long duration_per_op = duration / numOps;
        System.out.println("DGK Total: " + duration / 1000);
        System.out.println("DGK Average: " + duration_per_op / 1000);
    }


    @Test
    public void bench_Plaintext_Equals()  {
        String a = "2";
        String b = "2";
        int numOps = 10000000;
        long startTime = System.nanoTime();
        for (int i = 0; i < numOps; i++)
            a.equals(b);
        long duration = System.nanoTime() - startTime;
        long duration_per_op = duration / numOps;
        System.out.println("DET Total: " + duration / 1000);
        System.out.println("DET Average: " + duration_per_op / 1000);
    }
    @Test
    public void bench_RDN_DET_Equals() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        String a = "2";
        String b = "2";
        int numOps = 10000;
        String rnd_a = Base64.getUrlEncoder().encodeToString(
                SymmetricCipher.encrypt(SymmetricCipher.encrypt(ByteBuffer.allocate(Integer.BYTES).putInt(Integer.parseInt(a)).array(), det, fixed_iv), rnd)
        );
        String rnd_b = Base64.getUrlEncoder().encodeToString(
                SymmetricCipher.encrypt(SymmetricCipher.encrypt(ByteBuffer.allocate(Integer.BYTES).putInt(Integer.parseInt(b)).array(), det, fixed_iv), rnd)
        );
        long startTime = System.nanoTime();
        for (int i = 0; i < numOps; i++) {
            String det_a = new String(SymmetricCipher.decrypt(rnd, Base64.getUrlDecoder().decode(rnd_a)), StandardCharsets.UTF_8);
            String det_b = new String(SymmetricCipher.decrypt(rnd, Base64.getUrlDecoder().decode(rnd_b)), StandardCharsets.UTF_8);
            det_a.equals(det_b);
        }
        long duration = System.nanoTime() - startTime;
        long duration_per_op = duration / numOps;
        System.out.println("DET Total: " + duration / 1000);
        System.out.println("DET Average: " + duration_per_op / 1000);
    }

    @Test
    public void test_Symmetric_Encryption() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] a = "test_a".getBytes(StandardCharsets.UTF_8);
        byte[] b = "test_b".getBytes(StandardCharsets.UTF_8);
        byte[] extended_iv = SymmetricEncryptionUtils.generateRandomIV();
        String a1 = Base64.getUrlEncoder().encodeToString(SymmetricCipher.encrypt(a, det, fixed_iv));
        String a2 = Base64.getUrlEncoder().encodeToString(SymmetricEncryptionUtils.encrypt(a, det, extended_iv));
        String b1 = Base64.getUrlEncoder().encodeToString(SymmetricCipher.encrypt(b, rnd));
        String b2 = Base64.getUrlEncoder().encodeToString(SymmetricEncryptionUtils.encrypt(b, rnd));
        System.out.println("A1: " + a1);
        System.out.println("A2: " + a2);
        System.out.println("B1: " + b1);
        System.out.println("B2: " + b2);

        String dec_a1 = new String(SymmetricCipher.decrypt(det, Base64.getUrlDecoder().decode(a1), fixed_iv), StandardCharsets.UTF_8);
        System.out.println("DEC A1: " + dec_a1);
        String dec_b1 = new String(SymmetricCipher.decrypt(rnd, Base64.getUrlDecoder().decode(b1)), StandardCharsets.UTF_8);
        System.out.println("DEC B1: " + dec_b1);

        String dec_a2 = new String(SymmetricEncryptionUtils.decrypt(det, Base64.getUrlDecoder().decode(a2), extended_iv), StandardCharsets.UTF_8);
        System.out.println("DEC A2: " + dec_a2);
        String dec_b2 = new String(SymmetricEncryptionUtils.decrypt(rnd, Base64.getUrlDecoder().decode(b2)), StandardCharsets.UTF_8);
        System.out.println("DEC B2: " + dec_b2);

    }

    @Test
    public void bench_Symmetric_Encryption() throws InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        byte[] a = "test_a".getBytes(StandardCharsets.UTF_8);
        byte[] extended_iv = SymmetricEncryptionUtils.generateRandomIV();
        int numOperations = 100000;
        long startTime = System.nanoTime();
        byte[] enc_a;
        for (int i = 0; i < numOperations; i++){
            enc_a = SymmetricCipher.encrypt(a, det, fixed_iv);
            SymmetricCipher.decrypt(det, enc_a, fixed_iv);
            enc_a = SymmetricCipher.encrypt(a, rnd);
            SymmetricCipher.decrypt(rnd, enc_a);
        }
        long duration = System.nanoTime() - startTime;
        long duration_per_op = duration / numOperations;
        System.out.println("JAVAX Total: " + duration / 1000);
        System.out.println("JAVAX Average: " + duration_per_op / 1000);

        startTime = System.nanoTime();
        for (int i = 0; i < numOperations; i++){
            enc_a = SymmetricEncryptionUtils.encrypt(a, det, extended_iv);
            SymmetricEncryptionUtils.decrypt(det, enc_a, extended_iv);
            enc_a = SymmetricEncryptionUtils.encrypt(a, rnd);
            SymmetricEncryptionUtils.decrypt(rnd, enc_a);
        }

        duration = System.nanoTime() - startTime;
        duration_per_op = duration / numOperations;
        System.out.println("Libsodium Total: " + duration / 1000);
        System.out.println("Libsodium Average: " + duration_per_op / 1000);

    }

    @Test
    public void test_equals_arrays() {
        byte[] a = "test_a".getBytes(StandardCharsets.UTF_8);
        byte[] b = "test_a".getBytes(StandardCharsets.UTF_8);
        System.out.println(Arrays.equals(a, b));
    }

    public static byte[] integerToByteArray(int integer) {
        return new byte[]{(byte) (integer >> 24), (byte) (integer >> 16), (byte) (integer >> 8), (byte) integer};
    }

    public static int byteArrayToInteger(byte[] iv) {
        return (iv[0] << 24) | ((iv[1] & 0xff) << 16) | ((iv[2] & 0xff) << 8) | (iv[3] & 0xff);
    }

    @Test
    public void testSwaps() {

        List<String> triplesToDelete = new ArrayList<>(List.of("t0", "t1", "t2", "t3", "t4", "t5", "t6", "t7", "t8"));
        Map<String, List<String>> keywordsTrapdoors = new HashMap<>();
        keywordsTrapdoors.put(triplesToDelete.get(0), List.of("0k1", "0k2", "0k3", "0k4", "0k5"));
        keywordsTrapdoors.put(triplesToDelete.get(1), List.of("1k1", "1k2", "1k3", "1k4"));
        keywordsTrapdoors.put(triplesToDelete.get(2), List.of("2k1", "2k2", "2k3", "2k4", "2k5", "2k6", "2k7", "2k8", "2k9"));
        keywordsTrapdoors.put(triplesToDelete.get(3), List.of("3k1", "3k2", "3k3", "3k4", "3k5", "3k6", "3k7", "3k8", "3k9"));
        keywordsTrapdoors.put(triplesToDelete.get(4), List.of("4k1", "4k2", "4k3"));
        keywordsTrapdoors.put(triplesToDelete.get(5), List.of("5k1", "5k2", "5k3", "5k4", "5k5", "5k6"));
        keywordsTrapdoors.put(triplesToDelete.get(6), List.of("6k1", "6k2"));
        keywordsTrapdoors.put(triplesToDelete.get(7), List.of("7k1", "7k2", "7k3", "7k4", "7k5", "7k6", "7k7", "7k8"));
        keywordsTrapdoors.put(triplesToDelete.get(8), List.of("8k1", "8k2", "8k3", "8k4", "8k5", "8k6", "8k7"));
        Collections.shuffle(triplesToDelete);

        int totalTrapdoors = keywordsTrapdoors.values().stream().mapToInt(List::size).sum();
        String[] trapdoorsToDelete = new String[totalTrapdoors];
        List<Integer> permutation = generateRandomPermutation(totalTrapdoors);
        List<String> trapdoors;

        int offset = 0, length;
        for (String keyword : triplesToDelete) {
            trapdoors = keywordsTrapdoors.get(keyword);
            length = trapdoors.size();
            for (int i = 0; i < length; i++)
                trapdoorsToDelete[permutation.get(offset + i)] = trapdoors.get(i);
            offset += length;
        }

        offset = 0;
        for (String keyword : triplesToDelete) {
            length = keywordsTrapdoors.get(keyword).size();
            System.out.println(keyword + " | " + offset + " | " + length);
            for (int i = offset; i < offset + length; i++) {
                System.out.print(trapdoorsToDelete[permutation.get(i)] + ", ");
            }
            System.out.println();
            offset += length;
        }
        System.out.println(trapdoorsToDelete.length);


        Set<Integer> toDelete = new HashSet<>();
        SortedMap<Integer, Integer> swaps = new TreeMap<>();
        int frequency = 7;

        toDelete.add(4);
        toDelete.add(5);
        toDelete.add(6);
        toDelete.add(7);


        Queue<Integer> result = new ArrayDeque<>(frequency - toDelete.size());

        for (int i = frequency; i > 0; i--)
            if (!toDelete.contains(i))
                result.add(i);

        System.out.println(Arrays.toString(result.toArray()));
        Integer cur;
        for (int i = 1; i <= frequency; i++) {
            System.out.print(i + " ");
            if (toDelete.contains(i)) {
                cur = result.peek();
                if (cur != null && cur > i) {
                    toDelete.remove(i);
                    swaps.put(cur, i);
                    result.poll();
                }
            }
        }
        System.out.println(Arrays.toString(swaps.entrySet().toArray()));
        System.out.println(Arrays.toString(toDelete.toArray()));

    }

    public List<Integer> generateRandomPermutation(int total) {
        List<Integer> idxs = new ArrayList<>(total);
        for (int i = 0; i < total; i++) idxs.add(i);
        Collections.shuffle(idxs);
        return idxs;
    }

}
