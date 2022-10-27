import misc.HomomorphicException;

import java.math.BigInteger;
import java.security.KeyPair;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

public class LibraryTesting {
    private static int KEY_SIZE = 1024;
    private static KeyPair dgk = null;

    private static DGKPublicKey dgk_pk = null;
    private static DGKEqChecker dgk_eq = null;

    @BeforeAll
    public static void generate_keys() {
        DGKKeyPairGenerator p = new DGKKeyPairGenerator();
        dgk = p.generateKeyPair();
        dgk_pk = (DGKPublicKey) dgk.getPublic();
        DGKPrivateKey dgk_sk = (DGKPrivateKey) dgk.getPrivate();
        dgk_eq = new DGKEqChecker(dgk_sk.getP(), dgk_sk.getVp(), dgk_pk.getN(), dgk_pk.getU());

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

}
