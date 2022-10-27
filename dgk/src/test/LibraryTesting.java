import misc.HomomorphicException;

import java.security.KeyPair;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class LibraryTesting 
{	
	private static int KEY_SIZE = 1024;
	private static KeyPair dgk = null;
	
	private static DGKPublicKey dgk_pk = null;
	private static DGKPrivateKey dgk_sk = null;
	
	@BeforeAll
	public static void generate_keys() throws HomomorphicException {
		DGKKeyPairGenerator p = new DGKKeyPairGenerator();
		dgk = p.generateKeyPair();
		dgk_pk = (DGKPublicKey) dgk.getPublic();
		dgk_sk = (DGKPrivateKey) dgk.getPrivate();
	}
	
	@Test
	public void basic_DGK() throws HomomorphicException {
		/*
		 Test D(E(X)) = X
		BigInteger a = dgk_pk.encrypt(BigInteger.TEN);
		a = BigInteger.valueOf(DGKOperations.decrypt(a, dgk_sk));
		assertEquals(BigInteger.TEN, a);
		
		// Test Addition, note decrypting returns a long not BigInteger
		a = DGKOperations.encrypt(a, dgk_pk);
		a = DGKOperations.add(a, a, dgk_pk); //20
		assertEquals(20, DGKOperations.decrypt(a, dgk_sk));
		
		// Test Subtraction, note decrypting returns a long not BigInteger
		a = DGKOperations.subtract(a, DGKOperations.encrypt(BigInteger.TEN, dgk_pk), dgk_pk);// 20 - 10
		assertEquals(10, DGKOperations.decrypt(a, dgk_sk));
		
		// Test Multiplication, note decrypting returns a long not BigInteger
		a = DGKOperations.multiply(a, BigInteger.TEN, dgk_pk); // 10 * 10
		assertEquals(100, DGKOperations.decrypt(a, dgk_sk));
		*/
	}

}
