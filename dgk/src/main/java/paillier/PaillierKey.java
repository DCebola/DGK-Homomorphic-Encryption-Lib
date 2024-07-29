package paillier;

import java.math.BigInteger;

public interface PaillierKey 
{
	BigInteger getN();
	BigInteger getModulus();
}
