package cl.NicLabs.HomomorphicEncryption;

import java.math.BigInteger;

public class MathUtils {

	static public int factorial(int n) {
		int total = 1;
		for (int i = 1; i <= n; i++)
			total = total * i;
		return total;
	}
	
	static public BigInteger D(BigInteger n, BigInteger w) {
		BigInteger D = (w.subtract(BigInteger.ONE)).divide(n);
		return D;
	}
	
}
