package cl.NicLabs.HomomorphicEncryption;

import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

//import android.util.Log;

public class EncryptedValue implements Serializable {

	private static final long serialVersionUID = 1L;
	private BigInteger y1;
	private BigInteger y2;

	// EncryptionParameters values needed
	private BigInteger n;
	private int s;

	private EncryptedValue(BigInteger y1, BigInteger y2, BigInteger n, int s) {
		this.y1 = y1;
		this.y2 = y2;
		this.n = n;
		this.s = s;
	}

	/**
	 * Constructor for EncryptedValues
	 * 
	 * @param value
	 *            the BigInteger to encrypt
	 * @param param
	 *            the EncryptionParameters to be used in the encryptation. It
	 *            must be the same used for the encryption and decryption
	 *            proces.
	 */
	public EncryptedValue(BigInteger value, EncryptionParameters param) {
		// Log.d("EncryptedValue", "Encriptacion de valor: " + value);
		BigInteger anillo = param.getAnillo();
		SecureRandom rnd = new SecureRandom();
		BigInteger r = new BigInteger(anillo.bitLength(), rnd);

		BigInteger u = param.n.add(BigInteger.ONE);
		BigInteger s1 = u.modPow(value, anillo);
		BigInteger s2 = param.getPublicKey().modPow(r, anillo);
		this.y1 = param.g.modPow(r, anillo);
		this.y2 = (s2.multiply(s1)).mod(anillo);

		// this.param = param;
		this.n = param.n;
		this.s = param.s;
	}

	/**
	 * Method to add values that are in the encrypted form. It means use a
	 * multiplication in the encrypted space of the values. Both values must be
	 * encrypted with the same EncriptedParametes.
	 * 
	 * @param value2
	 *            The second term in the sum operation.
	 * @return a EncryptedValue with the sum of the terms. To decrypt it you
	 *         must use the same EncryptionParameters used in the encrypt
	 *         process.
	 */
	public EncryptedValue addValue(EncryptedValue value2) {
		// Log.d("EncryptedValue",
		// "Calculo suma de valores (Multiplicacion de Encriptados)");
		BigInteger first = this.y1.multiply(value2.y1);
		BigInteger second = this.y2.multiply(value2.y2);
		return new EncryptedValue(first, second, this.n, this.s);
	}

	/**
	 * Method to scale a value in its encrypted form.
	 * 
	 * @param factor
	 *            the factor to scale the value encrypted.
	 * @return A encryptedValue with the old value scaled by the factor. It must
	 *         be decrypted with the same encryptedParamters used in the
	 *         encryption process.
	 */
	public EncryptedValue scale(BigInteger factor) {
		// Log.d("EncryptedValue",
		// "Calculo multiplicacion por escalar (Calculo exponente de encriptados)");
		BigInteger first = this.y1.modPow(factor, this.getAnillo());
		BigInteger second = this.y2.modPow(factor, this.getAnillo());
		return new EncryptedValue(first, second, this.n, this.s);
	}

	/**
	 * Method to decrypt a EncryptedValue.
	 * 
	 * @param secretKey
	 *            BigInteger with the SecretKey to decrypt the EncryptedValue.
	 *            You must use the value of SecretKey available in the
	 *            EncryptionParameters through getSecretKey() method.
	 * @return a BigInteger with the real value of the EncryptedValue.
	 */
	public BigInteger decrypt(BigInteger secretKey) {
		// Log.d("EncryptedValue", "Desencriptacion");
		BigInteger anillo = this.getAnillo();

		BigInteger ret = this.y1.modPow(secretKey.negate(), anillo);
		ret = ret.multiply(this.y2);
		ret = ret.mod(anillo);
		return solveExponent(ret, this.n, this.s);
	}

	/**
	 * Internal method to solve exponent to decrypt value.
	 */
	private BigInteger solveExponent(BigInteger wm, BigInteger n, int s) {
		BigInteger t1, t2, i = BigInteger.ZERO;
		for (int j = 1; j < s + 1; j++) {
			t1 = MathUtils.D(n, wm.mod(n.pow(j + 1)));
			t2 = i;
			for (int k = 2; k < j + 1; k++) {
				i = i.subtract(BigInteger.ONE);
				t2 = (t2.multiply(i)).mod(n.pow(j));
				t1 = t1.subtract((t2.multiply(n.pow(k - 1)))
						.divide(new BigInteger(MathUtils.factorial(k) + "")));
			}
			i = t1;
		}
		return i;
	}

	/**
	 * Internal method to get the value of the algebraical ring
	 */
	private BigInteger getAnillo() {
		return this.n.pow(this.s + 1);
	}

}
