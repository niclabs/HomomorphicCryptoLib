package cl.NicLabs.OtherCryptoModels;

import java.math.BigInteger;
import java.security.Key;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AESModel {
	private static Key key;
	private static String encryptationMode = "AES";
	private static byte[] keyValue = new byte[] { 'T', 'h', 'e', 'B', 'e', 's',
			't', 'S', 'e', 'c', 'r', 'e', 't', 'K', 'e', 'y' };

	public AESModel() throws Exception {
		AESModel.key = generateKey();
	}

	public byte[] encrypt(BigInteger value) throws Exception {
		byte[] pureData = value.toByteArray();
		Cipher c = Cipher.getInstance(encryptationMode);
		c.init(Cipher.ENCRYPT_MODE, key);
		byte[] encVal = c.doFinal(pureData);
		return encVal;
	}

	public BigInteger decrypt(byte[] encryptedData) throws Exception {
		Cipher c = Cipher.getInstance(encryptationMode);
		c.init(Cipher.DECRYPT_MODE, key);
		byte[] decryptedValue = c.doFinal(encryptedData);
		return new BigInteger(decryptedValue);
	}

	private static Key generateKey() throws Exception {
		Key key = new SecretKeySpec(keyValue, encryptationMode);
		return key;
	}
}
