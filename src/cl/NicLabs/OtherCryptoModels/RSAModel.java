package cl.NicLabs.OtherCryptoModels;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;

public class RSAModel {
	static KeyPair keyPair;

	public RSAModel(int bitLenght) throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(bitLenght);
		RSAModel.keyPair = keyGen.genKeyPair();
	}

	public byte[] encrypt(BigInteger value) throws Exception {
		byte[] plainData = value.toByteArray();
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
		byte[] x = cipher.doFinal(plainData);
		return x;
	}

	public BigInteger decrypt(byte[] value) throws Exception {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
		byte[] y = cipher.doFinal(value);
		return new BigInteger(1,y);
	}
}
