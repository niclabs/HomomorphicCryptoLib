package cl.NicLabs.HomomorphicEncryption;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.math.BigInteger;
import java.security.SecureRandom;

//import android.util.Log;

public class EncryptionParameters implements Serializable {

	private static final long serialVersionUID = 1L;
	public int bitLength;
	public int requiredBitLength;

	@SuppressWarnings("unused")
	private BigInteger p;
	@SuppressWarnings("unused")
	private BigInteger q;
	public BigInteger n;
	public BigInteger g;
	public int s = 1;
	private BigInteger secretKey;
	private BigInteger publicKey;

	// log de construccion
	public int attemptsPrimeFactors;
	public int attemptsN;
	public long constructionTime;

	/**
	 * Constructor for an instance of EncryptionParameters. The algebraically
	 * structure its a ring in Z*_N^(S+1)
	 * 
	 * @param lengthOfN
	 *            the value of the minimum length in bits for the N parameter.
	 * @param s
	 *            the value of the S parameter.
	 */
	public EncryptionParameters(int lengthOfN, int s) {
		long tAux = System.currentTimeMillis();
		requiredBitLength = lengthOfN;
		attemptsN = attemptsPrimeFactors = 0;
		// Log.d("EncryptionParameters", "Construyendo Parametros...");
		BigInteger p, q, N;
		SecureRandom rnd;

		while (true) {
			++attemptsN;
			p = buildPrimeNumber(lengthOfN / 2);
			// Log.d("EncryptionParameters", "Valor p(" + p.bitLength() + "): "
			// + p);
			q = buildPrimeNumber(lengthOfN / 2);
			// Log.d("EncryptionParameters", "Valor q(" + q.bitLength() + "): "
			// + q);

			N = p.multiply(q);
			// Log.d("EncryptionParameters", "Valor n: " + N);
			if (lengthOfN < N.bitLength()
					&& N.bitLength() < (int) (1.5 * lengthOfN)) {
				// Log.d("EncryptionParameters", "N valido (" + N.bitLength()
				// + ")");
				bitLength = N.bitLength();
				break;
			}
			// else
			// Log.d("EncryptionParameters", "Errores en los primos ("
			// + lengthOfN + "<" + N.bitLength() + "<"
			// + (int) (1.5 * lengthOfN)
			// + "), repetir construccion...");
		}
		this.p = p;
		this.q = q;
		this.n = N;
		this.s = s;

		// Construccion de g
		// Log.d("EncryptionParameters", "Construccion de g");
		rnd = new SecureRandom();
		BigInteger i;
		BigInteger e = new BigInteger(N.pow(this.s).bitLength(), rnd);
		while (true) {
			rnd = new SecureRandom();
			i = new BigInteger(this.getAnillo().bitLength(), rnd);
			if (i.gcd(this.getAnillo()).compareTo(BigInteger.ONE) == 0) {
				break;
			}
		}
		this.g = ((N.add(BigInteger.ONE)).modPow(e, this.getAnillo())
				.multiply(i)).mod(this.getAnillo());

		// Construccion Claves
		buildKeys();
		constructionTime = System.currentTimeMillis() - tAux;
		// Log.d("EncryptionParameters", "Parametros Construidos");
	}

	/**
	 * 
	 * @return a BigInteger with the SecretKey value
	 */
	public BigInteger getSecretKey() {
		return this.secretKey;
	}

	/**
	 * 
	 * @return a BigInteger with the PublictKey value
	 */
	public BigInteger getPublicKey() {
		return this.publicKey;
	}

	private BigInteger buildPrimeNumber(int minLength) {
		// Log.d("EncryptionParameters", "Buscar primo de largo minimo "
		// + minLength);
		BigInteger prim, res = null;
		int primeNumberLength = 0;
		int test = 0;
		while (true) {
			++attemptsPrimeFactors;
			// if ((++test) % 100 == 0)
			// Log.d("EncryptionParameters", test + " intentos buscando primo");
			SecureRandom rnd = new SecureRandom();
			while (primeNumberLength < minLength) {
				primeNumberLength = rnd.nextInt((int) (1.5 * minLength));
			}
			rnd = new SecureRandom();
			prim = BigInteger.probablePrime(primeNumberLength, rnd);
			res = (new BigInteger("2").multiply(prim)).add(BigInteger.ONE);
			if (res.isProbablePrime(7))
				break;
		}
		return res;
	}

	private void buildKeys() {
		SecureRandom rnd = new SecureRandom();
		this.secretKey = new BigInteger(this.getAnillo().bitLength(), rnd);
		this.publicKey = this.g.modPow(this.secretKey, this.getAnillo());
	}

	public BigInteger getAnillo() {
		return this.n.pow(this.s + 1);
	}

	public String toString() {
		String ret = "Parametros: \n";
		ret += "n: " + this.n + "\n";
		ret += "g: " + this.g + "\n";
		ret += "s: " + this.s + "\n";
		ret += "n^(s+1): " + this.getAnillo() + "\n";
		ret += "PublicKey: " + this.getPublicKey() + "\n";
		ret += "SecretKey: " + this.getSecretKey() + "\n";
		ret += "Largo Solicitado: " + this.requiredBitLength + "\n";
		ret += "Largo Generado: " + this.bitLength + "\n";
		ret += "Primos Intentados: " + this.attemptsPrimeFactors + "\n";
		ret += "N's Intentados: " + this.attemptsN + "\n";
		ret += "tiempo de Construccion (ms): " + this.constructionTime + "\n";
		return ret;
	}

	/**
	 * Makes an HTML representation of the info por an EncryptionParameters
	 * instance.
	 * 
	 * @return a String with the HTML representation.
	 */
	public String toHtml() {
		String ret = "";
		ret += "<b>n</b>: " + this.n + "<br>";
		ret += "<br>";
		ret += "<b>g</b>: " + this.g + "<br>";
		ret += "<br>";
		ret += "<b>s</b>: " + this.s + "<br>";
		ret += "<br>";
		ret += "<b>n<sup>s+1</sup></b>: " + this.getAnillo() + "<br>";
		ret += "<br>";
		ret += "<b>Public<sub>key</sub></b>: " + this.getPublicKey() + "<br>";
		ret += "<br>";
		ret += "<b>Secret<sub>key</sub></b>: " + this.getSecretKey() + "<br>";
		ret += "<br>";
		ret += "<b>Largo Solicitado</b>: " + this.requiredBitLength + "<br>";
		ret += "<br>";
		ret += "<b>Largo Generado</b>: " + this.bitLength + "<br>";
		ret += "<br>";
		ret += "<b>Primos Intentados</b>: " + this.attemptsPrimeFactors
				+ "<br>";
		ret += "<br>";
		ret += "<b>N's Intentados</b>: " + this.attemptsN + "<br>";
		ret += "<br>";
		ret += "<b>Tiempo de Construccion (ms)</b>: " + this.constructionTime
				+ "<br>";
		return ret;
	}

	/**
	 * 
	 * @param fullPathFileName
	 *            String with the full path directory name + file name with the
	 *            selected name. you must have permission to write in the
	 *            selected location.
	 * @throws IOException
	 *             In case of haven't permission to write the selected location.
	 */
	public void saveParam(String fullPathFileName) throws IOException {
		ObjectOutputStream os = new ObjectOutputStream(new FileOutputStream(
				fullPathFileName));
		os.writeObject(this);
		os.close();
	}

	/**
	 * 
	 * @param fullPathFileName
	 *            String with the full path directory name + file name with the
	 *            selected name. you must have permission to read in the
	 *            selected location.
	 * @return The representation of the EncriptedValue as an object
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	static public EncryptionParameters loadParam(String fullPathFileName)
			throws IOException, ClassNotFoundException {
		ObjectInputStream ois = new ObjectInputStream(new FileInputStream(
				fullPathFileName));
		EncryptionParameters p = (EncryptionParameters) ois.readObject();
		ois.close();
		return p;
	}

}
