package rsaModule;

import java.math.BigInteger;
import java.util.Random;

public class KeyMaker {
	
	private RsaPublicKey publicKey;
	
	private RsaPrivateKey privateKey;
	
	private BigInteger p;
	
	private BigInteger q;
	
	private KeySet newKeys;
	
	private static final int minimumFirstPrimeBitLength = 41;
	
	private static final int rangeForFirstPrimeBitLength = 10;
	
	private static final int minimumPrimeBitLengthDifference = 5;
	
	private static final int maximumPrimeBitLengthDifference = 10;
	
	private static final BigInteger publicKeyExponent = new BigInteger("65537");
	
	public KeyMaker() {
		generateNewKeys();
		newKeys = new KeySet(publicKey, privateKey);
	}
	
	private void generateNewKeys() {
		generateRandomLargePrimes();
		
		//Calculate RSA significant values.
		BigInteger modulus = p.multiply(q);
		BigInteger totient = calculateTotient(p, q);
		BigInteger privateKeyExponent = calculatePrivateKeyExponent(publicKeyExponent, totient);
		
		//Create RsaKey objects and store to fields
		publicKey = new RsaPublicKey(modulus, publicKeyExponent, "self");
		privateKey = new RsaPrivateKey(modulus, privateKeyExponent);
	}
	
	private void generateRandomLargePrimes() {
		int bitLengthP = minimumFirstPrimeBitLength + (int) (rangeForFirstPrimeBitLength * Math.random());//Flag: Insecure RNG usage
		p = BigInteger.probablePrime(bitLengthP, new Random());//Flag: Questionable RNG Usage
		q = generateQFromP(p, bitLengthP);
	}
	
	private BigInteger generateQFromP(BigInteger p, int bitLengthP) {
		int bitLengthQ = applyRandomOffsetWithMinimumSeparation(bitLengthP);
		BigInteger q = BigInteger.probablePrime(bitLengthQ, new Random());//Flag: Questionable RNG Usage
		return q;
	}
	
	private int applyRandomOffsetWithMinimumSeparation(int bitLengthP) {
		int bitLengthQ = bitLengthP;
		while (Math.abs(bitLengthQ - bitLengthP) < minimumPrimeBitLengthDifference) {
			bitLengthQ = bitLengthP - (maximumPrimeBitLengthDifference / 2) + (int) (maximumPrimeBitLengthDifference * Math.random());//Flag: Insecure RNG Usage
		}
		return bitLengthQ;
	}
	
	private BigInteger calculateTotient(BigInteger p, BigInteger q) {
		BigInteger pMinusOne = p.subtract(BigInteger.ONE);
		BigInteger qMinusOne = q.subtract(BigInteger.ONE);
		BigInteger totient = (pMinusOne.multiply(qMinusOne)).divide(pMinusOne.gcd(qMinusOne));
		return totient;
	}
	
	/**
	 * A helper method for generateNewKeys() that calculates a private key exponent from a public key exponent and totient(modulus)
	 * via the Extended Euclidean Algorithm.
	 * @param publicExponent The previously calculated exponent of the public key.
	 * @param totient The totient of the modulus of the public and private key.
	 * @return The exponent of the private key corresponding to the input public key values.
	 */
	private BigInteger calculatePrivateKeyExponent(BigInteger publicExponent, BigInteger totient) {
		BigInteger r1 = totient;
		BigInteger t1 = BigInteger.ZERO;
		BigInteger r2 = publicExponent;
		BigInteger t2 = BigInteger.ONE;
		BigInteger r3 = r1.remainder(r2);
		BigInteger q = r1.divide(r2);
		BigInteger t3 = t1.subtract(q.multiply(t2));
		while (! r3.equals(BigInteger.ZERO)) {
			r1 = r2;
			t1 = t2;
			r2 = r3;
			t2 = t3;
			q = r1.divide(r2);
			r3 = r1.remainder(r2);
			t3 = t1.subtract(q.multiply(t2));
		}
		if (! t3.equals(totient)) {
			System.out.println("t3 Verification Error in Private Key Calculation. Strongly recommend regenerating keys.");
		}
		if (t2.compareTo(BigInteger.ZERO) < 0) {
			return totient.add(t2);
		} else {
			return t2;
		}
	}
	
	protected KeySet getNewKeys() {
		return newKeys;
	}
}
