package rsa_module.key_making;

import java.math.BigInteger;
import java.util.Random;

import rsa_module.data_structures.Key_Set;
import rsa_module.data_structures.Rsa_Private_Key;
import rsa_module.data_structures.Rsa_Public_Key;
import rsa_module.utility.Random_Number_Generator;

public class Key_Maker {
	
	private Rsa_Public_Key public_key;
	
	private Rsa_Private_Key private_key;
	
	private BigInteger p;
	
	private BigInteger q;
	
	private Key_Set new_keys;
	
	private Boolean randomNumbersAreNotPrime = true;
	
	private static final int minimum_first_prime_bit_length = 41;
	
	private static final int range_for_first_prime_bit_length = 10;
	
	private static final int minimumPrimeBitLengthDifference = 5;
	
	private static final int maximumPrimeBitLengthDifference = 10;
	
	private static final BigInteger publicKeyExponent = new BigInteger("65537");
	
	public Key_Maker() {
		while (randomNumbersAreNotPrime) {
			generate_new_keys();
		}
		new_keys = new Key_Set(public_key, private_key);
	}
	
	private void generate_new_keys() {
		generate_random_large_primes();
		
		//Calculate RSA significant values.
		BigInteger modulus = p.multiply(q);
		BigInteger totient = calculate_totient(p, q);
		BigInteger privateKeyExponent = calculate_private_key_exponent(totient);
		
		//Create RsaKey objects and store to fields
		public_key = new Rsa_Public_Key(modulus, publicKeyExponent, "self");
		private_key = new Rsa_Private_Key(modulus, privateKeyExponent);
	}
	
	private void generate_random_large_primes() {
		int bitLengthP = minimum_first_prime_bit_length + (int) (range_for_first_prime_bit_length * random_number(1));
		p = BigInteger.probablePrime(bitLengthP, new_random_generator());
		q = generate_q_from_p(p, bitLengthP);
	}
	
	private double random_number(double scale) {
		return Random_Number_Generator.generate_random_double(scale);
	}
	
	private Random new_random_generator() {
		return Random_Number_Generator.generate_new_random_generator();
	}
	
	private BigInteger generate_q_from_p(BigInteger p, int bitLengthP) {
		int bitLengthQ = apply_random_offset_with_minimum_separation(bitLengthP);
		BigInteger q = BigInteger.probablePrime(bitLengthQ, new_random_generator());
		return q;
	}
	
	private int apply_random_offset_with_minimum_separation(int bitLengthP) {
		int bitLengthQ = bitLengthP;
		while (Math.abs(bitLengthQ - bitLengthP) < minimumPrimeBitLengthDifference) {
			bitLengthQ = bitLengthP - (maximumPrimeBitLengthDifference / 2) + (int) (maximumPrimeBitLengthDifference * random_number(1));
		}
		return bitLengthQ;
	}
	
	private BigInteger calculate_totient(BigInteger p, BigInteger q) {
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
	private BigInteger calculate_private_key_exponent(BigInteger totient) {
		BigInteger r1 = totient;
		BigInteger t1 = BigInteger.ZERO;
		BigInteger r2 = publicKeyExponent;
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
		if (t3.equals(totient)) {
			randomNumbersAreNotPrime = false;
		}
		if (t2.compareTo(BigInteger.ZERO) < 0) {
			return totient.add(t2);
		} else {
			return t2;
		}
	}
	
	public Key_Set getNewKeys() {
		return new_keys;
	}
}
