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
	
	private Boolean random_numbers_are_not_prime = true;
	
	private static final int minimum_first_prime_bit_length = 41;
	
	private static final int maximum_first_prime_bit_length = 51;
	
	private static final int minimum_prime_bit_length_difference = 5;
	
	private static final int maximum_prime_bit_length_difference = 10;
	
	private static final BigInteger public_key_exponent = new BigInteger("65537");
	
	public Key_Maker() {
		while (random_numbers_are_not_prime) {
			generate_new_keys();
		}
		new_keys = new Key_Set(public_key, private_key);
	}
	
	private void generate_new_keys() {
		generate_random_large_primes();
		
		//Calculate RSA significant values.
		BigInteger modulus = p.multiply(q);
		BigInteger totient = calculate_totient(p, q);
		BigInteger private_key_exponent = calculate_private_key_exponent(totient);
		
		store_new_keys_to_fields(modulus, private_key_exponent);
	}
	
	private void generate_random_large_primes() {
		int bit_length_p = random_number(minimum_first_prime_bit_length, maximum_first_prime_bit_length);
		p = BigInteger.probablePrime(bit_length_p, new_random_generator());
		q = generate_q_from_p(p, bit_length_p);
	}
	
	private int random_number(int minimum, int maximum) {
		return Random_Number_Generator.generate_random_int(minimum, maximum);
	}
	
	private Random new_random_generator() {
		return Random_Number_Generator.generate_new_random_generator();
	}
	
	private BigInteger generate_q_from_p(BigInteger p, int bit_length_p) {
		int bit_length_q = random_bit_length_within_range_of(bit_length_p);
		BigInteger q = BigInteger.probablePrime(bit_length_q, new_random_generator());
		return q;
	}
	
	private int random_bit_length_within_range_of(int bit_length_p) {
		return bit_length_p + random_number(minimum_prime_bit_length_difference, maximum_prime_bit_length_difference);
	}
	
	private BigInteger calculate_totient(BigInteger p, BigInteger q) {
		BigInteger p_minus_one = p.subtract(BigInteger.ONE);
		BigInteger q_minus_one = q.subtract(BigInteger.ONE);
		BigInteger totient = (p_minus_one.multiply(q_minus_one)).divide(p_minus_one.gcd(q_minus_one));
		return totient;
	}
	
	//Extended Euclidean Algorithm
	private BigInteger calculate_private_key_exponent(BigInteger totient) {
		BigInteger r1 = totient;
		BigInteger t1 = BigInteger.ZERO;
		BigInteger r2 = public_key_exponent;
		BigInteger t2 = BigInteger.ONE;
		BigInteger r3 = r1.remainder(r2);
		BigInteger q = r1.divide(r2);
		BigInteger t3 = t1.subtract(q.multiply(t2));
		while (not_zero(r3)) {
			r1 = r2;
			t1 = t2;
			r2 = r3;
			t2 = t3;
			q = r1.divide(r2);
			r3 = r1.remainder(r2);
			t3 = t1.subtract(q.multiply(t2));
		}
		check_p_and_q_are_prime(t3, totient);
		return t2_modulus_totient(t2, totient);
	}
	
	private boolean not_zero(BigInteger i) {
		return ! i.equals(BigInteger.ZERO); 
	}
	
	private void check_p_and_q_are_prime(BigInteger t3, BigInteger totient) {
		if (t3.equals(totient)) {
			random_numbers_are_not_prime = false;
		}
	}
	
	private BigInteger t2_modulus_totient(BigInteger t2, BigInteger totient) {
		if (t2.compareTo(BigInteger.ZERO) < 0) {
			return totient.add(t2);
		} else {
			return t2;
		}
	}
	
	private void store_new_keys_to_fields(BigInteger modulus, BigInteger private_key_exponent) {
		public_key = new Rsa_Public_Key(modulus, public_key_exponent, "self");
		private_key = new Rsa_Private_Key(modulus, private_key_exponent);
	}
	
	public Key_Set getNewKeys() {
		return new_keys;
	}
}
