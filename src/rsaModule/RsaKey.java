/**
 * 
 */
package rsaModule;

import java.math.BigInteger;

/**
 * A Class to represent an RSA Key, containing a modulus value and exponent value implemented with BigInteger.
 * Public and Private keys extend this abstract base.
 * @author James Talbott
 */
public abstract class RsaKey {

	/**
	 * Field stores a BigInteger representing the modulus of this key.
	 */
	private BigInteger modulus;
	
	/**
	 * Field stores a BigInteger representing the exponent of this key.
	 */
	private BigInteger exponent;
	
	/**
	 * Standard constructor builds a key from its component values.
	 * @param modulus The new key's modulus.
	 * @param exponent The new key's exponent.
	 */
	public RsaKey(BigInteger modulus, BigInteger exponent) {
		this.modulus = modulus;
		this.exponent = exponent;
	}
	
	/**
	 * Alternate constructor builds a key from its String representation, to facilitate file reading.
	 * @param key The text form of the key, formatted "modulus,exponent"
	 */
	public RsaKey(String key) {
		this.modulus = new BigInteger(key.substring(key.indexOf(':') + 1, key.indexOf(',')));
		this.exponent = new BigInteger(key.substring(key.indexOf(',') + 1));
	}
	
	/**
	 * Getter for the modulus field.
	 * @return This key's modulus value.
	 */
	public BigInteger getModulus() {
		return modulus;
	}
	
	/**
	 * Getter for the exponent field.
	 * @return This key's exponent value.
	 */
	public BigInteger getExponent() {
		return exponent;
	}
}
