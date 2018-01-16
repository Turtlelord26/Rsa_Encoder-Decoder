/**
 * 
 */
package rsaModule;

import java.math.BigInteger;

/**
 * A Class to represent an RSA Private Key, containing a modulus value and exponent value implemented with BigInteger.
 * @author James Talbott
 */
public class RsaPrivateKey extends RsaKey {
	
	/**
	 * Standard constructor builds a key from its component values.
	 * @param modulus The new key's modulus.
	 * @param exponent The new key's exponent.
	 */
	public RsaPrivateKey(BigInteger modulus, BigInteger exponent) {
		super(modulus, exponent);
	}

	/**
	 * Alternate constructor for reading a key from a file.
	 * @param key The text form of the key, formatted "modulus,exponent".
	 */
	public RsaPrivateKey(String key) {
		super(key);
	}
	
	/**
	 * toString is overridden with specific syntax to support file read operations.
	 */
	@Override
	public String toString() {
		return getModulus().toString() + "," + getExponent().toString();
	}
	
	/**
	 * Equals implementation checks equality of stored fields.
	 */
	@Override
	public boolean equals(Object o) {
		if (o instanceof RsaPrivateKey) {
			RsaPrivateKey key = (RsaPrivateKey) o;
			return getModulus().equals(key.getModulus()) && 
					getExponent().equals(key.getExponent());
		} else {
			return false;
		}
	}
}
