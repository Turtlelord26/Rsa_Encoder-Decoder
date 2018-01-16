/**
 * 
 */
package rsaModule;

import java.math.BigInteger;

/**
 * A Class to represent an RSA Public Key, containing a modulus value and exponent value implemented with BigInteger.
 * @author James Talbott
 */
public class RsaPublicKey extends RsaKey{
	
	/**
	 * An identifier for the key, allowing it to be stored and searched.
	 */
	private String ID;
	
	/**
	 * Standard constructor builds a key from its component values.
	 * @param modulus The new key's modulus.
	 * @param exponent The new key's exponent.
	 */
	public RsaPublicKey(BigInteger modulus, BigInteger exponent, String ID) {
		super(modulus, exponent);
		this.ID = ID;
	}
	
	/**
	 * Alternate constructor for reading a key from a file.
	 * @param key The text form of the key, formatted "ID:modulus,exponent".
	 */
	public RsaPublicKey(String key) {
		super(key);
		int end = key.indexOf(':');
		if (end >= 0) {
			this.ID = key.substring(0, end);
		} else {
			this.ID = "";
		}
	}
	
	/**
	 * Getter method for the ID field.
	 * @return The stored ID String.
	 */
	public String getID() {
		return ID;
	}
	
	/**
	 * toString is overridden with specific syntax to support file read operations.
	 */
	@Override
	public String toString() {
		return getID() + ":" + getModulus().toString() + "," + getExponent().toString();
	}
	
	/**
	 * Equals implementation checks equality of stored fields.
	 */
	@Override
	public boolean equals(Object o) {
		if (o instanceof RsaPublicKey) {
			RsaPublicKey key = (RsaPublicKey) o;
			return getID().equals(key.getID()) && 
					getModulus().equals(key.getModulus()) && 
					getExponent().equals(key.getExponent());
		} else {
			return false;
		}
	}
}
