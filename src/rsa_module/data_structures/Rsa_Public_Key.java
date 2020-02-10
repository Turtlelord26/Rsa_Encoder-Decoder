/**
 * 
 */
package rsa_module.data_structures;

import java.math.BigInteger;

/**
 * A Class to represent an RSA Public Key, containing a modulus value and exponent value implemented with BigInteger.
 * @author James Talbott
 */
public class Rsa_Public_Key extends Rsa_Key{
	
	/**
	 * An identifier for the key, allowing it to be stored and searched.
	 */
	private String ID;
	
	/**
	 * Standard constructor builds a key from its component values.
	 * @param modulus The new key's modulus.
	 * @param exponent The new key's exponent.
	 */
	public Rsa_Public_Key(BigInteger modulus, BigInteger exponent, String ID) {
		super(modulus, exponent);
		this.ID = ID;
	}
	
	/**
	 * Alternate constructor for reading a key from a file.
	 * @param key The text form of the key, formatted "ID:modulus,exponent".
	 */
	public Rsa_Public_Key(String key) {
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
		if (o instanceof Rsa_Public_Key) {
			Rsa_Public_Key key = (Rsa_Public_Key) o;;
			return this.equals(key) && getID().equals(key.getID());
		} else {
			return false;
		}
	}
}
