/**
 * 
 */
package rsa_module.data_structures;

import java.math.BigInteger;

/**
 * A Class to represent an RSA Private Key, containing a modulus value and exponent value implemented with BigInteger.
 * @author James Talbott
 */
public class Rsa_Private_Key extends Rsa_Key {
	
	public Rsa_Private_Key(BigInteger modulus, BigInteger exponent) {
		super(modulus, exponent);
	}
	
	public Rsa_Private_Key(String key) {
		super(key);
	}
	
	@Override
	public String toString() {
		return getModulus().toString() + "," + getExponent().toString();
	}
	
	@Override
	public boolean equals(Object o) {
		if (o instanceof Rsa_Private_Key) {
			return this.equals((Rsa_Private_Key) o);
		} else {
			return false;
		}
	}
}
