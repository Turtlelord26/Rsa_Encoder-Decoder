/**
 * 
 */
package rsa_module.data_structures;

import java.math.BigInteger;

public abstract class Rsa_Key {

	private BigInteger modulus;
	
	private BigInteger exponent;
	
	public Rsa_Key(BigInteger modulus, BigInteger exponent) {
		this.modulus = modulus;
		this.exponent = exponent;
	}
	
	public Rsa_Key(String key) {
		this.modulus = new BigInteger(key.substring(key.indexOf(':') + 1, key.indexOf(',')));
		this.exponent = new BigInteger(key.substring(key.indexOf(',') + 1));
	}
	
	public BigInteger getModulus() {
		return modulus;
	}
	
	public BigInteger getExponent() {
		return exponent;
	}
	
	@Override
	public boolean equals(Object o) {
		if (o instanceof Rsa_Key) {
			return this.equals((Rsa_Key) o);
		} else {
			return false;
		}
	}
	
	public boolean equals(Rsa_Key key) {
		return getModulus().equals(key.getModulus()) && 
				getExponent().equals(key.getExponent());
	}
}
