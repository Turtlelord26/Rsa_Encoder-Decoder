package rsa_module;

import java.math.BigInteger;

import rsa_module.data_structures.Rsa_Public_Key;

/**
 * Helper class for RsaModule to generate ciphertext given plaintext and keys.
 * Designed to be used in a single line as cipherText = new RsaEncoder(args).getCipherText()
 * Individual objects intended to be lightweight but one-use.
 * @author James Talbott
 */
public class Rsa_Encoder extends Rsa_Encryption_Operator{

	private Rsa_Public_Key publicKey;

	private String plainText;

	private String cipherText;
	

	public Rsa_Encoder(Rsa_Public_Key publicKey, String plainText) {
		this.publicKey = publicKey;
		this.plainText = plainText;
		this.cipherText = encryptNumericText(convertPlainTextToNumericText());
	}
	
	public String getCipherText() {
		return cipherText;
	}
	
	private String convertPlainTextToNumericText() {
		String[] numericCharacters = convertPlainCharactersToNumericCharacters(plainText);
		int maximumNumericUnitLength = length_of_numeric_characters;
		numericCharacters = fill_out_units_to_constant_length(numericCharacters, maximumNumericUnitLength);
		return concatenate_units_into_text(numericCharacters);
	}
	
	private String[] convertPlainCharactersToNumericCharacters(String plainText) {
		String[] numericCharacters = new String[plainText.length()];
		for (int index = 0; index < plainText.length(); index++) {
			numericCharacters[index] = convertCharToNumber(plainText.charAt(index));
		}
		return numericCharacters;
	}
	
	private String convertCharToNumber(char character) {
		return Integer.valueOf((int) character).toString();
	}
	
	private String encryptNumericText(String numericText) {
		int lengthOfCipherUnits = publicKey.getModulus().toString().length(); 
		String[] cipherUnits = breakNumericTextIntoCipherUnits(numericText, lengthOfCipherUnits - 1); //Length minus 1 is necessary to ensure that the unit pre-encryption is always smaller than the modulus
		cipherUnits = encryptCipherUnits(cipherUnits);
		cipherUnits = fill_out_units_to_constant_length(cipherUnits, lengthOfCipherUnits);
		cipherText = concatenate_units_into_text(cipherUnits);
		return cipherText.toString();
	}
	
	private String[] breakNumericTextIntoCipherUnits(String numericText, int lengthOfCipherUnits) {
		int numericTextLength = numericText.length();
		String[] cipherUnits = new String[determineNumberOfCipherUnits(numericText, lengthOfCipherUnits)];
		for (int index = 0; index < cipherUnits.length; index ++) {
			cipherUnits[index] = numericText.substring(index * lengthOfCipherUnits, Math.min((index + 1) * lengthOfCipherUnits, numericTextLength));
		}
		return cipherUnits;
	}
	
	private int determineNumberOfCipherUnits(String numericText, int lengthOfCipherUnits) {
		int numberOfCipherUnits = numericText.length() / lengthOfCipherUnits;
		if (numericText.length() % lengthOfCipherUnits > 0) {
			numberOfCipherUnits++;
		}
		return numberOfCipherUnits;
	}
	
	private String[] encryptCipherUnits(String[] cipherUnits) {
		BigInteger numericUnit, encryptedUnit;
		String[] encryptedUnits = new String[cipherUnits.length];
		for (int index = 0; index < cipherUnits.length; index++) {
			numericUnit = new BigInteger(cipherUnits[index]);
			encryptedUnit = numericUnit.modPow(publicKey.getExponent(), publicKey.getModulus());
			encryptedUnits[index] = encryptedUnit.toString();
		}
		return encryptedUnits;
	}
}
