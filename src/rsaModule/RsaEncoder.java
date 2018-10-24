package rsaModule;

import java.math.BigInteger;

/**
 * Helper class for RsaModule to generate ciphertext given plaintext and keys.
 * Designed to be used in a single line as cipherText = new RsaEncoder(args).getCipherText()
 * Individual objects intended to be lightweight but one-use.
 * @author James Talbott
 */
public class RsaEncoder extends RSAEncryptionOperator{

	private RsaPublicKey publicKey;

	private String plainText;

	private String cipherText;
	

	public RsaEncoder(RsaPublicKey publicKey, String plainText) {
		this.publicKey = publicKey;
		this.plainText = plainText;
		this.cipherText = encryptNumericText(convertPlainTextToNumericText());
	}
	
	public String getCipherText() {
		return cipherText;
	}
	
	private String convertPlainTextToNumericText() {
		String[] numericCharacters = convertPlainCharactersToNumericCharacters(plainText);
		int maximumNumericUnitLength = lengthOfNumericCharacters;
		numericCharacters = fillOutUnitsToConstantLength(numericCharacters, maximumNumericUnitLength);
		return concatenateUnitsIntoText(numericCharacters);
	}
	
	private String[] convertPlainCharactersToNumericCharacters(String plainText) {
		String[] numericCharacters = new String[plainText.length()];
		for (int index = 0; index < plainText.length(); index++) {
			numericCharacters[index] = convertCharToNumber(plainText.charAt(index));
		}
		return numericCharacters;
	}
	
	private String convertCharToNumber(char character) {
		return new Integer((int) character).toString();
	}
	
	private String encryptNumericText(String numericText) {
		int lengthOfCipherUnits = publicKey.getModulus().toString().length(); 
		String[] cipherUnits = breakNumericTextIntoCipherUnits(numericText, lengthOfCipherUnits - 1); //Length minus 1 is necessary to ensure that the unit pre-encryption is always smaller than the modulus
		cipherUnits = encryptCipherUnits(cipherUnits);
		cipherUnits = fillOutUnitsToConstantLength(cipherUnits, lengthOfCipherUnits);
		cipherText = concatenateUnitsIntoText(cipherUnits);
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
