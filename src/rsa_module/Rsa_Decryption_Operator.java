package rsa_module;

import java.math.BigInteger;

import rsa_module.data_structures.Rsa_Key;

/**
 * Helper class for RsaModule to generate plaintext given ciphertext and keys.
 * Designed to be used in a single line as plainText = new RsaDecoder(args).getPlainText()
 * Individual objects intended to be lightweight but one-use.
 * @author James Talbott
 */
public class Rsa_Decryption_Operator extends Rsa_Operator {
	
	private Rsa_Key privateKey;
	
	private String plainText;
	
	private String cipherText;
	
	public Rsa_Decryption_Operator(Rsa_Key privateKey, String cipherText) {
		this.privateKey = privateKey;
		this.cipherText = cipherText;
		this.plainText = convertNumericTextToPlainText(decryptCipherTextintoNumericText());
	}
	
	public String getPlainText() {
		return plainText;
	}
	
	private String decryptCipherTextintoNumericText() {
		int cipherUnitLength = privateKey.getModulus().toString().length();
		String[] cipherUnits = break_text_into_units(cipherText, cipherUnitLength);
		String[] numericUnits = decryptCipherUnits(cipherUnits);
		numericUnits = fillOutDecipheredUnitsToConstantLength(numericUnits, cipherUnitLength - 1);//We used length - 1 during encryption to ensure the units were less than the modulus.
		String numericText = concatenate_units_into_text(numericUnits);
		return numericText;
	}
	
	private String[] decryptCipherUnits(String[] cipherUnits) {
		BigInteger encryptedChar, decryptedChar;
		String[] decryptedUnits = new String[cipherUnits.length];
		for (int index = 0; index < cipherUnits.length; index++) {
			encryptedChar = new BigInteger(cipherUnits[index]);
			decryptedChar = encryptedChar.modPow(privateKey.getExponent(), privateKey.getModulus());
			decryptedUnits[index] = decryptedChar.toString();
		}
		return decryptedUnits;
	}
	
	protected String[] fillOutDecipheredUnitsToConstantLength(String[] numericUnits, int cipherUnitsLength) {
		int lastUnitIndex = numericUnits.length - 1;
		int lastUnitLength = numericUnits[lastUnitIndex].length();
		numericUnits = fill_out_units_to_constant_length(numericUnits, cipherUnitsLength);
		numericUnits[lastUnitIndex] = adjustLastUnitLength(numericUnits, cipherUnitsLength, lastUnitLength);
		for (int j = 0; j < numericUnits.length; j++) {
		}
		return numericUnits;
	}
	
	private String adjustLastUnitLength(String[] numericUnits, int normalUnitLength, int lastUnitLength) {
		String lastUnit = numericUnits[numericUnits.length - 1];
		int totalLength = (numericUnits.length - 1) * normalUnitLength + lastUnitLength;
		int targetLength = getTargetLengthOfLastUnit(totalLength, lastUnitLength);
		return lastUnit.substring(lastUnit.length() - targetLength);
	}
	
	private int getTargetLengthOfLastUnit(int totalLength, int lastUnitLength) {
		int targetLength = lastUnitLength;
		while (totalLength % length_of_numeric_characters != 0) {
			targetLength++;
			totalLength++;
		}
		return targetLength;
	}
	
	private String convertNumericTextToPlainText(String numericText) {
		String[] numericUnits = break_text_into_units(numericText, length_of_numeric_characters);
		char[] plainUnits = convertNumericCharactersToPlainCharacters(numericUnits);
		return new String(plainUnits);
	}
	
	private char[] convertNumericCharactersToPlainCharacters(String[] numericUnits) {
		char[] plainUnits = new char[numericUnits.length];
		Integer numericCharacter;
		for (int index = 0; index < numericUnits.length; index++) {
			numericCharacter = Integer.valueOf((numericUnits[index]));
			plainUnits[index] = ((char) numericCharacter.intValue());
		}
		return plainUnits;
	}
}
