package rsaModule;

import java.math.BigInteger;

/**
 * Helper class for RsaModule to generate plaintext given ciphertext and keys.
 * Designed to be used in a single line as plainText = new RsaDecoder(args).getPlainText()
 * Individual objects intended to be lightweight but one-use.
 * @author James Talbott
 */
public class RsaDecoder {
	
	/**
	 * The Private Key of the user decrypting messages.
	 */
	private RsaKey privateKey;
	
	/**
	 * Storage field for the calculated plain text.
	 */
	private String plainText;
	
	/**
	 * The input encrypted text, which is to be deciphered.
	 */
	private String cipherText;
	
	/**
	 * Constructor takes a private key and encoded message, calculates the original message, and then stores it.
	 * @param publicKey
	 * @param privateKey
	 * @param cipherText
	 */
	public RsaDecoder(RsaKey privateKey, String cipherText) {
		this.privateKey = privateKey;
		this.cipherText = cipherText;
		this.plainText = numberToText(depadPaddedText(decodeCipherText()));
	}
	
	/**
	 * Getter method for the deciphered plaintext.
	 * @return The deciphered message.
	 */
	public String getPlainText() {
		return plainText;
	}
	
	/**
	 * Method applies the supplied private key to decode the cipher text into padded text.
	 * @return The decrypted but still padded message.
	 */
	private String decodeCipherText() {
		StringBuilder paddedText = new StringBuilder();
		int index = 0;
		int textLen = cipherText.length();
		BigInteger unit;
		String unitStr;
		int unitLen = privateKey.getModulus().toString().length();
		//Length is not minus 1 here, as encoded length 25 units will be length 26, for a length 26 modulus.
		while (index < textLen) {
			int end = Math.min(index + unitLen, textLen);
			unitStr = cipherText.substring(index, end);
			index += unitLen;
			unit = new BigInteger(unitStr);
			
			//Decode the unit
			unit = unit.modPow(privateKey.getExponent(), privateKey.getModulus());
			unitStr = unit.toString();
			
			//Restore leading zeroes, as we know exactly how long each unit should be from the encrypting process.
			if (end != textLen) {
				while (unitStr.length() < 25) {
					unitStr = "0" + unitStr;
				}
			} else {
				int numLeadingZeroes = (4 - ((paddedText.length() + unitStr.length()) % 4)) % 4;
				for (int i = 0; i < numLeadingZeroes; i++) {
					unitStr = "0" + unitStr;
				}
			}
			
			//Append to paddedText
			paddedText.append(unitStr);
		}
		return paddedText.toString();
	}
	
	/**
	 * Method to depad the message, returning it to its numeric state.
	 * @param paddedText The decrypted, padded message.
	 * @return The original message in numeric form.
	 */
	private String depadPaddedText(String paddedText) {
		//TODO Padding unimplemented
		String numericText = paddedText;
		return numericText;
	}
	
	/**
	 * Method to translate the numeric text into human-readable text, and returns it.
	 * @param numericText The computer-readable message, decrypted and depadded.
	 * @return The sender's original, unencrypted, unpadded, and readable message.
	 */
	private String numberToText(String numericText) {
		int len = numericText.length();
		StringBuilder plainText = new StringBuilder();
		int index = 0;
		String padUnit;
		while (index < len) {
			padUnit = numericText.substring(index, index + 4);
			plainText.append((char) (Integer.parseInt(padUnit)));
			index += 4;
		}
		return plainText.toString();
	}
}
