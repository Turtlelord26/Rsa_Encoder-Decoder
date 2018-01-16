package rsaModule;

import java.math.BigInteger;

/**
 * Helper class for RsaModule to generate ciphertext given plaintext and keys.
 * Designed to be used in a single line as cipherText = new RsaEncoder(args).getCipherText()
 * Individual objects intended to be lightweight but one-use.
 * @author James Talbott
 */
public class RsaEncoder {

	/**
	 * The Public Key of the intended recipient of a message.
	 */
	private RsaPublicKey publicKey;
	
	/**
	 * The input message to be ciphered.
	 */
	private String plainText;
	
	/**
	 * Storage field for the calculated cipher text.
	 */
	private String cipherText;
	
	/**
	 * Constructor takes a public key and a message, encodes the message, and stores it.
	 * @param publicKey
	 * @param privateKey
	 * @param plainText
	 */
	public RsaEncoder(RsaPublicKey publicKey, String plainText) {
		this.publicKey = publicKey;
		this.plainText = plainText;
		this.cipherText = encodePaddedText(padNumericText(textToNumber()));
	}
	
	/**
	 * Getter method to retrieve the calculated ciphertext.
	 * @return The input plaintext, encoded with the input keys.
	 */
	public String getCipherText() {
		return cipherText;
	}
	
	/**
	 * Method translates the human-readable input message into a computer-readable numeric message.
	 * Length enforcement maps a four-digit integer to each character.
	 * @return A computer-readable nuemricText.
	 */
	private String textToNumber() {
		StringBuilder numericText = new StringBuilder();
		Integer numChar;
		for (int i = 0; i < plainText.length(); i++) {
			numChar = new Integer((int) plainText.charAt(i));
			if (numChar >= 0 && numChar < 10) {//One-digit numChar
				numericText.append("000");
				numericText.append(numChar.toString());
			} else if (numChar >= 10 && numChar < 100) {//Two-digit numChar
				numericText.append("00");
				numericText.append(numChar.toString());
			} else if (numChar >= 100 && numChar < 1000) {//Three-digit numChar
				numericText.append("0");
				numericText.append(numChar.toString());
			} else if (numChar >= 1000) {//Four digit behavior
				numericText.append(numChar.toString());
			} else if (numChar >= 10000) {//Five+ digit behavior
				System.out.println("Error: five digit character encountered.");
				//Remember to alter Decoder too if this is flagged.
			} else {//negative numChar is anomalous
				System.out.println("Error: Unexpected behavior during text numerization.");
			}
		}
		return numericText.toString();
	}
	
	/**
	 * Method takes a numericText and pads it.
	 * @param numericText A computer-readable translation of the originally input plainText.
	 * @return The input message, now padded.
	 */
	private String padNumericText(String numericText) {
		//TODO Padding unimplemented
		String paddedText = numericText;
		return paddedText;
	}
	
	/**
	 * Method applies the input public key to encrypt the padded message, and returns it.
	 * @param paddedText The padded message.
	 * @return An encrypted message that can be decrypted with the recipient's private key.
	 */
	private String encodePaddedText(String paddedText) {
		StringBuilder cipherText = new StringBuilder();
		int index = 0;
		int textLen = paddedText.length();
		BigInteger unit;
		String unitStr;
		int unitLen = publicKey.getModulus().toString().length() - 1;
		//Length minus 1 ensures the unit is smaller than the modulus
		while (index < textLen) {
			int end = Math.min(index + unitLen, textLen);
			unitStr = paddedText.substring(index, end);
			index += unitLen;
			unit = new BigInteger(unitStr);
			
			//Encode the unit
			unit = unit.modPow(publicKey.getExponent(), publicKey.getModulus());
			unitStr = unit.toString();
			
			//Enforce length of encoded unit
			if (end != textLen) {
				while (unitStr.length() < 26) {
					unitStr = "0" + unitStr;
				}
			}
			
			//Append to cipherText
			cipherText.append(unitStr);
		}
		return cipherText.toString();
	}
}
