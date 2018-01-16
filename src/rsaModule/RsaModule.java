package rsaModule;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Random;
import java.util.Scanner;

/**
 * A demonstration program that can encrypt and decrypt text with an implementation of the RSA public key cryptosystem.
 * It uses text files to store keys between sessions, and appends its own current public key to messages it has encrypted, 
 * so that recipients can use it to respond. Manual entry of key data is supported but not failsafed.
 * @author James Talbott
 */
public class RsaModule {
	
	/**
	 * Stores the user's public key to append to outgoing messages.
	 */
	private RsaPublicKey publicKey;
	
	/**
	 * Stores the user's private key for decrypting incoming messages.
	 */
	private RsaPrivateKey privateKey;
	
	/**
	 * Stores the user's list of known public keys for encrypting outgoing messages.
	 */
	private PHashMap<String, RsaPublicKey> addressBook;
	
	/**
	 * Stores a FileRW object for the plaintext.
	 */
	private FileRW plainTextRW;
	
	/**
	 * Stores a FileRW object for the ciphertext.
	 */
	private FileRW cipherTextRW;
	
	/**
	 * Stores a file RW object for the key list.
	 */
	private FileRW keyTextRW;
	
	/**
	 * Constructor creates and stores FileRW objects, and loads data from those files into the appropriate fields.
	 * It then engages the user command input method.
	 * @param plainTextFile A File object for a .txt that stores plaintext.
	 * @param cipherTextFile A File object for a .txt that stores ciphertext.
	 * @param keyTextFile A File object for a .txt that stores keys.
	 */
	public RsaModule(File plainTextFile, File cipherTextFile, File keyTextFile) {
		plainTextRW = new FileRW(plainTextFile);
		cipherTextRW = new FileRW(cipherTextFile);
		keyTextRW = new FileRW(keyTextFile);
		addressBook = new PHashMap<String, RsaPublicKey>();
		String keys[] = keyTextRW.readFile().split(System.lineSeparator());
		if (keys.length < 2) {
			generateNewKeys();
		} else {
			//Load public keys from file into addressBook and RsaKey fields
			this.privateKey = new RsaPrivateKey(keys[0]);
			RsaPublicKey newkey;
			for (int i = 1; i < keys.length; i++) {
				newkey = new RsaPublicKey(keys[i]);
				if (newkey.getID().equals("self")) {
					this.publicKey = newkey;
				}
				addressBook.put(newkey.getID(), newkey);
			}
		}
		commandSwitch();
	}
	
	/**
	 * Main method sets up File objects with expected paths and calls the constructor with them.
	 * @param args Command line inputs not used at program initialization.
	 */
	public static void main(String[] args) {
		File plainTextFile = new File(Paths.get("src/rsaModule/assets/PlainText.txt").toString());
		File cipherTextFile = new File(Paths.get("src/rsaModule/assets/CipherText.txt").toString());
		File keyTextFile = new File(Paths.get("src/rsaModule/assets/KeyText.txt").toString());
		new RsaModule(plainTextFile, cipherTextFile, keyTextFile);
		
	}
	
	/**
	 * Method hosts the command interface by which users activate various supported actions.
	 * Notable inputs include "exit" to terminate the program and "help" for information on further commands.
	 */
	public void commandSwitch() {
		Scanner scan = new Scanner(System.in);
		scan.useDelimiter(System.lineSeparator());
		System.out.println("Enter a command, or type \"help\" for a list of commands.");
		String token = scan.next();
		String command = token.trim();
		while (! command.equals("exit")) {
			/**
			 * Command to encrypt available plaintext with own public key.
			 */
			if (command.equals("encrypt to self")) {
				String plainText = plainTextRW.readFile();
				String cipherText = new RsaEncoder(publicKey, plainText).getCipherText();
				cipherTextRW.writeToFile(cipherText + System.lineSeparator() + publicKey.toString());
				System.out.println("Encrypted text written to cipherText.txt");
			/**
			 * Command to encrypt available plaintext using a stored public key.
			 */
			} else if (command.equals("encrypt")) {
				System.out.println("Enter an ID to select the corresponding public key.");
				token = scan.next();
				command = token.trim();
				RsaPublicKey key = addressBook.get(command);
				if (key == null) {
					System.out.println("Error: entered ID has no matching Key stored.");
				} else {
					System.out.println("Type an identifier to append your public key to this message, or type \"skip\" "
							+ "to skip this step. Identifiers must not contain commas, colons, or newlines.");
					token = scan.next();
					command = token.trim();
					if (! command.equals("skip") && 
							! command.equals("self") && 
							command.indexOf(',') == -1 && 
							command.indexOf(":") == -1 && 
							command.indexOf('\n') == -1) {
						String plainText = plainTextRW.readFile();
						String cipherText = new RsaEncoder(key, plainText).getCipherText();
						RsaPublicKey outgoingKey = new RsaPublicKey(publicKey.getModulus(), publicKey.getExponent(), command);
						cipherTextRW.writeToFile(cipherText + System.lineSeparator() + outgoingKey.toString());
						System.out.println("Encrypted text written to cipherText.txt");
					} else {
						System.out.println("Error: malformed identifer entered. No text encrypted.");
					}
				}
			/**
			 * Command to decrypt available ciphertext from file using our private key.
			 * Naturally, this will only work if the ciphertext was encrypted with our public key.
			 */
			} else if (command.equals("decrypt")) {
				String[] cipherFileText = cipherTextRW.readFile().split(System.lineSeparator());
				String cipherText = cipherFileText[0];
				String plainText = new RsaDecoder(privateKey, cipherText).getPlainText();
				plainTextRW.writeToFile(plainText);
				System.out.println("Decrypted text written to plainText.txt");
				if (cipherFileText.length >= 2 && ! addressBook.containsKey(cipherFileText[1].substring(0, cipherFileText[1].indexOf(':')))) {
					String[] appendedKey = cipherFileText[1].split(":");
					String incomingID = appendedKey[0];
					String[] incomingKey = appendedKey[1].split(",");
					addressBook.put(incomingID, new RsaPublicKey(
							new BigInteger(incomingKey[0]), new BigInteger(incomingKey[1]), incomingID));
					StringBuilder newKeyText = new StringBuilder();
					newKeyText.append("selfPrivate: " + privateKey.toString() + System.lineSeparator());
					for (RsaPublicKey key : addressBook.values()) {
						newKeyText.append(key.toString() + System.lineSeparator());
					}
					keyTextRW.writeToFile(newKeyText.toString());
					System.out.println("Sender key saved with ID: " + incomingID); 
				}
			/**
			 * Command to generate a new public/private key pair for self.
			 */
			} else if (command.equals("generate new keys")) {
				System.out.println("Are you sure? Generating new keys is irreversible and any ciphertext encoded with "
						+ "old keys will be indecipherable.\nType \"Confirm\" (no quotes) to generate new keys.");
				token = scan.next();
				command = token.trim();
				if (command.equals("Confirm")) {
					generateNewKeys();
				} else {
					System.out.println("New keys have not been generated.");
				}
			}
			/**
			 * Help command provides information on other valid commands.
			 */
			else if (command.equals("help")) {
				System.out.println("Accepted commands are:");
				System.out.print("\"encrypt\": Runs the RSA encryption algorithm on the text in assets/PlainText.txt using a key ");
				System.out.print("in assets/KeyText.txt. User will be prompted to select an ID corresponding to the public key ");
				System.out.print("desired for encryption use and then for an ID to append to user's own outgoing public key. ");
				System.out.println("The encrypted message will be written to assets/CipherText.txt.");
				System.out.print("\"encrypt to self\": A shortcut for the encrypt command that encrypts the message with the user's ");
				System.out.println("own public key.");
				System.out.print("\"decrypt\": Runs the RSA decryption algorithm on the text in assets/CipherText.txt using the User's ");
				System.out.print("private key. Decrypted plaintext is stored in assets/PlainText.txt. If a public key is appended to ");
				System.out.println("the message, it will be added to the user's address book if it is not already there.");
				System.out.print("\"generate new keys\": Forces regeneration of the user's private and public keys. ");
				System.out.println("This command has a verify step.");
			}
			else {
				System.out.println("Unrecognized Command.");
			}
			System.out.println("Enter a command, or type \"help\" for a list of commands.");
			token = scan.next();
			command = token.trim();
		}
		scan.close();
		//Program Terminates
	}
	
	/**
	 * Getter method for the current public key.
	 * @return The currently stored RsaPublicKey object.
	 */
	public RsaPublicKey getPublicKey() {
		return publicKey;
	}
	
	/**
	 * Setter method for the public key.
	 * @param publicKey A new RsaPublicKey object.
	 */
	private void setPublicKey(RsaPublicKey publicKey) {
		this.publicKey = publicKey;
	}
	/**
	 * Getter method for the current private key.
	 * @return The currently stored RsaPrivateKey object
	 */
	private RsaPrivateKey getPrivateKey() {
		return privateKey;
	}
	
	/**
	 * Setter method for the private key.
	 * @param privateKey A new RsaPrivateKey object.
	 */
	private void setPrivateKey(RsaPrivateKey privateKey) {
		this.privateKey = privateKey;
	}
	
	/**
	 * Method generates a new public and private key for the user, stores them in the appropriate fields, and saves them to files.
	 */
	public void generateNewKeys() {
		//pick two random large primes
		int bitLengthP = 41 + (int) (10 * Math.random());//Flag: Insecure RNG usage
		BigInteger p = BigInteger.probablePrime(bitLengthP, new Random());//Flag: Questionable RNG Usage
		
		//Generate a near but not identical bitlength for the second prime
		int bitLengthQ = bitLengthP;
		while (Math.abs(bitLengthQ - bitLengthP) < 5) {
			bitLengthQ = bitLengthP - 5 + (int) (10 * Math.random());//Flag: Insecure RNG Usage
		}
		BigInteger q = BigInteger.probablePrime(bitLengthQ, new Random());//Flag: Questionable RNG Usage
		
		//Calculate RSA significant values. m1 signifies 'minus 1'.
		BigInteger modulus = p.multiply(q);
		BigInteger pm1 = p.subtract(BigInteger.ONE);
		BigInteger qm1 = q.subtract(BigInteger.ONE);
		BigInteger totient = (pm1.multiply(qm1)).divide(pm1.gcd(qm1));
		BigInteger pubExpnt = new BigInteger("65537");
		
		//Calculate the private key exponent with helper method
		BigInteger priExpnt = calcPriKeyExpnt(pubExpnt, totient);
		
		//Create RsaKey objects and store to fields
		setPublicKey(new RsaPublicKey(modulus, pubExpnt, "self"));
		setPrivateKey(new RsaPrivateKey(modulus, priExpnt));
		
		//Save to file
		String priKey = "selfPrivate:" + getPrivateKey().toString() + System.lineSeparator();
		addressBook.put("self", getPublicKey());
		keyTextRW.writeToFile(priKey + addressBook.toString());
	}
	
	/**
	 * A helper method for generateNewKeys() that calculates a private key exponent from a public key exponent and totient(modulus)
	 * via the Extended Euclidean Algorithm.
	 * @param pubExpnt The previously calculated exponent of the public key.
	 * @param totient The totient of the modulus of the public and private key.
	 * @return The exponent of the private key corresponding to the input public key values.
	 */
	private BigInteger calcPriKeyExpnt(BigInteger pubExpnt, BigInteger totient) {
		BigInteger r1 = totient;
		BigInteger t1 = BigInteger.ZERO;
		BigInteger r2 = pubExpnt;
		BigInteger t2 = BigInteger.ONE;
		BigInteger r3 = r1.remainder(r2);
		BigInteger q = r1.divide(r2);
		BigInteger t3 = t1.subtract(q.multiply(t2));
		while (! r3.equals(BigInteger.ZERO)) {
			r1 = r2;
			t1 = t2;
			r2 = r3;
			t2 = t3;
			q = r1.divide(r2);
			r3 = r1.remainder(r2);
			t3 = t1.subtract(q.multiply(t2));
		}
		if (! t3.equals(totient)) {
			System.out.println("t3 Verification Error in Private Key Calculation. Strongly recommend regenerating keys.");
		}
		if (t2.compareTo(BigInteger.ZERO) < 0) {
			return totient.add(t2);
		} else {
			return t2;
		}
	}
	
	/**
	 * An extension of HashMap meant solely to provide known behavior for toString().
	 * @author James
	 * @param <K> Key.
	 * @param <V> Value.
	 */
	public class PHashMap<K, V> extends HashMap<K, V> {
		
		/**
		 * Default serialization constant.
		 */
		private static final long serialVersionUID = 1L;

		/**
		 * 
		 * @return 
		 */
		@Override
		public String toString() {
			StringBuilder printForm = new StringBuilder();
			for (K key : this.keySet()) {
				printForm.append(this.get(key).toString() + System.lineSeparator());
			}
			return printForm.toString();
		}
	}
}
