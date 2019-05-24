package rsaModule;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.util.Scanner;

/**
 * A demonstration program that can encrypt and decrypt text with an implementation of the RSA public key cryptosystem.
 * It uses text files to store keys between sessions, and appends its own current public key to messages it has encrypted, 
 * so that recipients can use it to respond. Manual entry of key data is allowed but not failsafed.
 * @author James Talbott
 */
public class RsaModule {
	
	private RsaPublicKey publicKey;
	
	private RsaPrivateKey privateKey;
	
	private StringableHashMap<String, RsaPublicKey> addressBook;
	
	private FileRW plainTextRW;
	
	private FileRW cipherTextRW;
	
	private FileRW keyTextRW;
	
	private Scanner scan;
	
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
		addressBook = new StringableHashMap<String, RsaPublicKey>();
		String keys[] = keyTextRW.readFile().split(System.lineSeparator());
		if (detectExistingKeys(keys)) {
			loadExistingKeysIntoAddressBook(keys);
		} else {
			generateNewKeys();
		}
		scan = new Scanner(System.in);
		scan.useDelimiter(System.lineSeparator());
		commandSwitch();
	}
	
	private Boolean detectExistingKeys(String[] keys) {
		if (keys.length < 2) {
			return false;
		} else {
			return true;
		}
	}
	
	private void loadExistingKeysIntoAddressBook(String[] keys) {
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
				encrypt();
			} else if (command.equals("decrypt")) {
				decrypt();
			} else if (command.equals("generate new keys")) {
				confirmGenerateNewKeys();
			} else if (command.equals("help")) {
				printHelpText();
			} else {
				System.out.println("Unrecognized Command.");
			}
			System.out.println("Enter a command, or type \"help\" for a list of commands.");
			token = scan.next();
			command = token.trim();
		}
		scan.close();
		//Program Terminates
	}
	
	private void encrypt() {
		System.out.println("Enter an ID to select the corresponding public key.");
		String token = scan.next();
		String command = token.trim();
		RsaPublicKey key = addressBook.get(command);
		if (key == null) {
			System.out.println("Error: entered ID has no matching Key stored.");
		} else {
			System.out.println("Type an identifier to append your public key to this message, or type \"skip\" "
					+ "to skip this step. Identifiers must not contain commas, colons, or newlines.");
			token = scan.next();
			command = token.trim();
			if (isValidPubKeyID(command)) {
				encryptTextAndWriteToFile(key, command);
			} else {
				System.out.println("Error: malformed identifer entered. No text encrypted.");
			}
		}
	}
	
	private Boolean isValidPubKeyID(String command) {
		return ! command.equals("skip") && 
				! command.equals("self") && 
				command.indexOf(',') == -1 && 
				command.indexOf(':') == -1 && 
				command.indexOf('\n') == -1;
	}
	
	private void encryptTextAndWriteToFile(RsaPublicKey key, String identifier) {
		String plainText = plainTextRW.readFile();
		String cipherText = new RsaEncoder(key, plainText).getCipherText();
		RsaPublicKey outgoingKey = new RsaPublicKey(publicKey.getModulus(), publicKey.getExponent(), identifier);
		cipherTextRW.writeToFile(cipherText + System.lineSeparator() + outgoingKey.toString());
		System.out.println("Encrypted text written to cipherText.txt");
	}
	
	private void decrypt() {
		String[] cipherFileText = cipherTextRW.readFile().split(System.lineSeparator());
		String cipherText = cipherFileText[0];
		String plainText = new RsaDecoder(privateKey, cipherText).getPlainText();
		plainTextRW.writeToFile(plainText);
		System.out.println("Decrypted text written to plainText.txt");
		if (cipherTextHasAppendedID(cipherFileText) && isUnsavedPublicKeyID(cipherFileText[1])) {
			saveNewPublicKey(cipherFileText);
		}
	}
	
	private Boolean cipherTextHasAppendedID(String[] cipherFileText) {
		return cipherFileText.length == 2;
	}
	
	private boolean isUnsavedPublicKeyID(String cipherTextPublicKey) {
		return ! addressBook.containsKey(cipherTextPublicKey.substring(0, cipherTextPublicKey.indexOf(':')));
	}
	
	private void saveNewPublicKey(String[] cipherFileText) {
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
	
	private void confirmGenerateNewKeys() {
		System.out.println("Are you sure? Generating new keys is irreversible and any ciphertext encoded with "
				+ "old keys will be indecipherable.\nType \"Confirm\" (no quotes) to generate new keys.");
		String token = scan.next();
		String command = token.trim();
		if (command.equals("Confirm")) {
			generateNewKeys();
		} else {
			System.out.println("New keys have not been generated.");
		}
	}
	
	private void generateNewKeys() {
		KeySet newKeys = new KeyMaker().getNewKeys();
		publicKey = newKeys.getPublicKey();
		privateKey = newKeys.getPrivateKey();
		saveKeysToFile();
	}
	
	private void saveKeysToFile() {
		String priKey = "selfPrivate:" + privateKey.toString() + System.lineSeparator();
		addressBook.put("self", publicKey);
		keyTextRW.writeToFile(priKey + addressBook.toString());
	}
	
	private void printHelpText() {
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
}
