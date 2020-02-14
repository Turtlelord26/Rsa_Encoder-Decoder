package rsa_module;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Paths;
import java.util.Scanner;

import rsa_module.data_structures.Key_Set;
import rsa_module.data_structures.Rsa_Private_Key;
import rsa_module.data_structures.Rsa_Public_Key;
import rsa_module.data_structures.Stringable_HashMap;
import rsa_module.key_making.Key_Maker;
import rsa_module.utility.File_Accesser;

/**
 * A demonstration program that can encrypt and decrypt text with an implementation of the RSA public key cryptosystem.
 * It uses text files to store keys between sessions, and appends its own current public key to messages it has encrypted, 
 * so that recipients can use it to respond. Manual entry of key data is allowed but not failsafed.
 * @author James Talbott
 */
public class Rsa_Module {
	
	private Rsa_Public_Key public_key;
	
	private Rsa_Private_Key private_key;
	
	private Stringable_HashMap<String, Rsa_Public_Key> address_book;
	
	private File_Accesser plain_text_file_accesser;
	
	private File_Accesser cipher_text_file_accesser;
	
	private File_Accesser key_text_file_accesser;
	
	private Scanner input_scanner;
	
	/**
	 * Constructor creates and stores FileRW objects, and loads data from those files into the appropriate fields.
	 * It then engages the user command input method.
	 * @param plain_text_file A File object for a .txt that stores plaintext.
	 * @param cipherTextFile A File object for a .txt that stores ciphertext.
	 * @param keyTextFile A File object for a .txt that stores keys.
	 */
	public Rsa_Module(File plain_text_file, File cipherTextFile, File keyTextFile) {
		plain_text_file_accesser = new File_Accesser(plain_text_file);
		cipher_text_file_accesser = new File_Accesser(cipherTextFile);
		key_text_file_accesser = new File_Accesser(keyTextFile);
		address_book = new Stringable_HashMap<String, Rsa_Public_Key>();
		String keys[] = key_text_file_accesser.readFile().split(System.lineSeparator());
		if (detectExistingKeys(keys)) {
			loadExistingKeysIntoAddressBook(keys);
		} else {
			generateNewKeys();
		}
		input_scanner = new Scanner(System.in);
		input_scanner.useDelimiter(System.lineSeparator());
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
		this.private_key = new Rsa_Private_Key(keys[0]);
		Rsa_Public_Key newkey;
		for (int i = 1; i < keys.length; i++) {
			newkey = new Rsa_Public_Key(keys[i]);
			if (newkey.getID().equals("self")) {
				this.public_key = newkey;
			}
			address_book.put(newkey.getID(), newkey);
		}
	}
	
	/**
	 * Main method sets up File objects with expected paths and calls the constructor with them.
	 * @param args Command line inputs not used at program initialization.
	 */
	public static void main(String[] args) {
		File plainTextFile = new File(Paths.get("src/rsa_module/assets/PlainText.txt").toString());
		File cipherTextFile = new File(Paths.get("src/rsa_module/assets/CipherText.txt").toString());
		File keyTextFile = new File(Paths.get("src/rsa_module/assets/KeyText.txt").toString());
		new Rsa_Module(plainTextFile, cipherTextFile, keyTextFile);
		
	}
	
	/**
	 * Method hosts the command interface by which users activate various supported actions.
	 * Notable inputs include "exit" to terminate the program and "help" for information on further commands.
	 */
	public void commandSwitch() {
		System.out.println("Enter a command, or type \"help\" for a list of commands.");
		String token = input_scanner.next();
		String command = token.trim();
		while (! command.equals("exit")) {
			/**
			 * Command to encrypt available plaintext with own public key.
			 */
			if (command.equals("encrypt to self")) {
				String plainText = plain_text_file_accesser.readFile();
				String cipherText = new Rsa_Encryption_Operator(public_key, plainText).getCipherText();
				cipher_text_file_accesser.writeToFile(cipherText + System.lineSeparator() + public_key.toString());
				System.out.println("Encrypted text written to cipherText.txt");
			} else if (command.equals("encrypt")) {
				select_recipient_then_encrypt();
			} else if (command.equals("decrypt")) {
				decrypt();
			} else if (command.equals("generate new keys")) {
				if (confirmGenerateNewKeys()) {
					generateNewKeys();
				}
			} else if (command.equals("help")) {
				printHelpText();
			} else {
				System.out.println("Unrecognized Command.");
			}
			System.out.println("Enter a command, or type \"help\" for a list of commands.");
			token = input_scanner.next();
			command = token.trim();
		}
		input_scanner.close();
		//Program Terminates
	}
	
	private void select_recipient_then_encrypt() {
		System.out.println("Enter an ID to select the corresponding public key.");
		String token = input_scanner.next();
		String command = token.trim();
		Rsa_Public_Key recipient_key = address_book.get(command);
		if (recipient_key == null) {
			System.out.println("Error: entered ID has no matching Key stored.");
		} else {
			System.out.println("Type an identifier to append your public key to this message, or type \"skip\" "
					+ "to skip this step. Identifiers must not contain commas, colons, or newlines.");
			token = input_scanner.next();
			command = token.trim();
			if (is_valid_public_key_id(command)) {
				encrypt(recipient_key, command);
			} else {
				print_bad_identifier_input_error_message();
			}
		}
	}
	
	private Boolean is_valid_public_key_id(String command) {
		return ! command.equals("skip") && 
				! command.equals("self") && 
				command.indexOf(',') == -1 && 
				command.indexOf(':') == -1 && 
				command.indexOf('\n') == -1;
	}
	
	private void encrypt(Rsa_Public_Key recipient_key, String command) {
		String plain_text = retrieve_plain_text();
		String cipher_text = encrypt_plain_text(recipient_key, plain_text);
		Rsa_Public_Key outgoing_key = copy_public_key_adding_identifier(command);
		write_cipher_text_with_outgoing_key(cipher_text, outgoing_key);
		print_successful_encryption_confirmation_message();
	}
	
	private String retrieve_plain_text() {
		return plain_text_file_accesser.readFile();
	}
	
	private String encrypt_plain_text(Rsa_Public_Key recipient_key, String plain_text) {
		return new Rsa_Encryption_Operator(recipient_key, plain_text).getCipherText();
	}
	
	private Rsa_Public_Key copy_public_key_adding_identifier(String identifier) {
		return new Rsa_Public_Key(public_key.getModulus(), public_key.getExponent(), identifier);
	}
	
	private void write_cipher_text_with_outgoing_key(String cipher_text, Rsa_Public_Key outgoing_key) {
		cipher_text_file_accesser.writeToFile(cipher_text + System.lineSeparator() + outgoing_key.toString());
	}
	
	private void print_successful_encryption_confirmation_message() {
		System.out.println("Encrypted text written to cipherText.txt");
	}
	
	private void print_bad_identifier_input_error_message() {
		System.out.println("Error: malformed identifer entered. No text encrypted.");
	}
	
	private void decrypt() {
		String[] cipherFileText = cipher_text_file_accesser.readFile().split(System.lineSeparator());
		String cipherText = cipherFileText[0];
		String plainText = new Rsa_Decryption_Operator(private_key, cipherText).getPlainText();
		plain_text_file_accesser.writeToFile(plainText);
		System.out.println("Decrypted text written to plainText.txt");
		if (cipherTextHasAppendedID(cipherFileText) && isUnsavedPublicKeyID(cipherFileText[1])) {
			saveNewPublicKey(cipherFileText);
		}
	}
	
	private Boolean cipherTextHasAppendedID(String[] cipherFileText) {
		return cipherFileText.length == 2;
	}
	
	private boolean isUnsavedPublicKeyID(String cipherTextPublicKey) {
		return ! address_book.containsKey(cipherTextPublicKey.substring(0, cipherTextPublicKey.indexOf(':')));
	}
	
	private void saveNewPublicKey(String[] cipherFileText) {
		String[] appendedKey = cipherFileText[1].split(":");
		String incomingID = appendedKey[0];
		String[] incomingKey = appendedKey[1].split(",");
		address_book.put(incomingID, new Rsa_Public_Key(
				new BigInteger(incomingKey[0]), new BigInteger(incomingKey[1]), incomingID));
		StringBuilder newKeyText = new StringBuilder();
		newKeyText.append("selfPrivate: " + private_key.toString() + System.lineSeparator());
		for (Rsa_Public_Key key : address_book.values()) {
			newKeyText.append(key.toString() + System.lineSeparator());
		}
		key_text_file_accesser.writeToFile(newKeyText.toString());
		System.out.println("Sender key saved with ID: " + incomingID);
	}
	
	private boolean confirmGenerateNewKeys() {
		System.out.println("Are you sure? Generating new keys is irreversible and any ciphertext encoded with "
				+ "old keys will be indecipherable.\nType \"Confirm\" (no quotes) to generate new keys.");
		String token = input_scanner.next();
		String command = token.trim();
		if (command.equals("Confirm")) {
			return true;
		} else {
			System.out.println("New keys have not been generated.");
			return false;
		}
	}
	
	private void generateNewKeys() {
		Key_Set newKeys = new Key_Maker().getNewKeys();
		public_key = newKeys.getPublicKey();
		private_key = newKeys.getPrivateKey();
		saveKeysToFile();
	}
	
	private void saveKeysToFile() {
		String priKey = "selfPrivate:" + private_key.toString() + System.lineSeparator();
		address_book.put("self", public_key);
		key_text_file_accesser.writeToFile(priKey + address_book.toString());
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
