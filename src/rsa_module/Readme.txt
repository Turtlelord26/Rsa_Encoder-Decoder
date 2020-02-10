	This program is an implementation of RSA public key cryptography. Its functionality includes storage of the user's keys and other users' public keys, encryption of plaintext messages using any stored public key, and decryption of messages with the user's private key.

	.txt files are included in an assets folder. The program is not capable of creating new files if none exist, and will return errors in such a case. As long as the files exist, even if they are blank, the program will function normally.

	Program functions are accessed by an interactive command interface. After program initialization, it will prompt the user (with Systen.in) to enter a command. Recognized commands are:
* "encrypt": After further prompting for selecting a key to use from assets/KeyText.txt and identifying the sender, the program will encrypt any text in assets/PlainText.txt and write the result to assets/CipherText.txt, possibly with the user's public key appended.
* "encrypt to self": A shortcut of "encrypt" above that uses the user's own public key to encrypt the message.
* "decrypt": Runs decryption on any text in assets/CipherText.txt using the user's private key. If a public key is appended to the ciphertext, the program will store it in the user's assets/KeyText.txt if it is not already there.
* "generate new keys": Runs a method to generate a new private and public key for the user, deleting the old ones. As this is irreversible and may result in permanently unreadable messages, there is a prompted confirmation step.
* "help": Will display information on the above commands on System.out