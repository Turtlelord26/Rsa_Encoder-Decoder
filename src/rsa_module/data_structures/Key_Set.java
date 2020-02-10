package rsa_module.data_structures;

public class Key_Set {
	
	private final Rsa_Public_Key publicKey;
	
	private final Rsa_Private_Key privateKey;
	
	public Key_Set(Rsa_Public_Key publicKey, Rsa_Private_Key privateKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}
	
	public Rsa_Public_Key getPublicKey() {
		return publicKey;
	}
	
	public Rsa_Private_Key getPrivateKey() {
		return privateKey;
	}
}
