package rsaModule;

public class KeySet {
	
	private final RsaPublicKey publicKey;
	
	private final RsaPrivateKey privateKey;
	
	public KeySet(RsaPublicKey publicKey, RsaPrivateKey privateKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}
	
	protected RsaPublicKey getPublicKey() {
		return publicKey;
	}
	
	protected RsaPrivateKey getPrivateKey() {
		return privateKey;
	}
}
