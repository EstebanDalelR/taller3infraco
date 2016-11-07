import javax.crypto.Cipher;
import javax.crypto.SecretKey;

public class CifradorSimetrico {
    
	// -------------------------------
	// Atributos
	// -------------------------------

	private SecretKey desKey;
	private String PADDING;

	// -------------------------------
	// Constructor
	// -------------------------------

	public CifradorSimetrico() {
		PADDING = Cliente.ALGs + "/ECB/PKCS5Padding";
	}

	// -------------------------------
	// Métodos
	// -------------------------------

	public byte[] cifrar(byte[] clearText) {
		byte[] cipheredText;
		try {
			Cipher cipher = Cipher.getInstance(PADDING);
			cipher.init(Cipher.ENCRYPT_MODE, desKey);
			cipheredText = cipher.doFinal(clearText);
                        
			return cipheredText;
		} catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
                        
			return null;
		}
	}

	public byte[] descifrar(byte[] cipheredText) {
		try {
			Cipher cipher = Cipher.getInstance(PADDING);
			cipher.init(Cipher.DECRYPT_MODE, desKey);
			byte[] clearText = cipher.doFinal(cipheredText);
                        
			return clearText;
		} catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
                        
			return null;
		}
	}
	
	public void setKey(SecretKey LS) { this.desKey = LS; }
	
	public SecretKey getKey() { return this.desKey; }

}
