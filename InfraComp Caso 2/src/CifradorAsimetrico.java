import java.security.Key;
import java.security.KeyPair;

import javax.crypto.Cipher;

public class CifradorAsimetrico {

	// -------------------------------
	// Atributos
	// -------------------------------
    
	private final static String ALGORITMO = Cliente.ALGa;
	private KeyPair keyPair;

	// -------------------------------
	// Constructor
	// -------------------------------

	public CifradorAsimetrico(KeyPair parDeLlaves) {
		this.keyPair = parDeLlaves;
	}

	// -------------------------------
	// Métodos
	// -------------------------------

	public byte[] cifrar(byte[] clearText, Key llavePub) {
		try {
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			cipher.init(Cipher.ENCRYPT_MODE, llavePub);
			byte[] cipheredText = cipher.doFinal(clearText);
                        
			return cipheredText;
		} catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
                        
			return null;
		}
	}

	public byte[] descifrar(byte[] cipheredText) {
		try {
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
			byte[] clearText = cipher.doFinal(cipheredText);
                        
			return clearText;
		} catch (Exception e) {
			System.out.println("Excepcion: " + e.getMessage());
                        
			return null;
		}
	}

	public KeyPair getPair(){ return keyPair; }
}
