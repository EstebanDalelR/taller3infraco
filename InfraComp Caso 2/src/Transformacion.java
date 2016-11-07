
/**
 * Clase que contiene metodos static que proveen de metodos de transformacion al protocolo.
 */
public class Transformacion {

	/**
	 * Algoritmo de encapsulamiento a enteros. Convierte los bytes de un String a su representación como enteros.
	 * @param b Los bytes a representar como enteros.
	 * @return El string construido con la representacion de bytes como enteros.
	 */
    
	public static String transformar( byte[] b )
	{
		// Encapsulamiento con hexadesimales
		String ret = "";
		for (int i = 0 ; i < b.length ; i++) {
			String g = Integer.toHexString(((char)b[i])&0x00ff);
			ret += (g.length()==1?"0":"") + g;
		}
                
		return ret;
	}

	/**
	 * Algoritmo que transforma los enteros en los bytes correspondientes.
	 * @param ss El string con los enteros a transformar.
	 * @return Los bytes en su representación real.
	 */
        
	public static byte[] destransformar( String ss)
	{
		// Encapsulamiento con hexadecimales
		byte[] ret = new byte[ss.length()/2];
		for (int i = 0 ; i < ret.length ; i++) {
			ret[i] = (byte) Integer.parseInt(ss.substring(i*2,(i+1)*2), 16);
		}
                
		return ret;
	}
}
