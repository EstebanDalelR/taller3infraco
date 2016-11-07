import javax.security.auth.x500.X500Principal;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.Reader;
import java.math.BigInteger;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.util.Date;

import org.bouncycastle.asn1.*;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.*;

public class Cliente extends Thread {
    
    // ------------------------------------------
    // Constantes
    // ------------------------------------------
    
    public final static String ALGs = "AES";
    public final static String ALGa = "RSA";
    public final static String ALGd = "HMACSHA1";
    public final static String direccion = "localhost";
    public final static int puerto = 4444;
    
    // ------------------------------------------
    // Atributos
    // ------------------------------------------
    
    private KeyPair parDeLlaves;
    private SecretKey LS;
    private CifradorSimetrico simetrico;
    private CifradorAsimetrico asimetrico;
    private Socket canal;
    private PrintWriter writeStream;
    private BufferedReader readStream;
    private String datos;
    
    // ------------------------------------------
    // Constructor
    // ------------------------------------------
    
    public Cliente() {
        try {
            // Generacion de la pareja de llaves (K-,K+)
            KeyPairGenerator gen = KeyPairGenerator.getInstance(ALGa);
            gen.initialize(1024);
            this.parDeLlaves = gen.generateKeyPair();
            // 1. El cliente se comunica con el servidor para iniciar una sesión de consulta.
            this.canal = new Socket(direccion, puerto);
            readStream = new BufferedReader(new InputStreamReader(
                    canal.getInputStream()));
            writeStream = new PrintWriter(canal.getOutputStream(), true);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        // inicializacion de los cifradores
        this.simetrico = new CifradorSimetrico(); 
        this.asimetrico = new CifradorAsimetrico(parDeLlaves);
        
    }
    
    // ------------------------------------------
    // Run method
    // ------------------------------------------
    
    public void run() {
        
        String in;
        String consulta = "holi";
        String[] temp;
        Key llavePuServidor;
        try {
            // 1. El cliente se comunica con el servidor para iniciar una sesión de consulta.
            
            writeStream.write("HOLA");
            
            Thread.sleep(5000);
            if (!readStream.ready()) {
                //throw new Exception("NO ESTA LLEGANDO EL MSJ");
            }
            // 2. El servidor responde con un mensaje de confirmación.
            in = readStream.readLine();
            if (!in.equals("OK"))
                throw new Exception("El servidor no dio respuesta");
            //3. El cliente envía la lista de algoritmos de cifrado que usará durante la sesión y espera un mensaje del servidor
            //confirmando que soporta los algoritmos seleccionados (si no, el servidor envía un mensaje de terminación).
            writeStream.write("ALGORITMOS" + ":" + ALGs + ":" + ALGa + ":"
                    + ALGd);
            //4. El servidor responde con un mensaje de confirmación. O con un mensaje de error si no soporta alguno de los
            //algoritmos, en este caso ambos terminan la comunicación.
            in = readStream.readLine();
            if(in.equals("ERROR"))
                throw new Exception("El servidor arroja error");
            if (in.equals("OK"))
            {
                //5. El cliente envía su certificado digital (CD) para autenticarse con el servidor.
                X509Certificate cd_clnt = this.generarCertificadoV3(parDeLlaves);
                canal.getOutputStream().write(cd_clnt.getEncoded());
            }
            // 6. El servidor responde con su propio certificado digital (CD). Los dos certificados debe seguir el estándar X509.
            InputStream is = canal.getInputStream();
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cd_srv = (X509Certificate) cf.generateCertificate(is);
            llavePuServidor = cd_srv.getPublicKey();
            //7. El cliente envía un mensaje de confirmación.
            writeStream.write("OK");
            //8. El servidor genera una llave simétrica (LS) y la envía al cliente. Para proteger la llave, el servidor usa la llave pública
            //del cliente (KCi+).
            in = readStream.readLine();
            temp = in.split(":");
            if (!(temp[0]).equals("INIT"))
                throw new Exception(
                        "El servidor � yo la embarramos. Entonces fui yo con algo del buffer");
            
            //9. El cliente recibe la llave simétrica cifrada y la extrae. Después, el cliente responde enviando la misma llave simétrica,
            //cifrada con la llave pública del servidor (KS+).
            String LS_encryptada = temp[1];
            Transformacion t = new Transformacion();
            byte[] LSEncriptadoByte = t.destransformar(LS_encryptada);
            CifradorAsimetrico CA = new CifradorAsimetrico(parDeLlaves);
            byte[] LSDesencriptadoByte = CA.descifrar(LSEncriptadoByte);
            byte[] LSCifradoByte = CA.cifrar(LSDesencriptadoByte,llavePuServidor);
            String LSCifrado = t.transformar(LSCifradoByte);
            writeStream.write(LSCifrado);
            in = readStream.readLine();
            if (in.equals("OK"))
            {
                //10. A continuación el cliente usa la llave simétrica para cifrar la consulta (un código de identificación de cuenta) y el
                //código de integridad correspondiente .
                CifradorSimetrico CS = new CifradorSimetrico();
                SecretKey LS = new SecretKeySpec(LSDesencriptadoByte, 0, LSDesencriptadoByte.length, "AES");
                CS.setKey(LS);
                byte[] consultaByte = t.destransformar(consulta);
                byte[] hash = hashCryptoCode(consultaByte);
                byte[]consultaCifrada = CS.cifrar(consultaByte);
                byte[]hashCifrado = CS.cifrar(hash);
                String consultaFinal = consultaCifrada+":"+hashCifrado;
                writeStream.write(consultaFinal);
            }
            //11. El servidor recibe la información, descifra y chequea integridad. Si el usuario está autorizado para hacer la consulta
            //(vamos a suponer que si), el servidor responde la consulta con la cadena OK – <rta>. Si encuentra problemas
            //responde con la cadena ERROR.
            in = readStream.readLine();
            temp = in.split(":");
            if(temp[0].equals("OK"))
            {
                String rta = temp[1];
                //12. El cliente envía un mensaje confirmando la recepción del resultado y los dos terminan la comunicación.
                writeStream.write("Todo bien");
            }
            else
                throw new Exception("Error de autenticación");           
        } catch (Exception e) {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
        
        writeStream.close();
        try {
            readStream.close();
            canal.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
        
    }
    
    // ------------------------------------------
    // Métodos
    // ------------------------------------------
    
    /**
     * Crea un certificado X509 Version 3
     *
     * @param pair
     *            - Pareja de llaves
     * @return El certificado.
     * @throws InvalidKeyException
     * @throws SecurityException
     * @throws SignatureException
     */
    @SuppressWarnings("deprecation")
    public X509Certificate generarCertificadoV3(KeyPair pair)
            throws InvalidKeyException, SecurityException, SignatureException {
        
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(new X500Principal(
                "CN=Certificado : Cliente InfraComp Caso 2"));
        certGen.setNotBefore(new Date());
        certGen.setNotAfter(new Date(2014, 12, 31));
        certGen.setSubjectDN(new X500Principal(
                "CN=Certificado : Cliente InfraComp Caso 2"));
        certGen.setPublicKey(pair.getPublic());
        certGen.setSignatureAlgorithm("SHA256WithRSAEncryption");
        
        return certGen.generateX509Certificate(pair.getPrivate());
    }
    
    /**
     * Calcula el código HMAC, utilizando el algoritmo "ALGh", correspondiente a
     * un {} de datos
     *
     * @param datos
     *            - bytes de los datos a los cuales se les quieren calcular el
     *            código.
     * @return código HMAC en bytes.
     */
    private byte[] hashCryptoCode(byte[] datos) {
        try {
            String algoritmo = "Hmac" + ALGd.split("HMAC")[1];
            SecretKeySpec key = new SecretKeySpec(this.LS.getEncoded(),
                    algoritmo);
            Mac mac = Mac.getInstance(algoritmo);
            mac.init(key);
            byte[] rawHmac = mac.doFinal(datos);
            
            return rawHmac;
        } catch (Exception e) {
            e.printStackTrace();
            
            return null;
        }
    }
    
}
