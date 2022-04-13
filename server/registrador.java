import java.io.*;
import java.net.*;
import java.security.cert.Certificate;
import java.security.Security;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPathBuilder;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.util.EnumSet;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.*;
import javax.net.ssl.*;

public class registrador extends ClassServer {


	private static int DefaultServerPort = 9001;

	private static String raizMios = "/home/espafonsi/SEG_FINAL/server/";
	private static PrivateKey sK;
	private static PublicKey pK;
	private static PrivateKey sKfirma;
	private static PublicKey pKfirma;
	private static Certificate certificado;
	private static Certificate certificadoFirma;
	private static Certificate certificadoRoot;
	private static SecretKeySpec miClave;


	public registrador(ServerSocket ss, String alg) throws IOException {
		
		super(ss, sK, pK, sKfirma, pKfirma, certificado, certificadoFirma, certificadoRoot, miClave, alg);
	}

	public static void main(String args[]) {

		String[] cipherSuites = null;
		int port = DefaultServerPort;



		if (args.length != 4) {
			System.out.println("Faltan parámetros");
			return;
		}

		/*****************************************************************/
		definirAlmacenesServidor(args[0], args[1], args[2]);

		definirRevocacionOCSPStapling();
		/****************************************************************/

		getKeys(args[0], args[1], args[2]);

		try {
			ServerSocketFactory ssf = registrador.getServerSocketFactory("TLS", args[0], args[1], args[2]);

			ServerSocket ss = ssf.createServerSocket(port);

			// Ver los protocolos
			System.out.println("*****************************************************");
			System.out.println("*  Protocolos soportados en Servidor                 ");
			System.out.println("*****************************************************");

			String[] protocols = ((SSLServerSocket) ss).getEnabledProtocols();
			for (int i = 0; i < protocols.length; i++)
				System.out.println(protocols[i]);

			System.out.println("*****************************************************");
			System.out.println("*    Protocolo forzados                               ");
			System.out.println("*****************************************************");

			String[] protocolsNew = { "TLSv1.3", "TLSv1.2" };

			((SSLServerSocket) ss).setEnabledProtocols(protocolsNew);

			// volvemos a mostrarlos
			protocols = ((SSLServerSocket) ss).getEnabledProtocols();
			for (int i = 0; i < protocols.length; i++)
				System.out.println(protocols[i]);

			if (args.length >= 4 && args[3].equals("true")) {

				System.out.println("*****************************************************");
				System.out.println("*  Server inicializado CON Autenticacion de cliente  ");
				System.out.println("*****************************************************");

				// Ver Suites disponibles en Servidor

				System.out.println("*****************************************************");
				System.out.println("*         CypherSuites Disponibles en SERVIDOR       ");
				System.out.println("*****************************************************");

				cipherSuites = ((SSLServerSocket) ss).getSupportedCipherSuites();
				for (int i = 0; i < cipherSuites.length; i++)
					System.out.println(i + "--" + cipherSuites[i]);

				// Definir suites Habilitadas en server

				((SSLServerSocket) ss).setNeedClientAuth(true);

				String[] cipherSuitesHabilitadas = { "TLS_RSA_WITH_NULL_SHA256",
													 "TLS_ECDHE_RSA_WITH_NULL_SHA"};

				System.out.println("*****************************************************");
				System.out.println("*         CypherSuites Habilitadas en SERVIDOR       ");
				System.out.println("*****************************************************");

				cipherSuites = ((SSLServerSocket) ss).getEnabledCipherSuites();
				for (int i = 0; i < cipherSuites.length; i++)
					System.out.println(i + "--" + cipherSuites[i]);

			}

			new registrador(ss, args[3]);

		} catch (IOException e) {
			System.out.println("Unable to start ClassServer: " +
					e.getMessage());
			e.printStackTrace();
		}
	}

	private static ServerSocketFactory getServerSocketFactory(String type,String keySto, String pass, String trusSto) {

		if (type.equals("TLS")) {

			SSLServerSocketFactory ssf = null;


			try {
				/********************************************************************************
				 * Construir un contexto, pasandole el KeyManager y y TrustManager
				 * Al TrustManager se le incorpora el chequeo de certificados revocados por
				 * Ocsp.
				 * 
				 ********************************************************************************/
				// set up key manager to do server authentication

				char[] passphrase = pass.toCharArray();

				// --- Trust manager.

				// 1. Crear PKIXRevocationChecker

				CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
				PKIXRevocationChecker rc = (PKIXRevocationChecker) cpb.getRevocationChecker();
				rc.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
				rc.setOcspResponder(new URI("http://127.0.0.1:9080")); // Aqui poner la ip y puerto donde se haya
																		// lanzado el OCSP Responder
																		
				
				// 2. Crear el truststore

				KeyStore ts = KeyStore.getInstance("JCEKS");
				ts.load(new FileInputStream(raizMios + trusSto), passphrase);

				// 3. Crear los parametros PKIX y el PKIXRevocationChecker

				PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(ts, new X509CertSelector());
				pkixParams.addCertPathChecker(rc);
				pkixParams.setRevocationEnabled(true); // habilitar la revocacion (por si acaso)
				
				
				
				//
				TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
				tmf.init(new CertPathTrustManagerParameters(pkixParams));

				// set up key manager to do server authentication

				KeyManagerFactory kmf;
				KeyStore ks;


				// --- Key manager

				kmf = KeyManagerFactory.getInstance("SunX509");
				ks = KeyStore.getInstance("JCEKS");
				ks.load(new FileInputStream(raizMios + keySto), passphrase);
				kmf.init(ks, passphrase);

				// Crear el contexto
				SSLContext ctx;
				ctx = SSLContext.getInstance("TLS");
				ctx.init(kmf.getKeyManagers(),
						tmf.getTrustManagers(),
						null);

				ssf = ctx.getServerSocketFactory();
				return ssf;

			} catch (Exception e) {
				e.printStackTrace();
			}
		} else {
			return ServerSocketFactory.getDefault();
		}
		return null;
	}

	public static void getKeys(String keySto, String pass, String trustSto) {
		KeyStore ks;
		KeyPair pair;
		FileInputStream is;
		String nombre = "servidorsslfirma";

		try {
			ks = KeyStore.getInstance("JCEKS");
			is = new FileInputStream(raizMios + keySto); //"KeyStoreServer.jce"
			ks.load(is, pass.toCharArray());
			Key key = ks.getKey(nombre, pass.toCharArray());
			if (key instanceof PrivateKey) {
				certificadoFirma = ks.getCertificate(nombre);
				pKfirma = certificadoFirma.getPublicKey();
				pair = new KeyPair(pKfirma, (PrivateKey) key);
				sKfirma = pair.getPrivate();
			}

			nombre = "servidorssl";
			ks = KeyStore.getInstance("JCEKS");
			is = new FileInputStream(raizMios + keySto); //"KeyStoreServer.jce"
			ks.load(is, pass.toCharArray());
			key = ks.getKey(nombre, pass.toCharArray());
			if (key instanceof PrivateKey) {
				certificado = ks.getCertificate(nombre);
				pK = certificado.getPublicKey();
				pair = new KeyPair(pK, (PrivateKey) key);
				sK = pair.getPrivate();
			}



			ks = KeyStore.getInstance("JCEKS");
			is = new FileInputStream(raizMios + trustSto);  //"TrustStoreServer.jce"
			ks.load(is, pass.toCharArray());
			certificadoRoot = ks.getCertificate("root ca");

			ks = KeyStore.getInstance("JCEKS");
			is = new FileInputStream(raizMios + keySto); //"KeyStoreServer.jce"
			ks.load(is, pass.toCharArray());
			SecretKey skey = (SecretKey) ks.getKey("clavesecreta", pass.toCharArray());
			miClave = new SecretKeySpec(skey.getEncoded(), skey.getAlgorithm());

			System.out.println(pK);
			System.out.println(sK);
			System.out.println(certificado);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static void definirAlmacenesServidor(String keySto, String pass, String trustSto) {

		// Almacen de claves

		System.setProperty("javax.net.ssl.keyStore", raizMios + keySto);
		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword", pass);

		// Almacen de confianza
		System.setProperty("javax.net.ssl.trustStore", raizMios + trustSto);
		System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", pass);

	}

	private static void definirRevocacionOCSPStapling() {

		// Almacen de claves

		System.setProperty("jdk.tls.server.enableStatusRequestExtension", "true");
		System.setProperty("jdk.tls.stapling.ignoreExtensions", "true");
		//System.setProperty("jdk.tls.stapling.responderOverride", "false");
		System.setProperty("com.sun.net.ssl.checkRevocation", "true");
		//Security.setProperty("jdk.tls.server.enableStatusRequestExtension", "true");
		System.setProperty("jdk.tls.stapling.responderOverride", "false");
		//Security.setProperty("com.sun.net.ssl.checkRevocation", "true");
		System.setProperty("ocsp.enable", "true");
		//Security.setProperty("ocsp.enable", "true");
		//System.setProperty("jdk.tls.stapling.responderURI", "http://127.0.0.1:9080");

	}
}
