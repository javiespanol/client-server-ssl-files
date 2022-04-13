import java.net.*;
import java.io.*;
import java.util.*;
import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.*;
import java.security.spec.*;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertPathBuilder;
import java.security.cert.PKIXBuilderParameters;
import java.security.cert.PKIXRevocationChecker;
import java.security.cert.X509CertSelector;
import java.util.EnumSet;
import java.util.Enumeration;
import java.util.Scanner;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Key;
import java.security.*;
import java.math.BigInteger;
import java.security.MessageDigest;

public class cliente {

	private static String raizMios = "/home/espafonsi/SEG_FINAL/cliente/";
	private static String raizFicheros = "/home/espafonsi/SEG_FINAL/cliente/documentos/";
	private static String publicaServer = "//home/espafonsi/SEG_FINAL/cliente/servidorssl.pub";
	private static String publicaServerFirma = "/home/espafonsi/SEG_FINAL/cliente/servidorsslfirma.pub";

	private static PrivateKey sK;
	private static PublicKey pK;
	private static PrivateKey sKfirma;
	private static PublicKey pKfirma;
	private static PublicKey serverPublicKey;
	private static PublicKey serverPublicKeyFirma;
	private static Certificate certificado;
	private static Certificate certificadoFirma;
	private static Certificate certificadoRoot;
	private static byte[] documentoCifrado;
	private static byte[] paramSerializados;
	private static byte[] skeyCifrada;
	private static byte[] firmaDocumento;
	private static HashMap<Integer, String> mapa;
	private static byte[] documentoRecuperar;

	public static void main(String[] args) throws Exception {

		String host = null;
		int port = -1;
		String[] cipherSuitesDisponibles = null;
		mapa = new HashMap<Integer, String>();

		for (int i = 0; i < args.length; i++)
			System.out.println(args[i]);

		if (args.length < 2) {
			System.out.println("Faltan parámetros");
			return;
		}

		host = "localhost";
		port = 9001;

		try {

			

			String pass = menu_pass();
			char[] passphrase = pass.toCharArray();

			definirAlmacenesCliente(args[0], pass, args[1]);
			definirRevocacionOCSP();

			SSLSocketFactory factory = null;

			try {
				SSLContext ctx;
				KeyManagerFactory kmf;
				KeyStore ks;

				/********************************************************************************
				 * Construir un contexto, pasandole el KeyManager y y TrustManager
				 * Al TrustManager se le incorpora el chequeo de certificados revocados por
				 * Ocsp.
				 * 
				 ********************************************************************************/
				// --- Trust manager.

				// 1. Crear PKIXRevocationChecker
				CertPathBuilder cpb = CertPathBuilder.getInstance("PKIX");
				PKIXRevocationChecker rc = (PKIXRevocationChecker) cpb.getRevocationChecker();
				rc.setOptions(EnumSet.of(PKIXRevocationChecker.Option.NO_FALLBACK));
				rc.setOcspResponder(new URI("http://127.0.0.1:9001")); // Aqui poner la ip y puerto donde se haya
																		// lanzado el OCSP Responder

				// 2. Crear el truststore

				KeyStore ts = KeyStore.getInstance("JCEKS");
				ts.load(new FileInputStream(raizMios + args[1]), passphrase);
				Enumeration<String> e = ts.aliases();
				while (e.hasMoreElements()) {
					System.out.println(e.nextElement());
				}

				// 3. Crear los parametros PKIX y el PKIXRevocationChecker

				PKIXBuilderParameters pkixParams = new PKIXBuilderParameters(ts, new X509CertSelector());
				pkixParams.addCertPathChecker(rc);
				pkixParams.setRevocationEnabled(true); // habilitar la revocacion (por si acaso)

				//
				TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
				tmf.init(new CertPathTrustManagerParameters(pkixParams));

				// --- Key manager

				kmf = KeyManagerFactory.getInstance("SunX509");
				ks = KeyStore.getInstance("JCEKS");
				ks.load(new FileInputStream(raizMios + args[0]), passphrase);
				kmf.init(ks, passphrase);

				Enumeration<String> t = ks.aliases();
				while (t.hasMoreElements()) {
					System.out.println(t.nextElement());
				}

				// Crear el contexto
				ctx = SSLContext.getInstance("TLS");
				ctx.init(kmf.getKeyManagers(),
						tmf.getTrustManagers(),
						null);

				factory = ctx.getSocketFactory();

				// Suites disponibles

				System.out.println("*****************************************************");
				System.out.println("*         CypherSuites Disponibles en CLIENTE        ");
				System.out.println("*****************************************************");

				String[] cipherSuites = factory.getSupportedCipherSuites();
				for (int i = 0; i < cipherSuites.length; i++)
					System.out.println(cipherSuites[i]);

				// Suites habilitadas por defecto

				System.out.println("*****************************************************");
				System.out.println("*         CypherSuites Habilitadas por defecto       ");
				System.out.println("*****************************************************");

				String[] cipherSuitesDef = factory.getDefaultCipherSuites();
				for (int i = 0; i < cipherSuitesDef.length; i++)
					System.out.println(cipherSuitesDef[i]);

			} catch (Exception e) {
				throw new IOException(e.getMessage());
			}

			SSLSocket socket = (SSLSocket) factory.createSocket(host, port);

			// Ver los protocolos

			System.out.println("*****************************************************");
			System.out.println("*  Protocolos soportados en Cliente                 ");
			System.out.println("*****************************************************");

			String[] protocols = socket.getEnabledProtocols();
			for (int i = 0; i < protocols.length; i++)
				System.out.println(protocols[i]);

			System.out.println("*****************************************************");
			System.out.println("*    Protocolo forzado                               ");
			System.out.println("*****************************************************");

			String[] protocolsNew = { "TLSv1.3" };

			socket.setEnabledProtocols(protocolsNew);

			System.out.println("*****************************************************");
			System.out.println("*         CypherSuites  Disponibles (Factory)        ");
			System.out.println("*****************************************************");

			cipherSuitesDisponibles = factory.getSupportedCipherSuites();
			for (int i = 0; i < cipherSuitesDisponibles.length; i++)
				System.out.println(cipherSuitesDisponibles[i]);

			// Habilitar las suites deseadas

			String[] cipherSuitesHabilitadas = { "TLS_AES_128_GCM_SHA256",
					"TLS_RSA_WITH_AES_128_CBC_SHA256",
					"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
					"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
					"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
					"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
					"TLS_RSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
					"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
					"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"

			};
			if (true)
				socket.setEnabledCipherSuites(cipherSuitesHabilitadas);

			System.out.println("*****************************************************");
			System.out.println("*         CypherSuites Habilitadas en socket         ");
			System.out.println("*****************************************************");

			String[] cipherSuitesHabilSocket = socket.getEnabledCipherSuites();
			for (int i = 0; i < cipherSuitesHabilSocket.length; i++)
				System.out.println(cipherSuitesHabilSocket[i]);

			socket.getSSLParameters().getUseCipherSuitesOrder();

			System.out.println("Comienzo SSL Handshake");
			socket.startHandshake();
			System.out.println("Fin SSL Handshake");
			System.out.println("*****************" + socket.getSession());

			/******************************************************************************
			 * Flujos salientes para cabecera y datos
			 *******************************************************************************/

			OutputStream streamSalida = socket.getOutputStream();

			// Flujo normal (texto) para la cabecera
			PrintWriter flujoCabecera = new PrintWriter(new BufferedWriter(
					new OutputStreamWriter(streamSalida)));

			// Flujo binario (object) para los datos
			ObjectOutputStream flujoDatos = new ObjectOutputStream(streamSalida);
			/******************************************************************************
			 * Flujos entrantes para cabecera y datos
			 *******************************************************************************/

			BufferedReader flujoCabecera_E = new BufferedReader(new InputStreamReader(socket.getInputStream()));
			ObjectInputStream flujoDatos_E = new ObjectInputStream(socket.getInputStream());

			//leerMapa();

			while (true) {

				Boolean salir = false;
				String ruta = "";
				char opcion = menu();
				getKeys(args[0], pass, args[1]);

				switch (opcion) {

					/**************************************
					 * Registrar
					 *************************************/
					case 'R': {

						System.out.println("REGISTRAR DOCUMENTO");
						char tipo = menu_tipo();

						Registrar_documento registrar_documento = new Registrar_documento();

						if (tipo == 'P') {

							ruta = menu_fichero();
							String nombre = menu_nombre();
							if(nombre.length()>100){
								System.out.println("** NOMBRE DEMASIADO LARGO **");
								break;
							}
							if(nombre.length()==0){
								System.out.println("** NOMBRE DEMASIADO CORTO **");
							}
							firmarDocumento(ruta);
							registrar_documento.request(nombre, "PUBLICO", Files.readAllBytes(Paths.get(ruta)), null,
									null, firmaDocumento, certificadoFirma.getEncoded(), certificado.getEncoded());

						} else if (tipo == 'V') {

							ruta = menu_fichero();
							String nombre = menu_nombre();
							cifrarDocumento(ruta);
							firmarDocumento(ruta);
							registrar_documento.request(nombre, "PRIVADO", documentoCifrado, skeyCifrada,
									paramSerializados, firmaDocumento, certificadoFirma.getEncoded(),
									certificado.getEncoded());

						} else {
							System.out.println("** NO EXISTE ESA OPCIÓN **");
							break;
						}
						///home/espafonsi/SEG_FINAL/cliente/hola.png

						// enviar cabecera
						flujoCabecera.println("REGISTRAR");
						flujoCabecera.flush();
						// envíar datos
						flujoDatos.writeObject(registrar_documento);
						flujoDatos.flush();

						// Leer Respuesta ...

						String inputLine;

						inputLine = flujoCabecera_E.readLine();
						System.out.println(inputLine + "\n");

						Registrar_documento respuesta = (Registrar_documento) flujoDatos_E.readObject();

						if (respuesta.getNerror() == -1) {
							System.out.println("CERTIFICADO DE FIRMA INCORRECTO");
							break;
						} else if (respuesta.getNerror() == -2) {
							System.out.println("FIRMA INCORRECTA");
							break;
						} else if (respuesta.getNerror() == 0) {
							System.out.println("FICHERO REGISTRADO CORRECTAMENTE");
						} else {
							System.out.println("ERROR");
							break;
						}

						// Verificar SigRD

						CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
						InputStream inn = new ByteArrayInputStream(certificadoRoot.getEncoded());
						X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inn);
						X500Principal issuerCertAuthRoot = cert.getIssuerX500Principal();

						certificateFactory = CertificateFactory.getInstance("X.509");
						inn = new ByteArrayInputStream(respuesta.getCertificadoFirmaS());
						cert = (X509Certificate) certificateFactory.generateCertificate(inn);
						X500Principal issuerCertFirmaS = cert.getIssuerX500Principal();

						try {
							cert.checkValidity();
						} catch (Exception e) {
							System.out.println("CERTIFICADO DE REGISTRADOR INCORRECTO");
							break;
						}

						if(!issuerCertFirmaS.equals(issuerCertAuthRoot)){
							System.out.println("CERTIFICADO DE REGISTRADOR INCORRECTO");
							break;
						}


						PublicKey clavePublicaServidor = cert.getPublicKey();
						Signature verifier = Signature.getInstance(cert.getSigAlgName());
						verifier.initVerify(clavePublicaServidor);

						byte[] idR = respuesta.getIdRegistro().toString().getBytes();
						byte[] time = respuesta.getSelloTemporal().toString().getBytes();
						byte[] idP = respuesta.getIdPropietario().getBytes();
						byte[] doc = Files.readAllBytes(Paths.get(ruta));

						verifier.update(idR, 0, idR.length);
						verifier.update(time, 0, time.length);
						verifier.update(idP, 0, idP.length);
						verifier.update(doc, 0, doc.length);
						verifier.update(firmaDocumento, 0, firmaDocumento.length);

						Boolean resultado = false;
						resultado = verifier.verify(respuesta.getSigRD());

						if (resultado) {
							System.out.println(
									"DOCUMENTO CORRECTAMENTE REGISTRADO CON EL NUMERO: " + respuesta.getIdRegistro());
							MessageDigest md = MessageDigest.getInstance("SHA-512");
							md.update(doc, 0, doc.length);
							byte[] messageDigest = md.digest();

							BigInteger no = new BigInteger(1, messageDigest);
							String hashtext = no.toString(16);

							// Add preceding 0s to make it 32 bit
							while (hashtext.length() < 32) {
								hashtext = "0" + hashtext;
							}

							mapa.put(respuesta.getIdRegistro(), hashtext);

							File myObj = new File(ruta);
							myObj.delete();
							documentoCifrado=null;

							doc = null;
							firmaDocumento = null;

						} else {
							System.out.println("FIRMA INCORRECTA DEL REGISTRADOR");
							break;
						}

						break;
					}
					/**************************************
					 * Recuperar
					 *************************************/
					case 'O': {
						System.out.println("RECUPERAR DOCUMENTO");

						Integer idPedir = menu_id();

						Recuperar_documento recuperar_documento = new Recuperar_documento();
						recuperar_documento.request(certificado.getEncoded(), idPedir);

						// enviar cabecera
						flujoCabecera.println("RECUPERAR");
						flujoCabecera.flush();
						// envíar datos
						flujoDatos.writeObject(recuperar_documento);
						flujoDatos.flush();

						// Leer Respuesta ...

						String inputLine;

						inputLine = flujoCabecera_E.readLine();
						System.out.println(inputLine + "\n");
						Recuperar_documento respuesta = (Recuperar_documento) flujoDatos_E.readObject();

						if (respuesta.getNerror() == -3) {
							System.out.println("CERTIFICADO INCORRECTO");
							break;
						} else if (respuesta.getNerror() == -4) {
							System.out.println("DOCUMENTO NO EXISTENTE");
							break;
						} else if (respuesta.getNerror() == -5) {
							System.out.println("ACCESO NO PERMITIDO");
							break;
						} else if (respuesta.getNerror() == 0) {
							System.out.println("DOCUMENTO ENCONTRADO");

							documentoRecuperar = null;

							CertificateFactory cf = CertificateFactory.getInstance("X.509");
							InputStream innn = new ByteArrayInputStream(certificadoRoot.getEncoded());
							X509Certificate certAux = (X509Certificate) cf.generateCertificate(innn);
							X500Principal issuerCertAuthRoot = certAux.getIssuerX500Principal();

							CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
							InputStream inn = new ByteArrayInputStream(respuesta.getCertificadoFirmaS());
							X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inn);
							X500Principal issuerCertFirmaS = cert.getIssuerX500Principal();
							PublicKey publicaServidor = cert.getPublicKey();

							try {
								cert.checkValidity();
							} catch (Exception e) {
								System.out.println("CERTIFICADO DE REGISTRADOR INCORRECTO");
								break;
							}

							if(!issuerCertFirmaS.equals(issuerCertAuthRoot)){
								System.out.println("CERTIFICADO DE REGISTRADOR INCORRECTO");
								break;
							}


							if (respuesta.getTipoDocumento().equals("PUB")) {
								documentoRecuperar = respuesta.getDocumentoCifrado();
							} else if (respuesta.getTipoDocumento().equals("PRIV")) {
								descifrarRecuperar(respuesta);
							} else {
								System.out.println("ERROR");
								break;
							}

							Signature verifier = Signature.getInstance(cert.getSigAlgName());
							verifier.initVerify(publicaServidor);

							verifier.update(respuesta.getIdRegistro().toString().getBytes(), 0,
									respuesta.getIdRegistro().toString().getBytes().length);
							verifier.update(respuesta.getSelloTemporal().toString().getBytes(), 0,
									respuesta.getSelloTemporal().toString().getBytes().length);
							verifier.update(respuesta.getIdPropietario().getBytes(), 0,
									respuesta.getIdPropietario().getBytes().length);
							verifier.update(documentoRecuperar, 0, documentoRecuperar.length);

							firmarDocumento(documentoRecuperar);
							verifier.update(firmaDocumento, 0, firmaDocumento.length);

							Boolean resultado = false;
							resultado = verifier.verify(respuesta.getSigRD());
							

							if (resultado) {

								MessageDigest md = MessageDigest.getInstance("SHA-512");
								md.update(documentoRecuperar, 0, documentoRecuperar.length);
								byte[] messageDigest = md.digest();

								BigInteger no = new BigInteger(1, messageDigest);
								String hashtext = no.toString(16);

								// Add preceding 0s to make it 32 bit
								while (hashtext.length() < 32) {
									hashtext = "0" + hashtext;
								}

								if (hashtext.equals(mapa.get(respuesta.getIdRegistro()))) {

									System.out.println(
											"DOCUMENTO RECUPERADO CORRECTAMENTE CON ID: " + respuesta.getIdRegistro()
													+ " SELLO TEMPORAL: " + respuesta.getSelloTemporal());
									try (FileOutputStream s = new FileOutputStream(raizFicheros + respuesta.getIdRegistro().toString()
											+ "_" + respuesta.getIdPropietario())) {
										s.write(documentoRecuperar);
									}

								} else {
									System.out.println("DOCUMENTO ALTERADO POR EL REGISTRADOR");
									break;
								}

							} else {
								System.out.println("FALLO DE FIRMA DEL REGISTRADOR");
								break;
							}

						} else {
							System.out.println("ERROR");
							break;
						}

						break;

					}
					/**************************************
					 * Listar
					 *************************************/
					case 'L': {
						System.out.println("LISTAR DOCUMENTO");
						char tipo = menu_tipo();

						Listar_documento listar_documento = new Listar_documento();

						if (tipo == 'P') {

							listar_documento.request("PUB", certificado.getEncoded());

						} else if (tipo == 'V') {

							listar_documento.request("PRIV", certificado.getEncoded());

						} else {
							System.out.println("** NO EXISTE ESA OPCIÓN **");
							break;
						}

						// enviar cabecera
						flujoCabecera.println("LISTAR");
						flujoCabecera.flush();
						// envíar datos
						flujoDatos.writeObject(listar_documento);
						flujoDatos.flush();

						// Leer Respuesta ...

						String inputLine;

						inputLine = flujoCabecera_E.readLine();
						System.out.println(inputLine + "\n");

						Listar_documento respuesta = (Listar_documento) flujoDatos_E.readObject();

						if (respuesta.getNerror() == -3) {
							System.out.println("CERTIFICADO INCORRECTO");
						} else if (respuesta.getNerror() == 0) {

							for (int i = 0; i < respuesta.getListaDocumentos().size(); i++) {
								System.out.println(respuesta.getListaDocumentos().get(i));
							}
							System.out.println("");

						} else {
							System.out.println("ERROR");
						}

						break;
					}
					/**************************************
					 * Acabar
					 *************************************/
					case 'A': {
						System.out.println("ACABAR");

						// enviar cabecera
						flujoCabecera.println("ACABAR");
						flujoCabecera.flush();
						// envíar datos
						flujoDatos.flush();

						// Leer Respuesta ...

						//guardarMapa();

						salir = true;
						break;
					}

					default:
						break;

				}
				if (salir == true)
					break;
			}
		} catch (Exception e) {
			e.printStackTrace();
			System.out.println("Error generico.");
		}

	}

	private static void definirAlmacenesCliente(String keySto, String pass, String trustSto) {

		// Almacen de claves

		System.setProperty("javax.net.ssl.keyStore", raizMios + keySto);
		System.setProperty("javax.net.ssl.keyStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.keyStorePassword", pass);

		// Almacen de confianza
		System.setProperty("javax.net.ssl.trustStore", raizMios + trustSto);
		System.setProperty("javax.net.ssl.trustStoreType", "JCEKS");
		System.setProperty("javax.net.ssl.trustStorePassword", pass);

	}

	private static void definirRevocacionOCSP() {

		// Almacen de claves

		System.setProperty("com.sun.net.ssl.checkRevocation", "true");
		System.setProperty("ocsp.enable", "true");

	}

	public static void guardarMapa() throws Exception {
		try (ObjectOutputStream os = new ObjectOutputStream(new FileOutputStream("mapa.txt"))) {
			os.writeObject(mapa);
		}
	}

	public static void leerMapa() {
		try (ObjectInputStream is = new ObjectInputStream(new FileInputStream("mapa.txt"))) {
			mapa = (HashMap<Integer, String>) is.readObject();
		} catch (Exception e) {
			System.out.println("No hay mapa guardado");
		}
	}

	public static char menu() {

		System.out.println(" **** ESCRIBA ****");
		System.out.println(" -- Registrar (R)");
		System.out.println(" -- Listar (L)");
		System.out.println(" -- Recuperar (O)");
		System.out.println(" -- Acabar (A)");

		Scanner reader = new Scanner(System.in);
		String str = reader.next();
		char c = str.charAt(0);

		return c;

	}

	public static Integer menu_id() {

		System.out.println(" **** ESCOJA ****");

		Scanner reader = new Scanner(System.in);
		String str = reader.next();

		return Integer.parseInt(str);

	}

	public static char menu_tipo() {

		System.out.println(" **** ESCOJA ****");
		System.out.println(" -- Privado (V)");
		System.out.println(" -- Público (P)");

		Scanner reader = new Scanner(System.in);
		String str = reader.next();
		char c = str.charAt(0);

		return c;

	}

	public static String menu_fichero() {

		System.out.println(" **** ESCRIBA LA RUTA COMPLETA/RELATIVA ****");

		Scanner reader = new Scanner(System.in);
		String str = reader.next();

		return str;

	}

	public static String menu_pass() {

		System.out.println(" **** ESCRIBA LA CONTRASEÑA DEL KEYSTORE ****");

		Scanner reader = new Scanner(System.in);
		String str = reader.next();

		return str;

	}

	public static String menu_nombre() {

		System.out.println(" **** ESCRIBA EL NOMBRE PARA GUARDAR [1-100] ****");

		Scanner reader = new Scanner(System.in);
		String str = reader.next();

		return str;

	}

	public static void getKeys(String keySto, String pass, String trustSto) {
		KeyStore ks;
		KeyPair pair;
		FileInputStream is;
		String nombre = "clientetls";

		// Coger claves publica y privada del keyStore

		try {
			ks = KeyStore.getInstance("JCEKS");
			is = new FileInputStream(raizMios + keySto);
			ks.load(is, pass.toCharArray());
			Key key = ks.getKey(nombre, pass.toCharArray());
			if (key instanceof PrivateKey) {
				certificadoFirma = ks.getCertificate(nombre); // Certificado CertFirmaC
				pKfirma = certificadoFirma.getPublicKey();
				pair = new KeyPair(pKfirma, (PrivateKey) key);
				sKfirma = pair.getPrivate();
			}

			// Coger el CertAuthC del keyStore

			nombre = "clientetls_root";
			ks = KeyStore.getInstance("JCEKS");
			is = new FileInputStream(raizMios + keySto);
			ks.load(is, pass.toCharArray());
			key = ks.getKey(nombre, pass.toCharArray());
			if (key instanceof PrivateKey) {
				certificado = ks.getCertificate(nombre);
				pK = certificado.getPublicKey();
				pair = new KeyPair(pK, (PrivateKey) key);
				sK = pair.getPrivate();
			}

			// Coger el certificado del root

			ks = KeyStore.getInstance("JCEKS");
			is = new FileInputStream(raizMios + trustSto);
			ks.load(is, pass.toCharArray());
			certificadoRoot = ks.getCertificate("root ca");

			// Coger la clave pública del servidor conocida por todo el mundo

			byte[] keyBytes = Files.readAllBytes(Paths.get(publicaServer));
			X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			serverPublicKey = kf.generatePublic(spec);

			keyBytes = Files.readAllBytes(Paths.get(publicaServerFirma));
			spec = new X509EncodedKeySpec(keyBytes);
			kf = KeyFactory.getInstance("RSA");
			serverPublicKeyFirma = kf.generatePublic(spec);

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static void cifrarDocumento(String doc) throws Exception {

		String provider = "SunJCE";

		FileInputStream ftextoclaro = new FileInputStream(doc);

		byte[] bloqueclaro = new byte[2024];
		byte[] bloquecifrado = new byte[2048];
		ByteArrayOutputStream docCifrado = new ByteArrayOutputStream();

		String algoritmo = "AES";
		String transformacion = "/CBC/PKCS5Padding";
		int longclave = 192;
		int longbloque;

		// Generar clave simretrica

		KeyGenerator kgen = KeyGenerator.getInstance(algoritmo);
		byte[] skey_raw;
		kgen.init(longclave);
		SecretKey skey = kgen.generateKey();
		skey_raw = skey.getEncoded();
		SecretKeySpec ks = new SecretKeySpec(skey_raw, algoritmo);

		// Cifrar doc

		Cipher cifrador = Cipher.getInstance(algoritmo + transformacion);
		cifrador.init(Cipher.ENCRYPT_MODE, ks);

		int lf = 0;
		while ((longbloque = ftextoclaro.read(bloqueclaro)) > 0) {

			lf = lf + longbloque;
			bloquecifrado = cifrador.update(bloqueclaro, 0, longbloque);
			docCifrado.write(bloquecifrado);

		}
		
		bloquecifrado = cifrador.doFinal();
		docCifrado.write(bloquecifrado);

		documentoCifrado = docCifrado.toByteArray();

		// Parametros para enviar

		AlgorithmParameters param = AlgorithmParameters.getInstance(algoritmo);
		param = cifrador.getParameters();
		paramSerializados = param.getEncoded();

		// Cifrado de la clave simetrica

		algoritmo = serverPublicKey.getAlgorithm();
		transformacion = "/ECB/PKCS1Padding";

		Cipher cifradorClave = Cipher.getInstance(algoritmo + transformacion);
		cifradorClave.init(Cipher.ENCRYPT_MODE, serverPublicKey);
		ByteArrayOutputStream skeyAux = new ByteArrayOutputStream();

		bloquecifrado = cifradorClave.update(skey_raw, 0, skey_raw.length);
		skeyAux.write(bloquecifrado);
		bloquecifrado = cifradorClave.doFinal();
		skeyAux.write(bloquecifrado);

		skeyCifrada = skeyAux.toByteArray();

		ftextoclaro.close();
	}

	public static void firmarDocumento(String doc) throws Exception {

		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		InputStream inn = new ByteArrayInputStream(certificadoFirma.getEncoded());
		X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inn);

		String provider = "SunJCE";
		String algoritmo_base = cert.getPublicKey().getAlgorithm();
		String algoritmo = cert.getSigAlgName(); // Se puede cambiar con cert.getAlgorit

		int longitudClave = 2048;
		int longBloque;
		byte bloque[] = new byte[1024];

		FileInputStream ftextoclaro = new FileInputStream(doc);

		Signature signer = Signature.getInstance(algoritmo);
		signer.initSign(sKfirma);

		while ((longBloque = ftextoclaro.read(bloque)) > 0) {

			signer.update(bloque, 0, longBloque);

		}

		firmaDocumento = signer.sign();

	}

	public static void firmarDocumento(byte[] doc) throws Exception {

		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		InputStream inn = new ByteArrayInputStream(certificadoFirma.getEncoded());
		X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inn);

		String provider = "SunJCE";
		String algoritmo_base = cert.getPublicKey().getAlgorithm();
		String algoritmo = cert.getSigAlgName(); // Se puede cambiar con cert.getAlgorit

		int longitudClave = 2048;
		int longBloque;
		byte bloque[] = new byte[1024];

		ByteArrayInputStream ftextoclaro = new ByteArrayInputStream(doc);

		Signature signer = Signature.getInstance(algoritmo);
		signer.initSign(sKfirma);

		while ((longBloque = ftextoclaro.read(bloque)) > 0) {

			signer.update(bloque, 0, longBloque);

		}

		firmaDocumento = signer.sign();

	}

	private static void descifrarRecuperar(Recuperar_documento reg) throws Exception {

		byte[] dCifrado = reg.getDocumentoCifrado();
		byte[] skCifrada = reg.getClaveSimetricaCifrada();
		byte[] paramCifrado = reg.getParametrosCifrado();

		int longclave = 2048;
		int longbloque;
		byte[] bloqueclaro;
		byte[] bloquecifrado = new byte[1024];

		String provider = "SunJCE";

		// Descifrar la clave simetrica con la clave privada del cliente

		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		InputStream inn = new ByteArrayInputStream(reg.getCertificadoCifradoC());
		X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inn);

		String algoritmo = cert.getPublicKey().getAlgorithm();
		String transformacion = "/ECB/PKCS1Padding";

		Cipher descifrador1 = Cipher.getInstance(algoritmo + transformacion, provider);
		descifrador1.init(Cipher.DECRYPT_MODE, sK);

		bloqueclaro = descifrador1.update(skCifrada, 0, skCifrada.length);
		bloqueclaro = descifrador1.doFinal();

		// Descifrar el documento con la clave simetrica recien descifrada

		algoritmo = "AES";
		transformacion = "/CBC/PKCS5Padding";
		SecretKeySpec ks = new SecretKeySpec(bloqueclaro, algoritmo);

		Cipher descifrador2 = Cipher.getInstance(algoritmo + transformacion, provider);
		AlgorithmParameters params = AlgorithmParameters.getInstance(algoritmo, provider);
		params.init(paramCifrado);
		descifrador2.init(Cipher.DECRYPT_MODE, ks, params);

		ByteArrayInputStream docCifrado = new ByteArrayInputStream(dCifrado);
		ByteArrayOutputStream d = new ByteArrayOutputStream();

		int lf = 0;
		while ((longbloque = docCifrado.read(bloquecifrado)) > 0) {

			bloqueclaro = descifrador2.update(bloquecifrado, 0, longbloque);
			d.write(bloqueclaro);
			lf = lf + longbloque;
		}

		bloqueclaro = descifrador2.doFinal();
		d.write(bloqueclaro);
		documentoRecuperar = d.toByteArray();

	}

}