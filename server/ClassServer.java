import java.net.*;
import java.io.*;
import java.util.Date;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.x500.X500Principal;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.AlgorithmParameters;

public abstract class ClassServer implements Runnable {

	private ServerSocket server = null;
	private PrivateKey sK;
	private PublicKey pK;
	private PrivateKey sKfirma;
	private PublicKey pKfirma;
	private SecretKeySpec miClave;
	private Certificate certificadoS;
	private Certificate certificadoFirmaS;
	private Certificate certificadoRoot;
	private int sesion = 0;
	private Integer idRegistro = 0;
	private byte[] documento;
	private byte[] documentoCifradoRegistrar;
	private byte[] documentoRecuperar;
	private byte[] skeyCifradaRecuperar;
	private byte[] documentoDescifradoRegistrar;
	private byte[] paramSerializados;
	private byte[] paramSerializadosRecuperar;
	private byte[] SigRD;
	private ArrayList<Integer> listaPublicos;
	private ArrayList<Integer> listaPrivados;
	private ArrayList<String> listaEnviar;
	private HashMap<String, byte[]> mapa = new HashMap<String, byte[]>();

	private String tipoConfidencialidadRecuperar;
	private String alg;
	private Long selloTemporalRecuperar;
	private byte[] SigRDRecuperar;

	public ClassServer(ServerSocket ss, PrivateKey s, PublicKey p, PrivateKey sF, PublicKey pF, Certificate c, Certificate cF, Certificate cR,
			SecretKeySpec mC, String al) {
		server = ss;
		sK = s;
		pK = p;
		sKfirma = sF;
		pKfirma = pF;
		certificadoS = c;
		certificadoFirmaS = cF;
		certificadoRoot = cR;
		miClave = mC;
		listaPrivados = new ArrayList<Integer>();
		listaPublicos = new ArrayList<Integer>();
		listaEnviar = new ArrayList<String>();
		alg = al;
		//inicializarIdRegistro(); Si queremos leer los ficheros en caso de apagar el servidor
		newListener();
	}

	public void run() {

		Socket socket;

		// accept a connection
		try {
			socket = server.accept();

		} catch (IOException e) {
			System.out.println("Class Server died: " + e.getMessage());
			e.printStackTrace();
			return;
		}

		// create a new thread to accept the next connection
		newListener();

		try {
			// Crea dos canales de salida, sobre el socket
			// - uno binario
			// - uno de texto

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
			Integer nError = 0;
			Boolean certErr = false;
			Date date = new Date();
			Long time = date.getTime();
			String idPropietario = "";
			String inputLine = "";

			while (true) {

				if (nError != 0) {

					// enviar cabecera
					flujoCabecera.println("-- Respuesta error --");
					flujoCabecera.flush();

					if (inputLine.equals("REGISTRAR")) {

						Registrar_documento registrar_documento_error = new Registrar_documento();
						registrar_documento_error.response(nError);
						flujoDatos.writeObject(registrar_documento_error);
						flujoDatos.flush();

					} else if (inputLine.equals("LISTAR")) {

						Listar_documento listar_documento_error = new Listar_documento();
						listar_documento_error.response(nError);
						flujoDatos.writeObject(listar_documento_error);
						flujoDatos.flush();

					} else if (inputLine.equals("RECUPERAR")) {

						Recuperar_documento recuperar_documento_error = new Recuperar_documento();
						recuperar_documento_error.response(nError);
						flujoDatos.writeObject(recuperar_documento_error);
						flujoDatos.flush();

					} else {
						System.out.println("ERROR");
					}

					nError = 0;
					certErr = false;
				}

				inputLine = flujoCabecera_E.readLine().trim();

				System.out.println(inputLine);

				if (inputLine.equals("REGISTRAR")) {

					System.out.println("** REGISTRANDO DOCUMENTO **");

					Registrar_documento registrar_documento = (Registrar_documento) flujoDatos_E.readObject();
					String tipo = registrar_documento.getTipo();

					// Ver que tipo es, PRIVADO o PUBLICO

					if (tipo.equals("PRIVADO")) {

						descifrarRegistrar(registrar_documento);

					} else if (tipo.equals("PUBLICO")) {

						documento = registrar_documento.getDocumentoCifrado();

					} else {
						System.out.println("ERROR");
					}

					// Coger los certificados y ver sus SUBJECT e ISSUER

					CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
					InputStream inn = new ByteArrayInputStream(registrar_documento.getCertificadoCifradoC());
					X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inn);
					X500Principal issuerCertAuthC = cert.getIssuerX500Principal();
					X500Principal subjectCertAuthC = cert.getSubjectX500Principal();

					try {
						cert.checkValidity();
					} catch (Exception e) {
						certErr = true;
					}

					inn = new ByteArrayInputStream(certificadoRoot.getEncoded());
					cert = (X509Certificate) certificateFactory.generateCertificate(inn);
					X500Principal issuerCertAuthRoot = cert.getIssuerX500Principal();
					X500Principal subjectCertAuthRoot = cert.getSubjectX500Principal();

					inn = new ByteArrayInputStream(registrar_documento.getCertificadoFirmaC());
					cert = (X509Certificate) certificateFactory.generateCertificate(inn);
					X500Principal issuerCertFirmaC = cert.getIssuerX500Principal();
					X500Principal subjectCertFirmaC = cert.getSubjectX500Principal();

					try {
						cert.checkValidity();
					} catch (Exception e) {
						certErr = true;
					}

					// Comprobar validez certFirma

					if (!issuerCertFirmaC.equals(issuerCertAuthRoot) || !subjectCertAuthC.equals(subjectCertFirmaC) || certErr) {
						nError = -1;
						System.out.println("CERTIFICADO DE FIRMA INCORRECTO");
						continue;
					}

					// VERIFICAR FIRMA

					ByteArrayInputStream docAux = new ByteArrayInputStream(documento);
					int longBloque;
					byte bloque[] = new byte[1024];

					PublicKey clavePublicaCliente = cert.getPublicKey();
					Signature verifier = Signature.getInstance(cert.getSigAlgName());
					verifier.initVerify(clavePublicaCliente);

					while ((longBloque = docAux.read(bloque)) > 0) {
						verifier.update(bloque, 0, longBloque);
					}

					Boolean resultado = false;
					resultado = verifier.verify(registrar_documento.getFirmaDocumento());

					if (!resultado) {
						nError = -2;
						System.out.println("FIRMA INCORRECTA");
						continue;
					}

					idRegistro = idRegistro + 1;
					date = new Date();
					time = date.getTime();

					// FORMAR EL SigRD

					idPropietario = subjectCertFirmaC.toString().substring(3,
							subjectCertFirmaC.toString().indexOf(","));
					String algoritmo = cert.getSigAlgName();
					Signature signer = Signature.getInstance(algoritmo);
					signer.initSign(sKfirma);

					signer.update(idRegistro.toString().getBytes(), 0, idRegistro.toString().getBytes().length);
					signer.update(time.toString().getBytes(), 0, time.toString().getBytes().length);
					signer.update(idPropietario.getBytes(), 0, idPropietario.getBytes().length);
					signer.update(documento, 0, documento.length);
					signer.update(registrar_documento.getFirmaDocumento(), 0,
							registrar_documento.getFirmaDocumento().length);

					SigRD = signer.sign();

					if (tipo.equals("PRIVADO")) {

						cifrarRegistrar();
						try (FileOutputStream stream = new FileOutputStream(
								idRegistro.toString() + "_" + idPropietario + ".sig.cif")) {

							stream.write("Documento:".getBytes());
							stream.write(documentoCifradoRegistrar);
							stream.write("Firma:".getBytes());
							stream.write(registrar_documento.getFirmaDocumento());
							stream.write("idRegistro:".getBytes());
							stream.write(idRegistro.toString().getBytes());
							stream.write("selloTemporal:".getBytes());
							stream.write(time.toString().getBytes());
							stream.write("Nombre:".getBytes());
							stream.write(registrar_documento.getNombreDoc().getBytes());
							stream.write("SigRD:".getBytes());
							stream.write(SigRD);

							listaPrivados.add(idRegistro);

							registrar_documento.response(nError, idRegistro, time, idPropietario, SigRD,
									certificadoFirmaS.getEncoded());

						}

					} else if (tipo.equals("PUBLICO")) {

						try (FileOutputStream stream = new FileOutputStream(
								idRegistro.toString() + "_" + idPropietario + ".sig")) {

							stream.write("Documento:".getBytes());
							stream.write(documento);
							stream.write("Firma:".getBytes());
							stream.write(registrar_documento.getFirmaDocumento());
							stream.write("idRegistro:".getBytes());
							stream.write(idRegistro.toString().getBytes());
							stream.write("selloTemporal:".getBytes());
							stream.write(time.toString().getBytes());
							stream.write("Nombre:".getBytes());
							stream.write(registrar_documento.getNombreDoc().getBytes());
							stream.write("SigRD:".getBytes());
							stream.write(SigRD);

							listaPublicos.add(idRegistro);

							registrar_documento.response(nError, idRegistro, time, idPropietario, SigRD,
									certificadoFirmaS.getEncoded());

						}

					} else {
						System.out.println("ERROR");
					}

					// enviar cabecera
					flujoCabecera.println("- Respuesta registrar -");
					flujoCabecera.flush();

					// envíar datos
					flujoDatos.writeObject(registrar_documento);
					flujoDatos.flush();

				} else if (inputLine.equals("LISTAR")) {

					System.out.println("** PREPARANDO LISTADO **");
					Listar_documento listar_documento = (Listar_documento) flujoDatos_E.readObject();

					String tipo = listar_documento.getTipo();

					CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
					InputStream inn = new ByteArrayInputStream(listar_documento.getCertificadoCifradoC());
					X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inn);
					X500Principal issuerCertAuthC = cert.getIssuerX500Principal();
					X500Principal subjectCertAuthC = cert.getSubjectX500Principal();

					try {
						cert.checkValidity();
					} catch (Exception e) {
						certErr = true;
					}

					inn = new ByteArrayInputStream(certificadoRoot.getEncoded());
					cert = (X509Certificate) certificateFactory.generateCertificate(inn);
					X500Principal issuerCertAuthRoot = cert.getIssuerX500Principal();
					X500Principal subjectCertAuthRoot = cert.getSubjectX500Principal();



					if (!issuerCertAuthRoot.equals(issuerCertAuthC) || certErr) {
						nError = -3;
						System.out.println("CERTIFICADO INCORRECTO");
						continue;
					}

					// Ver que tipo es, PRIVADO o PUBLICO

					ArrayList<String> listAux = new ArrayList<String>();
					File folder = new File(System.getProperty("user.dir"));
					File[] listOfFiles = folder.listFiles();

					if (tipo.equals("PRIV")) {

						for (File file : listOfFiles) {
							if (file.isFile()) {
								if (file.getName().endsWith(".cif") && file.getName().contains(subjectCertAuthC
										.toString().substring(3, subjectCertAuthC.toString().indexOf(",")))) {
									listAux.add(file.getName());
								}
							}
						}

					} else if (tipo.equals("PUB")) {

						for (File file : listOfFiles) {
							if (file.isFile()) {
								if (file.getName().endsWith(".sig")) {
									listAux.add(file.getName());
								}
							}
						}
					} else {
						System.out.println("ERROR");
						continue;
					}

					listaEnviar = new ArrayList<String>();

					for (int i = 0; i < listAux.size(); i++) {

						byte[] aux = Files.readAllBytes(Paths.get(listAux.get(i)));
						ByteArrayInputStream nD = new ByteArrayInputStream(Arrays.copyOfRange(aux,
								KPM.indexOf(aux, "Nombre:".getBytes()) + "Nombre:".getBytes().length,
								KPM.indexOf(aux, "SigRD:".getBytes())));
						ByteArrayInputStream sT = new ByteArrayInputStream(Arrays.copyOfRange(aux,
								KPM.indexOf(aux, "selloTemporal:".getBytes()) + "selloTemporal:".getBytes().length,
								KPM.indexOf(aux, "Nombre:".getBytes())));
						String nombreDoc = new String(nD.readAllBytes());
						String selloTemporal = new String(sT.readAllBytes());
						String idRegistro = listAux.get(i).substring(0, listAux.get(i).indexOf("_"));
						String idProp = listAux.get(i).substring(listAux.get(i).indexOf("_") + 1,
								listAux.get(i).indexOf("."));
						listaEnviar.add("ID: " + idRegistro + " ,id_Propietario: " + idProp + " nombreDoc: " + nombreDoc
								+ " selloTemporal: " + selloTemporal);

					}

					System.out.println(listaEnviar);
					listar_documento.response(0, listaEnviar);

					// enviar cabecera
					flujoCabecera.println("- Respuesta listar -");
					flujoCabecera.flush();

					// envíar datos
					flujoDatos.writeObject(listar_documento);
					flujoDatos.flush();

				} else if (inputLine.equals("RECUPERAR")) {

					System.out.println("** RECUPERANDO DOCUMENTO **");
					Recuperar_documento recuperar_documento = (Recuperar_documento) flujoDatos_E.readObject();

					Integer idReg = recuperar_documento.getIdRegistro();

					CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
					InputStream inn = new ByteArrayInputStream(recuperar_documento.getCertificadoCifradoC());
					X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inn);
					X500Principal issuerCertAuthC = cert.getIssuerX500Principal();
					X500Principal subjectCertAuthC = cert.getSubjectX500Principal();


					CertificateFactory cf = CertificateFactory.getInstance("X.509");
					InputStream innn = new ByteArrayInputStream(certificadoRoot.getEncoded());
					X509Certificate certAux = (X509Certificate)cf.generateCertificate(innn);
					X500Principal issuerCertAuthRoot = certAux.getIssuerX500Principal();
					X500Principal subjectCertAuthRoot = certAux.getSubjectX500Principal();
					
					try {
						cert.checkValidity();
					} catch (Exception e) {
						certErr = true;
					}

					if(!issuerCertAuthRoot.equals(issuerCertAuthC) || certErr){
						nError=-3;
						System.out.println("CERTIFICADO INCORRECTO");
						continue;
					}
					

					String idProp = subjectCertAuthC.toString().substring(3, subjectCertAuthC.toString().indexOf(","));
					tipoConfidencialidadRecuperar = "";
					selloTemporalRecuperar = null;
					Boolean auxBoolean = false;

					if (listaPrivados.contains(idReg)) {

						File folder = new File(System.getProperty("user.dir"));
						File[] listOfFiles = folder.listFiles();
						for (File file : listOfFiles) {
							if (file.isFile()) {
								// Si empieza por idReg y contiene idProp es valido
								if (file.getName().startsWith(idReg.toString() + "_") && file.getName()
										.substring(file.getName().indexOf("_") + 1, file.getName().indexOf("."))
										.equals(idProp)) {

									tipoConfidencialidadRecuperar = "PRIV";
									descifrarRecuperar(file.getName());
									cifrarDocumentoRecuperar(cert.getPublicKey());
									auxBoolean=true;
								}
							}
						}
						if(!auxBoolean){
							nError = -5;
							System.out.println("ACCESO NO PERMITIDO");
							continue;
						}

					} else if (listaPublicos.contains(idReg)) {
						File folder = new File(System.getProperty("user.dir"));
						File[] listOfFiles = folder.listFiles();
						for (File file : listOfFiles) {
							if (file.isFile()) {
								// Si empieza por idReg es valido
								if (file.getName().startsWith(idReg.toString() + "_") && file.getName()
								.substring(file.getName().indexOf("_") + 1, file.getName().indexOf("."))
								.equals(idProp)) {

									byte[] aux = Files.readAllBytes(Paths.get(file.getName()));
									ByteArrayInputStream doc = new ByteArrayInputStream(Arrays.copyOfRange(aux,
											KPM.indexOf(aux, "Documento:".getBytes()) + "Documento:".getBytes().length,
											KPM.indexOf(aux, "Firma:".getBytes())));
									documentoDescifradoRegistrar = doc.readAllBytes();
									documentoRecuperar = documentoDescifradoRegistrar;

									tipoConfidencialidadRecuperar = "PUB";
									selloTemporalRecuperar = Long.parseLong(new String(Arrays.copyOfRange(aux,
											KPM.indexOf(aux, "selloTemporal:".getBytes())
													+ "selloTemporal:".getBytes().length,
											KPM.indexOf(aux, "Nombre:".getBytes()))));
									SigRDRecuperar = Arrays.copyOfRange(aux,
											KPM.indexOf(aux, "SigRD:".getBytes()) + "SigRD:".getBytes().length,
											aux.length);

								}
							}
						}

					} else {
						nError = -4;
						System.out.println("DOCUMENTO NO EXISTENTE");
						continue;
					}

					// En este punto tenemos en documentoDescifradoRegistrar, el documento
					// descifrado con clave secreta si es privado, y el documento tal cual si es
					// publico
					// Ahora hay que cifrar con clave secreta, y cifrar la clave secreta

					recuperar_documento.response(0, tipoConfidencialidadRecuperar, idReg, idProp,
							selloTemporalRecuperar, skeyCifradaRecuperar, documentoRecuperar, SigRDRecuperar,
							certificadoFirmaS.getEncoded(), paramSerializadosRecuperar);

					// enviar cabecera
					flujoCabecera.println("- Respuesta recuperar -");
					flujoCabecera.flush();
					// envíar datos
					flujoDatos.writeObject(recuperar_documento);
					flujoDatos.flush();

				} else if (inputLine.equals("ACABAR")) {

					System.out.println("CERRANDO CONEXION..." + "\n");
					break;

				} else {

					System.out.println("otro\n");

				}

			}

		} catch (Exception e) {
			// eat exception (could log error to log file, but
			// write out to stdout for now).
			System.out.println("error writing response: " + e.getMessage());
			e.printStackTrace();

		} finally {
			try {
				socket.close();
			} catch (IOException e) {
			}
		}
	}

	/********************************************************
	 * newListener()
	 * Create a new thread to listen.
	 *******************************************************/
	private void newListener() {
		(new Thread(this)).start();
		sesion = sesion + 1;
		System.out.println("** SESION NÚMERO:" + sesion + " **");
	}

	private void inicializarIdRegistro() {
		ArrayList<String> listAux = new ArrayList<String>();
		Integer num;
		listaPublicos = new ArrayList<Integer>();
		listaPrivados = new ArrayList<Integer>();
		File folder = new File(System.getProperty("user.dir"));
		File[] listOfFiles = folder.listFiles();
		for (File file : listOfFiles) {
			if (file.isFile()) {
				if (file.getName().endsWith(".sig")) {
					num = Integer.parseInt(file.getName().substring(0, file.getName().indexOf("_")));
					listAux.add(file.getName());
					listaPublicos.add(num);
				} else if (file.getName().endsWith(".cif")) {
					num = Integer.parseInt(file.getName().substring(0, file.getName().indexOf("_")));
					listAux.add(file.getName());
					listaPrivados.add(num);
				}
			}
		}

		Integer max = 0;
		for (int i = 0; i < listAux.size(); i++) {
			Integer idAux = Integer.parseInt(listAux.get(i).substring(0, listAux.get(i).indexOf("_")));
			if (idAux > max) {
				max = idAux;
			}
		}
		idRegistro = max;

	}

	public void cifrarDocumentoRecuperar(PublicKey clientPublicKey) throws Exception {

		String provider = "SunJCE";

		ByteArrayInputStream ftextoclaro = new ByteArrayInputStream(documentoDescifradoRegistrar);

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
		// System.out.println(lf);
		bloquecifrado = cifrador.doFinal();
		docCifrado.write(bloquecifrado);

		documentoRecuperar = docCifrado.toByteArray();

		// Parametros para enviar

		AlgorithmParameters param = AlgorithmParameters.getInstance(algoritmo);
		param = cifrador.getParameters();
		paramSerializadosRecuperar = param.getEncoded();

		// Cifrado de la clave simetrica

		algoritmo = clientPublicKey.getAlgorithm();
		transformacion = "/ECB/PKCS1Padding";

		Cipher cifradorClave = Cipher.getInstance(algoritmo + transformacion);
		cifradorClave.init(Cipher.ENCRYPT_MODE, clientPublicKey);
		ByteArrayOutputStream skeyAux = new ByteArrayOutputStream();

		bloquecifrado = cifradorClave.update(skey_raw, 0, skey_raw.length);
		skeyAux.write(bloquecifrado);
		bloquecifrado = cifradorClave.doFinal();
		skeyAux.write(bloquecifrado);

		skeyCifradaRecuperar = skeyAux.toByteArray();

		ftextoclaro.close();
	}

	private void descifrarRegistrar(Registrar_documento reg) throws Exception {

		byte[] dCifrado = reg.getDocumentoCifrado();
		byte[] skCifrada = reg.getCalveSimetricaCifrada();
		byte[] paramCifrado = reg.getParametrosCifrado();

		int longclave = 2048;
		int longbloque;
		byte[] bloqueclaro;
		byte[] bloquecifrado = new byte[1024];

		String provider = "SunJCE";

		// Descifrar la clave simetrica con la clave privada del server

		CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
		InputStream inn = new ByteArrayInputStream(reg.getCertificadoCifradoC());
		X509Certificate cert = (X509Certificate) certificateFactory.generateCertificate(inn);

		String algoritmo = pK.getAlgorithm();
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
		documento = d.toByteArray();

	}

	private void cifrarRegistrar() throws Exception {

		String provider = "SunJCE";

		byte[] bloqueclaro = new byte[2024];
		byte[] bloquecifrado = new byte[2048];
		ByteArrayOutputStream docCifrado = new ByteArrayOutputStream();
		ByteArrayInputStream doc = new ByteArrayInputStream(documento);

		String algoritmo = alg;
		String transformacion = "/CFB8/NOPADDING";
		int longclave = 192;
		int longbloque;

		// Cifrar doc

		Cipher cifrador = Cipher.getInstance(algoritmo + transformacion);
		cifrador.init(Cipher.ENCRYPT_MODE, miClave);

		AlgorithmParameters param = AlgorithmParameters.getInstance(algoritmo);
		param = cifrador.getParameters();
		paramSerializados = param.getEncoded();
		mapa.put(idRegistro.toString(), paramSerializados);

		while ((longbloque = doc.read(bloqueclaro)) > 0) {
			bloquecifrado = cifrador.update(bloqueclaro, 0, longbloque);
			docCifrado.write(bloquecifrado);
		}

		bloquecifrado = cifrador.doFinal();
		docCifrado.write(bloquecifrado);
		documentoCifradoRegistrar = docCifrado.toByteArray();

	}

	private void descifrarRecuperar(String nombreF) throws Exception {

		String provider = "SunJCE";

		byte[] bloqueclaro = new byte[2024];
		byte[] bloquecifrado = new byte[2048];

		byte[] aux = Files.readAllBytes(Paths.get(nombreF));
		ByteArrayInputStream doc = new ByteArrayInputStream(
				Arrays.copyOfRange(aux, KPM.indexOf(aux, "Documento:".getBytes()) + "Documento:".getBytes().length,
						KPM.indexOf(aux, "Firma:".getBytes())));

		selloTemporalRecuperar = Long.parseLong(new String(Arrays.copyOfRange(aux,
				KPM.indexOf(aux, "selloTemporal:".getBytes()) + "selloTemporal:".getBytes().length,
				KPM.indexOf(aux, "Nombre:".getBytes()))));
		SigRDRecuperar = Arrays.copyOfRange(aux, KPM.indexOf(aux, "SigRD:".getBytes()) + "SigRD:".getBytes().length,
				aux.length);

		ByteArrayOutputStream docDescifrado = new ByteArrayOutputStream();

		String algoritmo = alg;
		String transformacion = "/CFB8/NOPADDING";
		int longclave = 192;
		int longbloque;

		Cipher descifrador = Cipher.getInstance(algoritmo + transformacion, provider);
		AlgorithmParameters params = AlgorithmParameters.getInstance(algoritmo, provider);
		params.init(mapa.get(nombreF.substring(0, nombreF.indexOf("_"))));
		descifrador.init(Cipher.DECRYPT_MODE, miClave, params);

		while ((longbloque = doc.read(bloquecifrado)) > 0) {

			bloqueclaro = descifrador.update(bloquecifrado, 0, longbloque);
			docDescifrado.write(bloqueclaro);
		}

		bloqueclaro = descifrador.doFinal();
		docDescifrado.write(bloqueclaro);
		documentoDescifradoRegistrar = docDescifrado.toByteArray();

	}

}