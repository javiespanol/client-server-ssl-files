# client-server-ssl-files
Client - server app with encrypted file exchange

javac *.java

CLIENTE: java cliente KeyStoreClient.jce TrustStoreClient.jce 

SERVER: java registrador KeyStoreServer.jce 1234 TrustStoreServer.jce Blowfish

OCSP: sudo openssl ocsp -port 9080 -index db/index -rsigner root-ocsp.crt -rkey private/root-ocsp.key -CA root-ca.crt -text


***CUIDADO***

Hay que cambiar las variables raizMios, publicaServer, y todas las rutas absolutas que aparezcan en el codigo. También cambiar las IPs en caso de ejecutar en maquinas distintas

Hay que tener instalado OpenSSL, y generar los certificados oportunos.
