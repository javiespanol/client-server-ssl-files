import java.io.Serializable;

public class Registrar_documento implements Serializable{
    
    private static final long serialVersionUID = 6392106198310247028L;


    //REQUEST
    private String nombreDoc;
    private String tipoDocumento;
    private byte[] documentoCifrado;
    private byte[] claveSimetricaCifrada;
    private byte[] parametrosCifrado;
    private byte[] firmaDocumento;
    private byte[] certificadoFirmaC;
    private byte[] certificadoCifradoC;
    


    //RESPONSE
    private Integer nERROR;
    private Integer idRegistro;
    private Long selloTemporal;
    private String idPropietario;
    private byte[] SigRD;
    private byte[] certificadoFirmaS;


    public void request(String cadena, String tipo, byte[] documento, byte[] clave, byte[] parametros, byte[] firma, byte[] certFirma,  byte[] certAuth){
        nombreDoc=cadena;
        tipoDocumento=tipo;
        documentoCifrado=documento;
        claveSimetricaCifrada=clave;
        parametrosCifrado=parametros;
        firmaDocumento=firma;
        certificadoFirmaC=certFirma;
        certificadoCifradoC=certAuth;
    }
    
    public void response(Integer nE, Integer idR, Long sello, String idP, byte[] sig, byte[] certFir){
        nERROR=nE;
        idRegistro=idR;
        selloTemporal=sello;
        idPropietario=idP;
        SigRD=sig;
        certificadoFirmaS=certFir;
    }

    public byte[] getCertificadoFirmaS(){
        return certificadoFirmaS;
    }

    public byte[] getSigRD(){
        return SigRD;
    }

    public String getIdPropietario(){
        return idPropietario;
    }

    public Long getSelloTemporal(){
        return selloTemporal;
    }

    public Integer getNerror(){
        return nERROR;
    }
    
    public Integer getIdRegistro(){
        return idRegistro;
    }

    public void response(int nE){
        nERROR=nE;
    }

    public String getNombreDoc(){
        return nombreDoc;
    }

    public String getTipo(){
        return tipoDocumento;
    }

    public byte[] getDocumentoCifrado(){
        return documentoCifrado;
    }

    public byte[] getCalveSimetricaCifrada(){
        return claveSimetricaCifrada;
    }

    public byte[] getParametrosCifrado(){
        return parametrosCifrado;
    }

    public byte[] getCertificadoFirmaC(){
        return certificadoFirmaC;
    }

    public byte[] getCertificadoCifradoC(){
        return certificadoCifradoC;
    }

    public byte[] getFirmaDocumento(){
        return firmaDocumento;
    }
}