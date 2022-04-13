import java.io.Serializable;

public class Recuperar_documento implements Serializable{
    
    private static final long serialVersionUID = 6392106198310247028L;


    private Integer idRegistro;

    //REQUEST
    private byte[] certificadoCifradoC;



    //RESPONSE
    private Integer nERROR;
    private String tipoDocumento;
    private Long selloTemporal;
    private String idPropietario;
    private byte[] SigRD;
    private byte[] certificadoFirmaS;
    private byte[] documentoCifrado;
    private byte[] claveSimetricaCifrada;
    private byte[] parametrosCifrado;


    public void request(byte[] cert, Integer idR){
        certificadoCifradoC=cert;
        idRegistro=idR;
    }

    public void response(Integer nE){
        nERROR=nE;
    }

    public void response(Integer nE, String tipo, Integer idR, String idP, Long sello, byte[] clave, byte[] doc, byte[] sig, byte[] certFirma, byte[] param){
        tipoDocumento=tipo;
        nERROR=nE;
        idRegistro=idR;
        idPropietario=idP;
        selloTemporal=sello;
        claveSimetricaCifrada=clave;
        documentoCifrado=doc;
        SigRD=sig;
        certificadoFirmaS=certFirma;
        parametrosCifrado=param;

    }

    public Integer getNerror(){
        return nERROR;
    }

    public String getTipoDocumento(){
        return tipoDocumento;
    }

    public Integer getIdRegistro(){
        return idRegistro;
    }

    public String getIdPropietario(){
        return idPropietario;
    }

    public byte[] getCertificadoCifradoC(){
        return certificadoCifradoC;
    }

    public byte[] getParametrosCifrado(){
        return parametrosCifrado;
    }

    public Long getSelloTemporal(){
        return selloTemporal;
    }

    public byte[] getSigRD(){
        return SigRD;
    }

    public byte[] getCertificadoFirmaS(){
        return certificadoFirmaS;
    }

    public byte[] getDocumentoCifrado(){
        return documentoCifrado;
    }

    public byte[] getClaveSimetricaCifrada(){
        return claveSimetricaCifrada;
    }
}
