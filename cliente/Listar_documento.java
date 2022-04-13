import java.io.Serializable;
import java.util.*;

public class Listar_documento implements Serializable{

    private static final long serialVersionUID = 6392106198310247028L;


    //REQUEST
    private String tipo;
    private byte[] certificadoCifradoC;
    

    //RESPONSE
    private Integer nERROR;
    private ArrayList<String> listaDocumentos;


    public void request(String type, byte[] cert){
        tipo=type;
        certificadoCifradoC=cert;
    }

    public void response(Integer nE){
        nERROR=nE;
    }

    public void response(Integer nE, ArrayList<String>lista){
        nERROR=nE;
        listaDocumentos=lista;
    }

    public String getTipo(){
        return tipo;
    }

    public byte[] getCertificadoCifradoC(){
        return certificadoCifradoC;
    }

    public Integer getNerror(){
        return nERROR;
    }

    public ArrayList<String> getListaDocumentos(){
        return listaDocumentos;
    }
    
}