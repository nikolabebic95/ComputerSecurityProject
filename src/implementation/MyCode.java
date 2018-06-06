package implementation;

import code.GuiException;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;
import x509.v3.CodeV3;

import java.util.Enumeration;

@SuppressWarnings("unused")
public class MyCode extends CodeV3 {

    private LocalKeyStore localKeyStore = new LocalKeyStore();

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        return localKeyStore.loadLocalKeystore();
    }

    @Override
    public void resetLocalKeystore() {
        localKeyStore = new LocalKeyStore();
    }

    @Override
    public int loadKeypair(String s) {
        throw new NotImplementedException();
    }

    @Override
    public boolean saveKeypair(String s) {
        throw new NotImplementedException();
    }

    @Override
    public boolean removeKeypair(String s) {
        throw new NotImplementedException();
    }

    @Override
    public boolean importKeypair(String s, String s1, String s2) {
        throw new NotImplementedException();
    }

    @Override
    public boolean exportKeypair(String s, String s1, String s2) {
        throw new NotImplementedException();
    }

    @Override
    public boolean importCertificate(String s, String s1) {
        throw new NotImplementedException();
    }

    @Override
    public boolean exportCertificate(String s, String s1, int i, int i1) {
        throw new NotImplementedException();
    }

    @Override
    public boolean exportCSR(String s, String s1, String s2) {
        throw new NotImplementedException();
    }

    @Override
    public String importCSR(String s) {
        throw new NotImplementedException();
    }

    @Override
    public boolean signCSR(String s, String s1, String s2) {
        throw new NotImplementedException();
    }

    @Override
    public boolean importCAReply(String s, String s1) {
        throw new NotImplementedException();
    }

    @Override
    public boolean canSign(String s) {
        throw new NotImplementedException();
    }

    @Override
    public String getSubjectInfo(String s) {
        throw new NotImplementedException();
    }

    @Override
    public String getCertPublicKeyAlgorithm(String s) {
        throw new NotImplementedException();
    }

    @Override
    public String getCertPublicKeyParameter(String s) {
        throw new NotImplementedException();
    }
}
