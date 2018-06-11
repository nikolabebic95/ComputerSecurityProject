package implementation;

import code.GuiException;
import sun.reflect.generics.reflectiveObjects.NotImplementedException;
import x509.v3.CodeV3;
import x509.v3.GuiV3;

import java.security.cert.X509Certificate;
import java.util.Enumeration;

@SuppressWarnings("unused")
public class MyCode extends CodeV3 {

    private LocalKeyStore localKeyStore;
    private GuiHelper guiHelper;

    private void initLocalKeyStore() {
        if (localKeyStore == null) {
            localKeyStore = new LocalKeyStore();
        }
    }

    public MyCode(boolean[] algorithm_conf, boolean[] extensions_conf, boolean extensions_rules) throws GuiException {
        super(algorithm_conf, extensions_conf, extensions_rules);
        guiHelper = new GuiHelper(access);
        initLocalKeyStore();
    }

    @Override
    public Enumeration<String> loadLocalKeystore() {
        // Base constructor calls loadLocalKeystore during construction,
        // so the keystore needs to be initialized. This wouldn't be possible
        // if the keystore was initialized in the declaration, because java
        // order of initialization specifies that first the base constructor
        // is called, and then the child class is initialized.
        initLocalKeyStore();
        return localKeyStore.loadLocalKeystore();
    }

    @Override
    public void resetLocalKeystore() {
        localKeyStore = new LocalKeyStore();
    }

    @Override
    public int loadKeypair(String alias) {
        X509Certificate certificate = localKeyStore.loadCertificate(alias);
        if (certificate == null) {
            return ConstantsHelper.LOAD_ERROR;
        }

        guiHelper.show(certificate);
        return localKeyStore.verifyCertificate(certificate, alias);
    }

    @Override
    public boolean saveKeypair(String alias) {
        try {
            return localKeyStore.generateKeyPair(alias, Integer.parseInt(access.getPublicKeyParameter()), access);
        } catch (NumberFormatException e) {
            GuiV3.reportError("RSA parameter is not an integer");
            return false;
        }
    }

    @Override
    public boolean removeKeypair(String alias) {
        return localKeyStore.removeKeyPair(alias);
    }

    @Override
    public boolean importKeypair(String alias, String file, String password) {
        return localKeyStore.importKeyPair(alias, file, password.toCharArray());
    }

    @Override
    public boolean exportKeypair(String alias, String file, String password) {
        return localKeyStore.exportKeyPair(alias, file, password.toCharArray());
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
