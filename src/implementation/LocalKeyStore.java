package implementation;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

class LocalKeyStore {
    // region Fields

    private KeyStore keyStoreImpl;
    private static final String FILE_NAME = "local_key_store.p12";
    private static final char[] PASSWORD = "pass".toCharArray();

    // endregion

    // region Logging

    private void logException(Exception e) {
        Logger.getLogger(LocalKeyStore.class.getName()).log(Level.SEVERE, e.toString());
    }

    // endregion

    // region Initialization

    {
        createKeyStore();
    }

    private void createKeyStore() {
        try {
            keyStoreImpl = KeyStore.getInstance("pkcs12");
            saveLocalKeyStoreToFile();
        } catch (KeyStoreException e) {
            logException(e);
        }
    }

    private void loadLocalKeyStoreFromFile() {
        try (FileInputStream fis = new FileInputStream(FILE_NAME)) {
            keyStoreImpl.load(fis, PASSWORD);
        } catch (CertificateException | NoSuchAlgorithmException | IOException e) {
            logException(e);
        }
    }

    private void saveLocalKeyStoreToFile() {
        try (FileOutputStream fos = new FileOutputStream(FILE_NAME)) {
            keyStoreImpl.store(fos, PASSWORD);
        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
            logException(e);
        }
    }

    public Enumeration<String> loadLocalKeystore() {
        try {
            loadLocalKeyStoreFromFile();
            return keyStoreImpl.aliases();
        } catch (KeyStoreException e) {
            logException(e);
            return null;
        }
    }

    // endregion
}
