package implementation;

import sun.reflect.generics.reflectiveObjects.NotImplementedException;
import x509.v3.GuiV3;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Enumeration;
import java.util.logging.Level;
import java.util.logging.Logger;

class LocalKeyStore {
    // region Fields

    private KeyStore keyStoreImpl;
    private static final String FILE_NAME = "local_key_store.p12";
    private static final char[] PASSWORD = "pass".toCharArray();
    private static final SecureRandom random = new SecureRandom();

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
            keyStoreImpl.load(null, PASSWORD);
            if (!Files.exists(Paths.get(FILE_NAME))) {
                saveLocalKeyStoreToFile();
            }
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
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

    // region Certificates

    public X509Certificate loadCertificate(String alias) {
        try {
            return (X509Certificate) keyStoreImpl.getCertificate(alias);
        } catch (KeyStoreException e) {
            logException(e);
            return null;
        }
    }

    int verifyCertificate(X509Certificate certificate) {
        // throw new NotImplementedException();
        // TODO: Implement
        return 0;
    }

    public boolean generateKeyPair(String alias, int seed, GuiV3 gui) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(seed, random);
            KeyPair generated = keyPairGenerator.generateKeyPair();
            Certificate[] chain = new Certificate[1];
            chain[0] = CertificateFactory.createCertificateFromKeyPair(generated, gui);
            keyStoreImpl.setKeyEntry(alias, generated.getPrivate(), null, chain);
            saveLocalKeyStoreToFile();
            return true;
        } catch (NoSuchAlgorithmException | KeyStoreException e) {
            logException(e);
            return false;
        }
    }

    public boolean removeKeyPair(String alias) {
        try {
            keyStoreImpl.deleteEntry(alias);
            return true;
        } catch (KeyStoreException e) {
            logException(e);
            return false;
        }
    }

    // endregion

    // region Import/export

    boolean importKeyPair(String alias, String file, char[] password) {
        try {
            KeyStore temp = KeyStore.getInstance("PKCS12");
            try (FileInputStream fis = new FileInputStream(file)) {
                temp.load(fis, password);
            }

            ArrayList<String> aliases = Collections.list(temp.aliases());
            aliases.forEach(importedAlias -> {
                try {
                    Key key = temp.getKey(importedAlias, password);
                    Certificate[] chain = temp.getCertificateChain(importedAlias);
                    keyStoreImpl.setKeyEntry(alias, key, null, chain);
                } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException e) {
                    logException(e);
                }
            });

            saveLocalKeyStoreToFile();
            return true;
        } catch (KeyStoreException | IOException | CertificateException | NoSuchAlgorithmException e) {
            logException(e);
            return false;
        }
    }

    boolean exportKeyPair(String alias, String file, char[] password) {
        try {
            KeyStore temp = KeyStore.getInstance("PKCS12");
            temp.load(null, password);

            Key key = keyStoreImpl.getKey(alias, null);
            Certificate[] chain = keyStoreImpl.getCertificateChain(alias);

            temp.setKeyEntry(alias, key, password, chain);

            try (FileOutputStream fos = new FileOutputStream(file)) {
                temp.store(fos, password);
            }

            return true;
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException | UnrecoverableKeyException e) {
            logException(e);
            return false;
        }
    }

    // endregion
}
