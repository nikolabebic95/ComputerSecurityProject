package implementation;

import gui.Constants;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import x509.v3.GuiV3;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
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
    private static CertificateFactory factory;

    static {
        try {
            factory = CertificateFactory.getInstance("X.509");
        } catch (CertificateException e) {
            System.exit(1);
        }
    }

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

    int verifyCertificate(X509Certificate certificate, String alias) {
        try {
            if (keyStoreImpl.isCertificateEntry(alias)) {
                return ConstantsHelper.LOAD_TRUSTED;
            }

            Certificate[] chain = keyStoreImpl.getCertificateChain(alias);
            if (chain.length == 1) {
                certificate.verify(certificate.getPublicKey());
                if (certificate.getBasicConstraints() != -1) {
                    return ConstantsHelper.LOAD_SIGNED;
                }

                return ConstantsHelper.LOAD_NOT_SIGNED;
            } else {
                for (int i = 0; i < chain.length - 1; i++) {
                    chain[i].verify(chain[i + 1].getPublicKey());
                    if (((X509Certificate)chain[i + 1]).getBasicConstraints() == -1) {
                        return ConstantsHelper.LOAD_NOT_SIGNED;
                    }
                }

                return ConstantsHelper.LOAD_SIGNED;
            }

        } catch (KeyStoreException e) {
            return ConstantsHelper.LOAD_ERROR;
        } catch (CertificateException | NoSuchAlgorithmException | InvalidKeyException | NoSuchProviderException | SignatureException e) {
            return ConstantsHelper.LOAD_NOT_SIGNED;
        }
    }

    public boolean generateKeyPair(String alias, int seed, GuiV3 gui) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(seed, random);
            KeyPair generated = keyPairGenerator.generateKeyPair();
            Certificate[] chain = new Certificate[1];
            chain[0] = CertificateCreator.createCertificateFromKeyPair(generated, gui);
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

    boolean importCertificate(String file, String alias) {
        try (FileInputStream fis = new FileInputStream(file)) {
            try (DataInputStream dis = new DataInputStream(fis)) {
                byte[] bytes = new byte[dis.available()];
                dis.readFully(bytes);
                try (ByteArrayInputStream bis = new ByteArrayInputStream(bytes)) {
                    Collection<? extends Certificate> certificates = factory.generateCertificates(bis);
                    certificates.forEach(certificate -> {
                        try {
                            keyStoreImpl.setCertificateEntry(alias, certificate);
                            saveLocalKeyStoreToFile();
                        } catch (KeyStoreException e) {
                            logException(e);
                        }
                    });

                    return true;
                }
            }
        } catch (IOException | CertificateException e) {
            logException(e);
        }
        return false;
    }

    boolean exportCertificate(String file, String alias, int encoding, int format) {
        try {
            if (encoding == Constants.DER) {
                if (format == Constants.HEAD) {
                    try (FileOutputStream fos = new FileOutputStream(file)) {
                        byte[] certificate = keyStoreImpl.getCertificate(alias).getEncoded();
                        fos.write(certificate);
                        return true;
                    }
                }
            } else if (encoding == Constants.PEM) {
                if (format == Constants.HEAD) {
                    try (FileWriter fw = new FileWriter(file)) {
                        try (PemWriter pw = new PemWriter(fw)) {
                            byte[] certificate = keyStoreImpl.getCertificate(alias).getEncoded();
                            pw.writeObject(new PemObject("CERTIFICATE", certificate));
                            return true;
                        }
                    }
                } else if (format == Constants.CHAIN) {
                    Certificate[] chain = keyStoreImpl.getCertificateChain(alias);
                    try (FileWriter fw = new FileWriter(file)) {
                        try (PemWriter pw = new PemWriter(fw)) {
                            for (Certificate certificate : chain) {
                                pw.writeObject(new PemObject("CERTIFICATE", certificate.getEncoded()));
                            }

                            return true;
                        }
                    }
                }
            }
        } catch (IOException | KeyStoreException | CertificateEncodingException e) {
            logException(e);
        }

        return false;
    }

    // endregion

    // region CSR

    public boolean exportCsr(String file, String alias, String algorithm) {
        try {
            X509Certificate certificate = (X509Certificate) keyStoreImpl.getCertificate(alias);

            X500Name name = CertificateCreator.getName(StringUtility.getProperSubjectIssuerString(certificate.getSubjectDN().toString()));
            SubjectPublicKeyInfo info = SubjectPublicKeyInfo.getInstance(certificate.getPublicKey().getEncoded());
            PKCS10CertificationRequestBuilder builder = new PKCS10CertificationRequestBuilder(name, info);
            Key key = keyStoreImpl.getKey(alias, null);
            AlgorithmIdentifier signature = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
            AlgorithmIdentifier digest = new DefaultDigestAlgorithmIdentifierFinder().find(signature);
            AsymmetricKeyParameter parameter = PrivateKeyFactory.createKey(key.getEncoded());
            ContentSigner signer = new BcRSAContentSignerBuilder(signature, digest).build(parameter);
            PKCS10CertificationRequest request = builder.build(signer);

            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(request.getEncoded());
            }

            return true;
        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableKeyException | IOException | OperatorCreationException e) {
            logException(e);
            return false;
        }
    }

    public String importCsr(String file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            try (DataInputStream dis = new DataInputStream(fis)) {
                byte[] data = new byte[dis.available()];
                dis.readFully(data);
                PKCS10CertificationRequest request = new PKCS10CertificationRequest(data);
                ContentVerifierProvider provider = new JcaContentVerifierProviderBuilder().build(request.getSubjectPublicKeyInfo());
                if (request.isSignatureValid(provider)) {
                    return StringUtility.getProperSubjectIssuerString(request.getSubject().toString());
                }

                GuiV3.reportError("CSR does not have a valid signature");
                return null;
            }
        } catch (IOException | OperatorCreationException | PKCSException e) {
            logException(e);
            return null;
        }
    }

    // endregion

    // region Utilities

    public boolean importCaReply(String file, String alias) {
        try (FileInputStream fis = new FileInputStream(file)) {
            Collection<? extends Certificate> chain = CertificateFactory.getInstance("X.509").generateCertificates(fis);
            Key key = keyStoreImpl.getKey(alias, null);
            keyStoreImpl.deleteEntry(alias);
            keyStoreImpl.setKeyEntry(alias, key, null, chain.toArray(new Certificate[chain.size()]));
            return true;
        } catch (IOException | CertificateException | NoSuchAlgorithmException | UnrecoverableKeyException | KeyStoreException e) {
            logException(e);
            return false;
        }
    }

    public boolean canSign(String alias) {
        try {
            X509Certificate certificate = (X509Certificate) keyStoreImpl.getCertificate(alias);
            if (certificate.getBasicConstraints() == -1) {
                // Not Certificate Authority
                return false;
            }

            boolean[] keyUsage = certificate.getKeyUsage();

            return keyUsage != null && keyUsage[Constants.KEY_CERT_SIGN];
        } catch (KeyStoreException e) {
            logException(e);
            return false;
        }
    }

    public String getSubjectInfo(String alias) {
        try {
            X509Certificate certificate = (X509Certificate)keyStoreImpl.getCertificate(alias);
            return StringUtility.getProperSubjectIssuerString(certificate.getSubjectDN().toString());
        } catch (KeyStoreException e) {
            logException(e);
            return null;
        }
    }

    public String getCertificatePublicKeyParameter(String alias) {
        try {
            Certificate certificate = keyStoreImpl.getCertificate(alias);
            RSAPublicKey key = (RSAPublicKey)certificate.getPublicKey();
            return key.getModulus().bitLength() + "";
        } catch (KeyStoreException e) {
            logException(e);
            return null;
        }
    }

    // endregion
}
