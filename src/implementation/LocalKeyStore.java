package implementation;

import gui.Constants;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.*;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaContentVerifierProviderBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.util.CollectionStore;
import org.bouncycastle.util.Selector;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import x509.v3.GuiV3;

import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

class LocalKeyStore {
    // region Fields

    private KeyStore keyStoreImpl;
    private PKCS10CertificationRequest request;
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
            keyStoreImpl = KeyStore.getInstance("pkcs12", new BouncyCastleProvider());
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
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", new BouncyCastleProvider());
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
            KeyStore temp = KeyStore.getInstance("PKCS12", new BouncyCastleProvider());
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
            KeyStore temp = KeyStore.getInstance("PKCS12", new BouncyCastleProvider());
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
            AlgorithmIdentifier signature = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm);
            AlgorithmIdentifier digest = new DefaultDigestAlgorithmIdentifierFinder().find(signature);
            AsymmetricKeyParameter parameter = PrivateKeyFactory.createKey(keyStoreImpl.getKey(alias, null).getEncoded());
            PKCS10CertificationRequest request = builder.build(new BcRSAContentSignerBuilder(signature, digest).build(parameter));

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
                this.request = request; // signCsr needs this
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

    public boolean signCsr(String file, String alias, String algorithm, GuiV3 gui) {
        PKCS10CertificationRequest request = this.request;
        try {
            X509Certificate certificate = (X509Certificate) keyStoreImpl.getCertificate(alias);
            X500Name issuer = new JcaX509CertificateHolder(certificate).getSubject();
            BigInteger serialNumber = new BigInteger(gui.getSerialNumber());
            Date notBefore = gui.getNotBefore();
            Date notAfter = gui.getNotAfter();
            X500Name subject = request.getSubject();
            PublicKey publicKey = new JcaPKCS10CertificationRequest(request).setProvider(new BouncyCastleProvider()).getPublicKey();

            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(issuer, serialNumber, notBefore, notAfter, subject, publicKey);

            CertificateCreator.keyUsage(builder, gui);
            CertificateCreator.issuerAlternativeNames(builder, gui);
            CertificateCreator.inhibitAnyPolicy(builder, gui);

            PrivateKey privateKey = (PrivateKey) keyStoreImpl.getKey(alias, null);
            ContentSigner signer = new JcaContentSignerBuilder(algorithm).setProvider(new BouncyCastleProvider()).build(privateKey);

            X509Certificate signed = new JcaX509CertificateConverter().getCertificate(builder.build(signer));

            ArrayList<JcaX509CertificateHolder> chain = new ArrayList<>();
            chain.add(new JcaX509CertificateHolder(signed));

            for (Certificate c : keyStoreImpl.getCertificateChain(alias)) {
                X509Certificate xc = (X509Certificate)c;
                chain.add(new JcaX509CertificateHolder(xc));
            }

            CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
            generator.addCertificates(new CollectionStore<>(chain));

            CMSTypedData typedData = new CMSProcessableByteArray(signed.getEncoded());
            CMSSignedData signedData = generator.generate(typedData);

            try (FileOutputStream fos = new FileOutputStream(file)) {
                fos.write(signedData.getEncoded());
            }

            return true;
        } catch (KeyStoreException | InvalidKeyException | NoSuchAlgorithmException | UnrecoverableKeyException | OperatorCreationException | CertificateException | CMSException | IOException e) {
            logException(e);
            return false;
        }
    }

    // endregion

    // region Utilities

    private boolean verifyCaReply(String file, String alias) {
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter().setProvider(new BouncyCastleProvider());

        try (FileInputStream fis = new FileInputStream(file)) {
            try (DataInputStream dis = new DataInputStream(fis)) {
                byte[] bytes = new byte[dis.available()];
                dis.readFully(bytes);

                CMSSignedData signedData = new CMSSignedData(bytes);
                Collection<SignerInformation> collection = signedData.getSignerInfos().getSigners();

                for (SignerInformation signer : collection) {
                    @SuppressWarnings({"unchecked"})
                    Selector<X509CertificateHolder> selector = (Selector<X509CertificateHolder>) signer.getSID();
                    Collection<X509CertificateHolder> holders = signedData.getCertificates().getMatches(selector);

                    Optional<X509CertificateHolder> first = holders.stream().findFirst();
                    if (!first.isPresent()) {
                        continue;
                    }

                    X509CertificateHolder holder = first.get();
                    X509Certificate certificate = converter.getCertificate(holder);

                    if (!signer.verify(new JcaSimpleSignerInfoVerifierBuilder().build(certificate))) {
                        return false;
                    }
                }

                Collection<X509CertificateHolder> holders = signedData.getCertificates().getMatches(null);
                Optional<X509CertificateHolder> first = holders.stream().findFirst();
                if (!first.isPresent()) {
                    return false;
                }

                X509CertificateHolder holder = first.get();
                X509Certificate certificate = converter.getCertificate(holder);
                X509Certificate toVerify = (X509Certificate) keyStoreImpl.getCertificate(alias);

                return toVerify.getSubjectX500Principal().equals(certificate.getSubjectX500Principal());
            }
        } catch (IOException | CMSException | CertificateException | OperatorCreationException | KeyStoreException e) {
            logException(e);
            return false;
        }
    }

    public boolean importCaReply(String file, String alias) {
        if (!verifyCaReply(file, alias)) {
            GuiV3.reportError("CA Reply not valid");
            return false;
        }

        try (FileInputStream fis = new FileInputStream(file)) {
            Collection<? extends Certificate> chain = CertificateFactory.getInstance("X.509").generateCertificates(fis);
            Key key = keyStoreImpl.getKey(alias, null);
            keyStoreImpl.setKeyEntry(alias, key, null, chain.toArray(new Certificate[chain.size()]));
            saveLocalKeyStoreToFile();
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
