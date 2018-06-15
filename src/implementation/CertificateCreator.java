package implementation;

import gui.Constants;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder;
import x509.v3.GuiV3;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;

public final class CertificateCreator {
    private CertificateCreator() {}

    private static final HashMap<Integer, Integer> KEY_USAGES = new HashMap<>();
    static {
        KEY_USAGES.put(0, KeyUsage.digitalSignature);
        KEY_USAGES.put(1, KeyUsage.nonRepudiation);
        KEY_USAGES.put(2, KeyUsage.keyEncipherment);
        KEY_USAGES.put(3, KeyUsage.dataEncipherment);
        KEY_USAGES.put(4, KeyUsage.keyAgreement);
        KEY_USAGES.put(5, KeyUsage.keyCertSign);
        KEY_USAGES.put(6, KeyUsage.cRLSign);
        KEY_USAGES.put(7, KeyUsage.encipherOnly);
        KEY_USAGES.put(8, KeyUsage.decipherOnly);

    }

    private static X500Name getSubject(String commonName, String organization, String organizationUnit, String locality, String state, String country) {
        X500NameBuilder ret = new X500NameBuilder();

        HashMap<ASN1ObjectIdentifier, String> map = new HashMap<>();

        map.put(BCStyle.CN, commonName);
        map.put(BCStyle.O, organization);
        map.put(BCStyle.OU, organizationUnit);
        map.put(BCStyle.L, locality);
        map.put(BCStyle.ST, state);
        map.put(BCStyle.C, country);

        map.forEach((key, value) -> {
            if (!value.isEmpty()) {
                ret.addRDN(key, value);
            }
        });

        return ret.build();
    }

    private static X500Name getSubject(GuiV3 gui) {
        return getSubject(
                gui.getSubjectCommonName(),
                gui.getSubjectOrganization(),
                gui.getSubjectOrganizationUnit(),
                gui.getSubjectLocality(),
                gui.getSubjectState(),
                gui.getSubjectCountry());
    }

    private static void keyUsage(JcaX509v3CertificateBuilder builder, GuiV3 gui) throws CertIOException {
        boolean[] usage = gui.getKeyUsage();
        HashMap<Integer, Integer> keyUsages = new HashMap<>(KEY_USAGES);
        boolean any = false;
        for (int i = 0; i < usage.length; i++) {
            if (usage[i]) any = true;
            else keyUsages.remove(i);
        }

        int ret = 0;

        for (Integer entry : keyUsages.values()) {
            ret |= entry;
        }

        KeyUsage returnUsage = new KeyUsage(ret);
        if (any) builder.addExtension(Extension.keyUsage, gui.isCritical(Constants.KU), returnUsage);
    }

    private static void issuerAlternativeNames(JcaX509v3CertificateBuilder builder, GuiV3 gui) throws CertIOException {
        HashMap<String, Integer> map = new HashMap<>();
        map.put("dns", GeneralName.dNSName);
        map.put("rfc822", GeneralName.dNSName);
        map.put("uniformResourceIdentifier", GeneralName.dNSName);
        map.put("x400Address", GeneralName.dNSName);
        map.put("directory", GeneralName.dNSName);
        map.put("registeredID", GeneralName.dNSName);
        map.put("ipAddress", GeneralName.dNSName);
        map.put("other", GeneralName.dNSName);
        map.put("ediParty", GeneralName.dNSName);

        String[] alternativeNames = gui.getAlternativeName(Constants.IAN);

        if (alternativeNames.length > 0) {
            alternativeNames = alternativeNames[0].split(";");
            GeneralName[] generalNames = new GeneralName[alternativeNames.length];

            for (int i = 0; i < alternativeNames.length; i++) {
                String[] parts = alternativeNames[i].split("=");
                generalNames[i] = new GeneralName(map.get(parts[0]), parts[1]);
            }

            GeneralNames ret = new GeneralNames(generalNames);
            builder.addExtension(Extension.issuerAlternativeName, gui.isCritical(Constants.IAN), ret);
        }
    }

    private static void inhibitAnyPolicy(JcaX509v3CertificateBuilder builder, GuiV3 gui) throws CertIOException {
        if (gui.getInhibitAnyPolicy() && !gui.getSkipCerts().isEmpty()) {
            builder.addExtension(Extension.inhibitAnyPolicy, gui.isCritical(Constants.IAP), new ASN1Integer(new BigInteger(gui.getSkipCerts())));
        }
    }

    public static X509Certificate createCertificateFromKeyPair(KeyPair keyPair, GuiV3 gui) {
        try {
            BigInteger serialNumber = new BigInteger(gui.getSerialNumber());
            Date notBefore = gui.getNotBefore();
            Date notAfter = gui.getNotAfter();
            X500Name subject = getSubject(gui);

            JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(subject, serialNumber, notBefore, notAfter, subject, keyPair.getPublic());

            keyUsage(builder, gui);
            issuerAlternativeNames(builder, gui);
            inhibitAnyPolicy(builder, gui);

            AlgorithmIdentifier signature = new DefaultSignatureAlgorithmIdentifierFinder().find(gui.getPublicKeyDigestAlgorithm());
            AlgorithmIdentifier digest = new DefaultDigestAlgorithmIdentifierFinder().find(signature);
            AsymmetricKeyParameter parameter = PrivateKeyFactory.createKey(keyPair.getPrivate().getEncoded());
            ContentSigner signer = new BcRSAContentSignerBuilder(signature, digest).build(parameter);

            X509CertificateHolder holder = builder.build(signer);
            return new JcaX509CertificateConverter().getCertificate(holder);
        } catch (NumberFormatException | IOException | OperatorCreationException | CertificateException e) {
            return null;
        }
    }

    public static X500Name getName(String subject) {
        String[] arr = new String[6];
        for (int i = 0; i < 6; i++) {
            arr[i] = "";
        }

        HashMap<String, Integer> map = new HashMap<>();
        map.put("CN", 0);
        map.put("O", 1);
        map.put("OU", 2);
        map.put("L", 3);
        map.put("ST", 4);
        map.put("C", 5);

        String[] parts = subject.split(",");
        for (String part : parts) {
            String[] pair = part.split("=");
            arr[map.get(pair[0])] = pair[1];
        }

        return getSubject(arr[0], arr[1], arr[2], arr[3], arr[4], arr[5]);
    }
}
