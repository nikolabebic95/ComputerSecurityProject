package implementation;

import gui.Constants;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import x509.v3.GuiV3;

import java.io.IOException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.*;

class GuiHelper {
    private final GuiV3 gui;

    GuiHelper(GuiV3 gui) {
        this.gui = gui;
    }

    private void keyUsage(X509Certificate certificate) {
        if (certificate.getKeyUsage() != null) {
            gui.setKeyUsage(certificate.getKeyUsage());
        }
    }

    private void issuerAlternativeNames(X509Certificate certificate) {
        HashMap<String, String> map = new HashMap<>();
        map.put("0", "other");
        map.put("1", "rfc822");
        map.put("2", "dns");
        map.put("3", "x400Address");
        map.put("4", "directory");
        map.put("5", "ediParty");
        map.put("6", "uniformResourceIdentifier");
        map.put("7", "ipAddress");
        map.put("8", "registeredId");

        try {
            Collection<List<?>> names = certificate.getIssuerAlternativeNames();
            if (names != null && !names.isEmpty()) {
                ArrayList<String> alternativeNames = new ArrayList<>();
                names.forEach(list -> {
                    String index = list.get(0).toString();
                    String alternativeName = list.get(1).toString();
                    alternativeNames.add(map.get(index) + "=" + alternativeName);
                });

                String ret = String.join(",", alternativeNames);
                gui.setAlternativeName(Constants.IAN, ret);
            }
        } catch (CertificateParsingException e) {
            GuiV3.reportError(e);
        }
    }

    private void inhibitAnyPolicy(X509Certificate certificate) {
        final String oid = Extension.inhibitAnyPolicy.toString();
        byte[] bytes = certificate.getExtensionValue(oid);
        if (bytes == null) return;

        gui.setInhibitAnyPolicy(true);
        try {
            ASN1Integer integer = (ASN1Integer)X509ExtensionUtil.fromExtensionValue(bytes);
            gui.setSkipCerts(integer.getValue().toString());
        } catch (IOException e) {
            GuiV3.reportError(e);
        }
    }

    public void show(X509Certificate certificate) {
        // region Basics
        gui.setSubject(certificate.getSubjectDN().toString());
        gui.setIssuer(certificate.getIssuerDN().toString());
        gui.setVersion(Constants.V3);
        gui.setSerialNumber(certificate.getSerialNumber().toString());
        gui.setNotBefore(certificate.getNotBefore());
        gui.setNotAfter(certificate.getNotAfter());
        gui.setPublicKeyDigestAlgorithm(certificate.getSigAlgName());
        String publicKeyAlgorithm = certificate.getPublicKey().getAlgorithm();
        gui.setPublicKeyAlgorithm(publicKeyAlgorithm);
        gui.setSubjectSignatureAlgorithm(publicKeyAlgorithm);
        gui.setIssuer(certificate.getIssuerDN().toString());
        gui.setIssuerSignatureAlgorithm(publicKeyAlgorithm);
        // endregion

        // region Criticals
        Set<String> criticals = certificate.getCriticalExtensionOIDs();
        criticals.forEach(str -> {
            if (str.equals(Extension.keyUsage.toString())) {
                gui.setCritical(Constants.KU, true);
            } else if (str.equals(Extension.issuerAlternativeName.toString())) {
                gui.setCritical(Constants.IAN, true);
            } else if (str.equals(Extension.inhibitAnyPolicy.toString())) {
                gui.setCritical(Constants.IAP, true);
            }
        });
        // endregion

        keyUsage(certificate);
        issuerAlternativeNames(certificate);
        inhibitAnyPolicy(certificate);
    }
}
