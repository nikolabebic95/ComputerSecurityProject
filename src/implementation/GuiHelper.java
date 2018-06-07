package implementation;

import gui.Constants;
import org.bouncycastle.asn1.x509.Extension;
import x509.v3.GuiV3;

import java.security.cert.X509Certificate;

class GuiHelper {
    private final GuiV3 gui;

    GuiHelper(GuiV3 gui) {
        this.gui = gui;
    }

    public void show(X509Certificate certificate) {
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

        // TODO: Finish
        gui.setCritical(Constants.CP, certificate.getCriticalExtensionOIDs().contains(Extension.certificatePolicies.toString()));
    }
}
