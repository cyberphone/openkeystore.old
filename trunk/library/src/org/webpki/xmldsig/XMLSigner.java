package org.webpki.xmldsig;

import java.io.IOException;

import java.security.cert.X509Certificate;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import javax.security.auth.x500.X500Principal;

import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.CertificateUtil;


public class XMLSigner extends XMLSignerCore
  {

    private boolean include_cert_path;

    private SignerInterface signer_implem;


    public void setExtendedCertPath (boolean flag)
      {
        this.include_cert_path = flag;
      }


    PublicKey populateKeys (XMLSignatureWrapper r) throws GeneralSecurityException, IOException
      {
        // Prepare all certificate data
        r.certificates = signer_implem.prepareSigning (include_cert_path);
        X509Certificate certificate = r.certificates[0];

        r.x509IssuerName = certificate.getIssuerX500Principal().getName (X500Principal.RFC2253);
        r.x509SerialNumber = certificate.getSerialNumber ();
       // Note: only output as a comment and therefore NOT normalized (unreadable)
        r.x509SubjectName = CertificateUtil.convertRFC2253ToLegacy (certificate.getSubjectX500Principal().getName ());
        return certificate.getPublicKey ();
      }

    byte[] getSignatureBlob (byte[] data, SignatureAlgorithms sig_alg) throws GeneralSecurityException, IOException
      {
        return signer_implem.signData (data, sig_alg);
      }


    /**
     * Creates an XMLSigner using the given {@link SignerInterface SignerInterface}.
     */
    public XMLSigner (SignerInterface signer_implem)
      {
        this.signer_implem = signer_implem;
      }

  }
