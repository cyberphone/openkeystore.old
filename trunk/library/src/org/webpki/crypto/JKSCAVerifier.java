package org.webpki.crypto;

import java.io.IOException;

import java.security.cert.X509Certificate;
import java.security.KeyStore;
import java.security.GeneralSecurityException;


public class JKSCAVerifier implements VerifierInterface
  {
    private X509Store ca_certificates;

    private boolean abort_on_non_trusted = true;

    private boolean trusted;

    private AuthorityInfoAccessCAIssuersSpi aia_caissuer_handler;

    private X509Certificate[] certificate_path;

    public JKSCAVerifier (KeyStore caCertsKS) throws IOException
      {
        try
          {
            ca_certificates = new X509Store (caCertsKS);
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e.getMessage ());
          }
      }


    public JKSCAVerifier () throws IOException
      {
        try
          {
            KeyStore ks = KeyStore.getInstance ("JKS");
            ks.load (null);
            ca_certificates = new X509Store (ks);
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e.getMessage ());
          }
        abort_on_non_trusted = false;
      }
    

    public boolean verifyCertificatePath (X509Certificate[] in_certificate_path) throws IOException
      {
        try
          {
            certificate_path = in_certificate_path;
            if (aia_caissuer_handler != null)
              {
                certificate_path = aia_caissuer_handler.getUpdatedPath (certificate_path);
              }
            trusted = ca_certificates.verifyCertificates (certificate_path);
            if (abort_on_non_trusted && !trusted)
              {
                throw new IOException ("Unknown CA");
              }
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e.getMessage ());
          }
        return trusted;
      }

    public void setAuthorityInfoAccessCAIssuersHandler (AuthorityInfoAccessCAIssuersSpi aia_caissuer_handler)
      {
        this.aia_caissuer_handler = aia_caissuer_handler;
      }


    public void setTrustedRequired (boolean flag) throws IOException
      {
        abort_on_non_trusted = flag;
      }


    public X509Certificate[] getSignerCertificatePath () throws IOException
      {
        return certificate_path;
      }

 
   public CertificateInfo getSignerCertificateInfo () throws IOException
      {
        return new CertificateInfo (certificate_path[0], trusted);
      }

  }
