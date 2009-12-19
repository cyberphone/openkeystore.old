package org.webpki.crypto;

import java.io.IOException;

import java.util.Enumeration;
import java.security.cert.X509Certificate;
import java.security.cert.Certificate;

import java.security.KeyStore;
import java.security.Signature;
import java.security.PrivateKey;
import java.security.GeneralSecurityException;
import java.security.UnrecoverableKeyException;


public class JKSSignCertStore implements SignerInterface, CertificateSelectorSpi
  {
    private PrivateKey private_key;

    private boolean authorization_failed;

    private KeyStore signer_cert_keystore;

    private X509Certificate signer_certificate;

    private AuthorityInfoAccessCAIssuersSpi aia_caissuer_handler;

    private String key_alias;

    private KeyContainerTypes container_type;


    private void testKey (String key_alias) throws IOException, GeneralSecurityException
      {
        if (!signer_cert_keystore.isKeyEntry (key_alias))
          {
            throw new IOException ("Specified certficate does not have a private key: " + key_alias);
          }
      }


    private X509Certificate[] getCertPath (String key_alias, boolean path_expansion) throws IOException, GeneralSecurityException
      {
        testKey (key_alias);
        Certificate[] cp = signer_cert_keystore.getCertificateChain (key_alias);
        X509Certificate[] certificate_path = new X509Certificate[cp.length];
        for (int q = 0; q < cp.length; q++)
          {
            certificate_path[q] = (X509Certificate)cp[q];
          }
        if (path_expansion && aia_caissuer_handler != null)
          {
            return aia_caissuer_handler.getUpdatedPath (certificate_path);
          }
        return certificate_path;
      }


    public CertificateSelection getCertificateSelection (CertificateFilter[] cfs, 
                                                         CertificateFilter.KeyUsage default_key_usage) throws IOException
      {
        boolean path_expansion = false;
        for (CertificateFilter cf : cfs)
          {
            if (cf.needsPathExpansion ())
              {
                path_expansion = true;
                break;
              }
          }
        CertificateSelection cs = new CertificateSelection (this);
        try
          {
            Enumeration<String> aliases = signer_cert_keystore.aliases ();
            while (aliases.hasMoreElements ())
              {
                String new_key = aliases.nextElement ();
                if (signer_cert_keystore.isKeyEntry (new_key))
                  {
                    X509Certificate[] curr_path = getCertPath (new_key, path_expansion);
                    if (cfs.length == 0)
                      {
                        if (CertificateFilter.matchKeyUsage (default_key_usage, curr_path[0]))
                          {
                            cs.addEntry (new_key, curr_path[0]);
                          }
                        continue;
                      }
                    for (CertificateFilter cf : cfs)
                      {
                        if (cf.matches (curr_path, default_key_usage, container_type))
                          {
                            cs.addEntry (new_key, curr_path[0]);
                            break;  // No need to test other filters for this key; it is already selected
                          }
                      }
                  }
              }
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e.getMessage ());
          }
        return cs;
      }

    
    public X509Certificate[] prepareSigning (boolean include_cert_path) throws IOException
      {
        try
          {
            signer_certificate = (X509Certificate) signer_cert_keystore.getCertificate (key_alias);

            if (include_cert_path)
              {
                return getCertPath (key_alias, true); 
              }

            return new X509Certificate[] {signer_certificate};
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e.getMessage ());
          }
      }


    public void setAuthorityInfoAccessCAIssuersHandler (AuthorityInfoAccessCAIssuersSpi aia_caissuer_handler)
      {
        this.aia_caissuer_handler = aia_caissuer_handler;
      }


    public byte[] signData (byte[] data, SignatureAlgorithms algorithm) throws IOException
      {
        try
          {
            Signature signer = Signature.getInstance (algorithm.getJCEName ());
            signer.initSign (private_key);
            signer.update (data);
            return signer.sign ();
          }
        catch (GeneralSecurityException e)
          {
            authorization_failed = true;
            throw new IOException (e.getMessage ());
          }
      }

 
    public JKSSignCertStore (KeyStore signer_cert_keystore, KeyContainerTypes container_type)
      {
        this.signer_cert_keystore = signer_cert_keystore;
        this.container_type = container_type;
      }


    public boolean authorizationFailed ()
      {
        return authorization_failed;
      }


    public void setKey (String in_key_alias, String password) throws IOException
      {
        key_alias = in_key_alias;
        try
          {
            if (key_alias == null)
              {
                // Search for signer certificate/key:
                Enumeration<String> aliases = signer_cert_keystore.aliases ();

                while (aliases.hasMoreElements ())
                  {
                    String new_key = aliases.nextElement ();
                    if (signer_cert_keystore.isKeyEntry (new_key))
                      {
                        if (key_alias != null)
                          {
                            authorization_failed = true;
                            throw new IOException ("Missing certificate alias and multiple matches");
                          }
                        key_alias = new_key;
                      }
                  }
                if (key_alias == null)
                  {
                    throw new IOException ("No matching certificate");
                  }
              }
            else
              {
                testKey (key_alias);
              }
            private_key = (PrivateKey)signer_cert_keystore.getKey (key_alias, 
                                                                   password == null ? null : password.toCharArray ());
          }
        catch (UnrecoverableKeyException e)
          {
            authorization_failed = true;
            throw new IOException (e.getMessage ());
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e.getMessage ());
          }
      }


    public CertificateInfo getSignerCertificateInfo () throws IOException
      {
        return new CertificateInfo (signer_certificate);
      }

  }
