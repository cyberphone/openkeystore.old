package org.webpki.hlca;

import java.io.IOException;

import java.util.LinkedHashMap;

import java.security.cert.X509Certificate;

import org.webpki.crypto.AuthorityInfoAccessCAIssuersCache;
import org.webpki.crypto.CertificateFilter;

import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.KeyAttributes;
import org.webpki.sks.SecureKeyStore;


/**
 * PKI certificate high-level support class.
 */
abstract class CertificateSupport extends HighLevelKeyStore
  {

    private AuthorityInfoAccessCAIssuersCache aia_caissuer_handler = new AuthorityInfoAccessCAIssuersCache ();

    private LinkedHashMap<Integer,SelectedCertificate> selection = new LinkedHashMap<Integer,SelectedCertificate> ();

    /**
     * Initializes the object for a specific keystore.
     */
    public CertificateSupport (SecureKeyStore sks)
      {
        super (sks);
      }


    boolean wantAsymmetricKeys ()
      {
        return true;
      }
   

    void addEntry (int key_handle, X509Certificate certificate)
      {
        selection.put (key_handle, new SelectedCertificate (certificate, key_handle, sks));
      }


    X509Certificate[] getCertPath (X509Certificate[] cert_path, boolean path_expansion) throws IOException
      {
        if (path_expansion)
          {
            return aia_caissuer_handler.getUpdatedPath (cert_path);
          }
        return cert_path;
      }


    /**
     * Filters PKI certificates.  This method is primarily designed for on-line signature and authentication
     * where they relying party provides a filter scheme such as with TLS and WASP.
     */
    public SelectedCertificate[] getCertificateSelection (CertificateFilter[] cfs, CertificateFilter.KeyUsage default_key_usage) throws IOException
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
        EnumeratedKey ek = new EnumeratedKey ();
        while ((ek = sks.enumerateKeys (ek)).isValid ())
          {
            int key_handle = ek.getKeyHandle ();
            KeyAttributes key_attributes = sks.getKeyAttributes (key_handle);
            X509Certificate[] cert_path = key_attributes.getCertificatePath ();
            if (wantAsymmetricKeys ())
              {
                // Standard PKI usage
               if (!key_attributes.isAsymmetric ())
                 {
                   continue;
                 }
               cert_path = getCertPath (cert_path, path_expansion);
              }
            else
              {
                // Key management usage
                cert_path = new X509Certificate[]{cert_path[0]};
              }
            if (cfs.length == 0)
              {
                if (CertificateFilter.matchKeyUsage (default_key_usage, cert_path[0]))
                  {
                    addEntry (key_handle, cert_path[0]);
                  }
                continue;
              }
            for (CertificateFilter cf : cfs)
              {
                if (cf.matches (cert_path, default_key_usage, null))
                  {
                    addEntry (key_handle, cert_path[0]);
                    break;  // No need to test other filters for this key; it is already selected
                  }
              }
          }
        return selection.values ().toArray (new SelectedCertificate[0]);
      }


    /**
     * Filters PKI certificates.  This method is primarily designed for on-line signature and authentication
     * where they relying party provides a filter scheme such as with TLS and WASP.
     */
    public SelectedCertificate[] getCertificateSelection (CertificateFilter cf, CertificateFilter.KeyUsage default_key_usage) throws IOException
      {
        return getCertificateSelection (new CertificateFilter[]{cf}, default_key_usage);
      }


    /**
     * Opens a key (key handle) for cryptographic operations.
     * @param selected_certificate High-level certificate selector.
     * @param optional_pin An optional PIN or password value needed for opening the key.  For keys that
     * are not PIN or password protected this value should be <code>null</code>.
     * @throws IOException if there are hard errors.
     */
    public void open (SelectedCertificate selected_certificate, String optional_pin) throws IOException
      {
        open (selected_certificate.key_id, optional_pin);
      }

  }
