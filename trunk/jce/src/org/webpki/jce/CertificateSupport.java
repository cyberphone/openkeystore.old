package org.webpki.jce;

import java.io.IOException;

import java.util.LinkedHashMap;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import org.webpki.crypto.AuthorityInfoAccessCAIssuersCache;
import org.webpki.crypto.CertificateFilter;

import org.webpki.util.WrappedException;


/**
 * PKI certificate high-level support class.
 */
abstract class CertificateSupport extends UniversalKeyStore
  {

    private AuthorityInfoAccessCAIssuersCache aia_caissuer_handler = new AuthorityInfoAccessCAIssuersCache ();

    private LinkedHashMap<Integer,SelectedCertificate> selection = new LinkedHashMap<Integer,SelectedCertificate> ();

    /**
     * Initializes the object for a specfic user.
     */
    public CertificateSupport (int user_id)
      {
        super (user_id);
      }


    boolean wantAsymmetricKeys ()
      {
        return true;
      }
   

    void addEntry (int key_int, X509Certificate certificate)
      {
        selection.put (key_int, new SelectedCertificate (certificate, key_int, user_id));
      }


    X509Certificate[] getCertPath (int key_id, boolean path_expansion) throws IOException, GeneralSecurityException, SQLException
      {
        if (path_expansion)
          {
            X509Certificate[] new_cert_path = aia_caissuer_handler.getUpdatedPath (cert_path);
            if (new_cert_path.length > cert_path.length)
              {
                Connection conn = KeyUtil.getDatabaseConnection ();
                PreparedStatement pstmt = conn.prepareStatement ("UPDATE USERKEYS SET CertPath=? WHERE KeyID=?");
                pstmt.setBytes (1, KeyUtil.createDBCertificatePath (new_cert_path));
                pstmt.setInt (2, key_id);
                pstmt.executeUpdate ();
                pstmt.close ();
                conn.close ();
                return new_cert_path;
              }
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
        Connection conn = null;
        PreparedStatement pstmt = null;
        ResultSet rs = null;
        try
          {
            conn = KeyUtil.getDatabaseConnection ();
            pstmt = conn.prepareStatement ("SELECT USERKEYS.KeyId, " +
                                                  "USERKEYS.CertPath " +
                                           "FROM USERKEYS " +
                                           "WHERE USERKEYS.UserID=? " +
                                           (wantAsymmetricKeys () ? "AND USERKEYS.PrivateKey IS NOT NULL " : "") +
                                           "AND USERKEYS.CertPath IS NOT NULL ORDER BY USERKEYS.KeyId ASC");
            pstmt.setInt (1, user_id);
            rs = pstmt.executeQuery ();
            while (rs.next ())
              {
                int key_id = rs.getInt (1);
                cert_path = KeyUtil.restoreCertificatePathFromDB (rs.getBytes (2));
                if (wantAsymmetricKeys ())
                  {
                    // Standard PKI usage
                    cert_path = getCertPath (key_id, path_expansion);
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
                        addEntry (key_id, cert_path[0]);
                      }
                    continue;
                  }
                for (CertificateFilter cf : cfs)
                  {
                    if (cf.matches (cert_path, default_key_usage, null))
                      {
                        addEntry (key_id, cert_path[0]);
                        break;  // No need to test other filters for this key; it is already selected
                      }
                  }
              }
            rs.close ();
            pstmt.close ();
            conn.close ();
          }
        catch (GeneralSecurityException gse)
          {
            throw new WrappedException (gse);
          }
        catch (SQLException sqle)
          {
            throw new WrappedException (sqle);
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
     * @param pin A PIN or password value needed for opening the key.  For keys that
     * are not PIN or password protected this value should be <code>null</code>.
     * @return <code>true</code> if successful else <code>false</code>.
     * @throws IOException if there are hard errors.
     */
    public boolean open (SelectedCertificate selected_certificate, String pin) throws IOException
      {
        return open (selected_certificate.key_id, pin);
      }

  }
