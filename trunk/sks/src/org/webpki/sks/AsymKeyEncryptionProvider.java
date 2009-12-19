package org.webpki.sks;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;

import org.webpki.crypto.AsymEncryptionAlgorithms;

import org.webpki.util.WrappedException;



/**
 * PKI encryption and decryption support.
 */
public class AsymKeyEncryptionProvider extends CertificateSupport
  {
    /**
     * Initializes the object for a specific keystore.
     */
    public AsymKeyEncryptionProvider (SecureKeyStore sks)
      {
        super (sks);
      }


    /**
     * Encrypts data using the public key.
     */
    public byte[] encrypt (byte[] data, X509Certificate public_key, AsymEncryptionAlgorithms algorithm) throws IOException
      {
        try
          {
            Cipher cipher = Cipher.getInstance (algorithm.getJCEName ());
            cipher.init (Cipher.ENCRYPT_MODE, public_key.getPublicKey ());
            return cipher.doFinal (data);
          }
        catch (GeneralSecurityException gse)
          {
            throw new WrappedException (gse);
          }
      }


    /**
     * Encrypts data using the public key.
     */
    public byte[] encrypt (byte[] data, int key_id, AsymEncryptionAlgorithms algorithm) throws IOException
      {
        try
          {
            Connection conn = KeyUtil.getDatabaseConnection ();
            PreparedStatement pstmt = conn.prepareStatement ("SELECT CertPath FROM USERKEYS WHERE KeyID=? " +
                                                             "AND UserID=? AND PrivateKey IS NOT NULL");
            pstmt.setInt (1, key_id);
            pstmt.setInt (2, user_id);
            ResultSet rs = pstmt.executeQuery ();
            X509Certificate public_key = null;
            if (rs.next ())
              {
                public_key = KeyUtil.restoreCertificatePathFromDB (rs.getBytes (1))[0];
              }
            rs.close ();
            pstmt.close ();
            conn.close ();
            if (public_key == null)
              {
                throw new IOException ("Couldn't get CertPath for key: " + key_id);
              }
            return encrypt (data, public_key, algorithm);
          }
        catch (SQLException sqle)
          {
            throw new WrappedException (sqle);
          }
      }


    /**
     * Decrypts data using the private key.
     */
    public byte[] decrypt (byte[] data, AsymEncryptionAlgorithms algorithm) throws IOException
      {
        checkPrivateKey ();
        byte[] result = sks.privateKeyDecrypt (data,
                                               key_id,
                                               algorithm,
                                               binary_optional_pin,
                                               key_auth_callback);
        conditionalClose ();
        return result;
      }

  }
