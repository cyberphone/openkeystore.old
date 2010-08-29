package org.webpki.hlca;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import javax.crypto.Cipher;

import org.webpki.crypto.AsymEncryptionAlgorithms;

import org.webpki.sks.SecureKeyStore;

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
    public byte[] encrypt (byte[] data, int key_handle, AsymEncryptionAlgorithms algorithm) throws IOException
      {
        return encrypt (data, sks.getKeyAttributes (key_handle).getCertificatePath ()[0], algorithm);
      }


    /**
     * Decrypts data using the private key.
     */
    public byte[] decrypt (byte[] data, AsymEncryptionAlgorithms algorithm) throws IOException
      {
        byte[] result = sks.asymmetricKeyDecrypt (key_handle,
                                                  new byte[0],
                                                  algorithm.getURI (),
                                                  getAuthorization (),
                                                  data);
        return result;
      }

  }
