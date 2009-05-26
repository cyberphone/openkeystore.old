package org.webpki.jce;

import java.io.IOException;

import org.webpki.crypto.MacAlgorithms;

import org.webpki.jce.crypto.CryptoDriver;

/**
 * MAC (Message Authentication Code) support.
 */
public class HmacProvider extends UniversalKeyStore
  {

    public HmacProvider (int user_id)
      {
        super (user_id);
      }


    boolean wantAsymmetricKeys ()
      {
        return false;
      }


    /**
     * Create MAC of the data using the opened key.
     */
    public byte[] mac (byte[] data, MacAlgorithms algorithm) throws IOException
      {
        checkSymmetricKeyAndAlgorithm (algorithm.getURI ());
        byte[] result = CryptoDriver.symmetricKeyHMAC (data,
                                                       secret_key_handle,
                                                       algorithm);
        conditionalClose ();
        return result;
      }

  }
