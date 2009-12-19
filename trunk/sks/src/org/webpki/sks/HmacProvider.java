package org.webpki.sks;

import java.io.IOException;

import org.webpki.crypto.MacAlgorithms;


/**
 * MAC (Message Authentication Code) support.
 */
public class HmacProvider extends HighLevelKeyStore
  {

    public HmacProvider (SecureKeyStore sks)
      {
        super (sks);
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
        byte[] result = sks.symmetricKeyHMAC (data, key_id, algorithm, binary_optional_pin, key_auth_callback);
        conditionalClose ();
        return result;
      }

  }
