package org.webpki.hlca;

import java.io.IOException;

import org.webpki.crypto.MacAlgorithms;

import org.webpki.sks.SecureKeyStore;



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
        return sks.performHMAC (key_handle, algorithm.getURI (), getAuthorization (), data);
      }
  }
