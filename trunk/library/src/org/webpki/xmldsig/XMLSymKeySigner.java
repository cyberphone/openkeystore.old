package org.webpki.xmldsig;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;


public class XMLSymKeySigner extends XMLSignerCore
  {
    byte[] symmetric_key;

    MacAlgorithms hmac_algorithm;


    PublicKey populateKeys (XMLSignatureWrapper r) throws GeneralSecurityException, IOException
      {
        return null;
      }

    byte[] getSignatureBlob (byte[] data, SignatureAlgorithms sig_alg) throws GeneralSecurityException, IOException
      {
        return hmac_algorithm.digest (symmetric_key, data);
      }


    /**
     * Creates an XMLSymKeySigner.
     */
    public XMLSymKeySigner (byte[] symmetric_key, MacAlgorithms hmac_algorithm)
      {
        this.symmetric_key = symmetric_key;
        this.hmac_algorithm = hmac_algorithm;
      }

  }
