package org.webpki.xmldsig;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.AsymKeySignerInterface;


public class XMLAsymKeySigner extends XMLSignerCore
  {

    AsymKeySignerInterface signer;

    PublicKey populateKeys (XMLSignatureWrapper r) throws GeneralSecurityException, IOException
      {
        return r.public_key = signer.getPublicKey ();
      }

    byte[] getSignatureBlob (byte[] data, SignatureAlgorithms sig_alg) throws GeneralSecurityException, IOException
      {
        return signer.signData (data, sig_alg);
      }


    /**
     * Creates an XMLAsymKeySigner.
     */
    public XMLAsymKeySigner (AsymKeySignerInterface signer)
      {
        this.signer = signer;
      }

  }
