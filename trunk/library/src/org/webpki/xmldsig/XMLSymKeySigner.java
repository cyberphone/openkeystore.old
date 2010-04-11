package org.webpki.xmldsig;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;


public class XMLSymKeySigner extends XMLSignerCore
  {
    SymKeySignerInterface sym_signer;
    
    String key_name = "symmetric-key";

    PublicKey populateKeys (XMLSignatureWrapper r) throws GeneralSecurityException, IOException
      {
        return null;
      }

    byte[] getSignatureBlob (byte[] data, SignatureAlgorithms sig_alg) throws GeneralSecurityException, IOException
      {
        return sym_signer.signData (data);
      }


    /**
     * Creates an XMLSymKeySigner.
     */
    public XMLSymKeySigner (SymKeySignerInterface sym_signer)
      {
        this.sym_signer = sym_signer;
      }
    
    public void SetKeyName (String key_name)
      {
        this.key_name = key_name;
      }
 
  }
