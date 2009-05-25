package org.webpki.xmldsig;

import java.io.IOException;

import java.security.PublicKey;
import java.security.GeneralSecurityException;


public class XMLAsymKeyVerifier extends XMLVerifierCore
  {
    private PublicKey public_key;


    public PublicKey getPublicKey ()
      {
        return public_key;
      }


    void verify (XMLSignatureWrapper signature) throws IOException, GeneralSecurityException
      {
        // Right kind of XML Dsig?
        if ((public_key = signature.public_key) == null)
          {
            throw new IOException ("Missing public key!");
          }

        // Check signature
        core_verify (signature, public_key);
      }
    
  }
