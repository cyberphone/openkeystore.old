package org.webpki.xmldsig;

import java.io.IOException;

import java.security.GeneralSecurityException;

import org.webpki.crypto.MacAlgorithms;


public class XMLSymKeyVerifier extends XMLVerifierCore
  {
    byte[] symmetric_key;

    MacAlgorithms optional_required_algorithm;


    void verify (XMLSignatureWrapper signature) throws IOException, GeneralSecurityException
      {
        // Right kind of XML Dsig?
        if (signature.public_key != null || signature.certificates != null)
          {
            throw new IOException ("Missing symmetric key!");
          }

        // Check signature
        core_verify (signature, null);
      }


    public XMLSymKeyVerifier (byte[] symmetric_key, MacAlgorithms optional_required_algorithm)
      {
        this.symmetric_key = symmetric_key;
        this.optional_required_algorithm = optional_required_algorithm;
      }

  }
