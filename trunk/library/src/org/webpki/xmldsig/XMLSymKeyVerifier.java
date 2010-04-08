package org.webpki.xmldsig;

import java.io.IOException;

import java.security.GeneralSecurityException;

import org.webpki.crypto.SymKeyVerifierInterface;


public class XMLSymKeyVerifier extends XMLVerifierCore
  {
    SymKeyVerifierInterface sym_verifier;

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


    public XMLSymKeyVerifier (SymKeyVerifierInterface sym_verifier)
      {
        this.sym_verifier = sym_verifier;
      }

  }
