package org.webpki.sks;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.util.WrappedException;


/**
 * Digester help object.
 */
class Digester
  {
    MessageDigest md;

    Digester (SignatureAlgorithms algorithm) throws GeneralSecurityException
      {
        md = MessageDigest.getInstance (algorithm.getDigestAlgorithm ().getJCEName ());
      }


    Digester update (byte b) throws GeneralSecurityException
      {
        md.update (b);
        return this;
      }


    Digester update (byte[] data) throws GeneralSecurityException
      {
        md.update (data);
        return this;
      }


    Digester update (byte[] buf, int offset, int len) throws GeneralSecurityException
      {
        md.update (buf, offset, len);
        return this;
      }


    byte[] digest () throws GeneralSecurityException
      {
        return md.digest ();
      }


    static byte[] digestAll (byte[] data, SignatureAlgorithms algorithm)
      {
        try
          {
            return new Digester (algorithm).update (data).digest ();
          }
        catch (GeneralSecurityException gse)
          {
            throw new WrappedException (gse);
          }
      }

  }
