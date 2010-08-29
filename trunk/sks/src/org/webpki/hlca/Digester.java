package org.webpki.hlca;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
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
    ByteArrayOutputStream baos;

    Digester (SignatureAlgorithms algorithm) throws GeneralSecurityException
      {
        if (algorithm.getDigestAlgorithm () == null)
          {
            baos = new ByteArrayOutputStream ();
          }
        else
          {
            md = MessageDigest.getInstance (algorithm.getDigestAlgorithm ().getJCEName ());
          }
      }


    Digester update (byte b) throws GeneralSecurityException
      {
        if (md == null)
          {
            baos.write (b);
          }
        else
          {
            md.update (b);
          }
        return this;
      }


    Digester update (byte[] data) throws GeneralSecurityException
      {
        if (md == null)
          {
            try
              {
                baos.write (data);
              } 
            catch (IOException e)
              {
                throw new GeneralSecurityException (e);
              }
          }
        else
          {
            md.update (data);
          }
        return this;
      }


    Digester update (byte[] buf, int offset, int len) throws GeneralSecurityException
      {
        if (md == null)
          {
            baos.write (buf, offset, len);
          }
        else
          {
            md.update (buf, offset, len);
          }
        return this;
      }


    byte[] digest () throws GeneralSecurityException
      {
        return md == null ? baos.toByteArray () : md.digest ();
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
