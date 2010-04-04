package org.webpki.crypto;

import java.io.IOException;

import java.security.GeneralSecurityException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;


public enum MacAlgorithms
  {
    HMAC_MD5    ("http://www.w3.org/2001/04/xmldsig-more#hmac-md5",    "HmacMD5"),
    HMAC_SHA1   ("http://www.w3.org/2000/09/xmldsig#hmac-sha1",        "HmacSHA1"),
    HMAC_SHA256 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "HmacSHA256"),
    HMAC_SHA384 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", "HmacSHA384"),
    HMAC_SHA512 ("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", "HmacSHA512");

    private final String uri;       // As expressed in XML messages
    private final String jcename;   // As expressed for JCE

    private MacAlgorithms (String uri, String jcename)
      {
        this.uri = uri;
        this.jcename = jcename;
      }


    public String getURI ()
      {
        return uri;
      }


    public String getJCEName ()
      {
        return jcename;
      }

    
    public byte[] digest (byte[] key, byte[] data) throws IOException
      {
        try
          {
            Mac mac = Mac.getInstance (getJCEName ());
            mac.init (new SecretKeySpec (key, "RAW"));  // Note: any length is OK in HMAC
            return mac.doFinal (data);
          }
        catch (GeneralSecurityException gse)
          {
            IOException iox = new IOException ();
            iox.initCause (gse.getCause ());
            throw iox;
          }
      }


    public static boolean testAlgorithmURI (String uri)
      {
        for (MacAlgorithms alg : MacAlgorithms.values ())
          {
            if (uri.equals (alg.uri))
              {
                return true;
              }
          }
        return false;
      }


    public static MacAlgorithms getAlgorithmFromURI (String uri) throws IOException
      {
        for (MacAlgorithms alg : values ())
          {
            if (uri.equals (alg.uri))
              {
                return alg;
              }
          }
        throw new IOException ("Unknown algorithm: " + uri);
      }

  }
