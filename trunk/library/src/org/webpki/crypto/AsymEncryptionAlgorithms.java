package org.webpki.crypto;

import java.io.IOException;


public enum AsymEncryptionAlgorithms implements EncryptionAlgorithms
  {
    RSA_PKCS_1  ("1.2.840.113549.1.1.1",  "http://www.w3.org/2001/04/xmlenc#rsa-1_5",  "RSA/ECB/PKCS1Padding"),
    RSA_RAW     (null,                    "internal:RSA/ECB/NoPadding",                "RSA/ECB/NoPadding");

    private final String         oid;             // As expressed in OIDs
    private final String         uri;             // As expressed in XML
    private final String         jcename;         // As expressed for JCE

    private AsymEncryptionAlgorithms (String oid, String uri, String jcename)
      {
        this.oid = oid;
        this.uri = uri;
        this.jcename = jcename;
      }


    public String getOID ()
      {
        return oid;
      }


    public String getJCEName ()
      {
        return jcename;
      }


    public String getURI ()
      {
        return uri;
      }


    public static AsymEncryptionAlgorithms getAlgorithmFromOID (String oid) throws IOException
      {
        for (AsymEncryptionAlgorithms alg : values ())
          {
            if (oid.equals (alg.oid))
              {
                return alg;
              }
          }
        throw new IOException ("Unknown algorithm: " + oid);
      }


    public static AsymEncryptionAlgorithms getAlgorithmFromURI (String uri) throws IOException
      {
        for (AsymEncryptionAlgorithms alg : values ())
          {
            if (uri.equals (alg.uri))
              {
                return alg;
              }
          }
        throw new IOException ("Unknown algorithm: " + uri);
      }
  }
