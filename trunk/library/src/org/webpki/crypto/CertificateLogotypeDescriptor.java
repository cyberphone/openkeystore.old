package org.webpki.crypto;

import java.io.IOException;

import org.webpki.util.URLDereferencer;
import org.webpki.util.ArrayUtil;


public class CertificateLogotypeDescriptor
  {
    private String uri;

    private String mime_type;

    private String algorithm_oid;

    private byte[] sha1_data;


    public String getURI ()
      {
        return uri;
      }


    public String getMimeType ()
      {
        return mime_type;
      }


    public String getAlgorithmOID ()
      {
        return algorithm_oid;
      }


    public byte[] getSHA1Data ()
      {
        return sha1_data;
      }


    public boolean isSupported ()
      {
        return (mime_type.equals ("image/gif") || mime_type.equals ("image/jpeg")) &&
                HashAlgorithms.SHA1.getOID ().equals (algorithm_oid);
      }


    public int hashCode ()
      {
        return mime_type.hashCode () ^ algorithm_oid.hashCode () ^ uri.hashCode ();
      }


    public CertificateLogotype getLogotype () throws IOException
      {
        if (isSupported ())
          {
            URLDereferencer dref = new URLDereferencer (uri);
            if (dref.getMimeType ().equals (mime_type))
              {
                if (ArrayUtil.compare (HashAlgorithms.SHA1.digest (dref.getData ()), sha1_data))
                  {
                    return new CertificateLogotype (dref.getData (), mime_type);
                  }
              }
          }
        throw new IOException ("Unsupported or incorrect logotype format");
      }

    public boolean equals (Object o)
      {
        return o instanceof CertificateLogotypeDescriptor &&
               mime_type.equals (((CertificateLogotypeDescriptor)o).mime_type) &&
               algorithm_oid.equals (((CertificateLogotypeDescriptor)o).algorithm_oid) &&
               uri.equals (((CertificateLogotypeDescriptor)o).uri);
      }


    public CertificateLogotypeDescriptor (String uri, String mime_type, String algorithm_oid, byte[] sha1_data)
      {
        this.uri = uri;
        this.mime_type = mime_type;
        this.algorithm_oid = algorithm_oid;
        this.sha1_data = sha1_data;
      }

  }
