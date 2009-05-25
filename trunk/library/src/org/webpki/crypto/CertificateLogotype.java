package org.webpki.crypto;

import org.webpki.util.MimeTypedObject;


public class CertificateLogotype implements MimeTypedObject
  {
    private byte[] data;

    private String mime_type;


    public String getMimeType ()
      {
        return mime_type;
      }


    public byte[] getData ()
      {
        return data;
      }


    public CertificateLogotype (byte[] data, String mime_type)
      {
        this.data = data;
        this.mime_type = mime_type;
      }

  }
