package org.webpki.util;

import java.io.IOException;
import java.io.Serializable;

import org.webpki.net.HttpsWrapper;


public class URLDereferencer implements MimeTypedObject, Serializable
  {
    private static final long serialVersionUID = 1L;

    private byte[] data;

    private String ct;


    public URLDereferencer (String url) throws IOException
      {
        HttpsWrapper wrap = new HttpsWrapper ();
        wrap.setRequireSuccess (true);
        wrap.makeGetRequest (url);
        ct = wrap.getContentType ();
        if (ct == null)
          {
            throw new IOException ("MIME type missing for url: " + url);
          }
        data = wrap.getData ();
      }


    public byte[] getData () throws IOException
      {
        return data;
      }


    public String getMimeType () throws IOException
      {
        return ct;
      }

  }
