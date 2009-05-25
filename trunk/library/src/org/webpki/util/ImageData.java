package org.webpki.util;

import java.io.IOException;
import java.io.Serializable;


public class ImageData implements MimeTypedObject, Serializable
  {
    private static final long serialVersionUID = 1L;

    @SuppressWarnings("unused")
    private ImageData () {}

    byte[] data;

    String mime_type;


    public ImageData (byte[] data, String mime_type)
      {
        this.data = data;
        this.mime_type = mime_type;
      }

    public byte[] getData () throws IOException
      {
        return data;
      }


    public String getMimeType () throws IOException
      {
        return mime_type;
      }
  }
