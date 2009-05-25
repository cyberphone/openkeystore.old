package org.webpki.util;

import java.io.IOException;


public interface MimeTypedObject
  {

    public byte[] getData () throws IOException;

    public String getMimeType () throws IOException;

  }
