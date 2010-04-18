package org.webpki.keygen2;

import java.io.IOException;

public enum APIDescriptors
  {
    SET_CERTIFICATE_PATH  ("setCerttificatePath"),
    SET_SYMMETRIC_KEY     ("setSymmetricKey"),
    CLOSE_SESSION         ("closeProvisioningSession"),
    ADD_EXTENSION         ("addExtension");

    private byte[] binary;       // As expressed in MACs

    private APIDescriptors (String string)
      {
        try
          {
            binary = string.getBytes ("UTF-8");
          }
        catch (IOException e)
          {
            binary = null;
          }
      }
    
    public byte[] getBinary ()
      {
        return binary;
      }

  }
