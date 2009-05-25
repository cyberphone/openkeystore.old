package org.webpki.crypto;

import java.io.IOException;

public enum KeyUsageBits
  {
           digitalSignature,
           nonRepudiation,
           keyEncipherment,
           dataEncipherment,
           keyAgreement,
           keyCertSign,
           cRLSign,
           encipherOnly,
           decipherOnly;


    public static KeyUsageBits getKeyUsageBit (String arg) throws IOException
      {
        for (KeyUsageBits kubit : values ())
          {
            if (kubit.toString ().equalsIgnoreCase (arg))
              {
                return kubit;
              }
          }
        throw new IOException ("Bad KeyUsage bit: " + arg);
      }

  }
