package org.webpki.asn1;

import java.io.IOException;

public class ASN1T61String extends ASN1String
  {
    ASN1T61String(String value)
      {
        super(T61STRING, value);
      }

    ASN1T61String(DerDecoder decoder) throws IOException
      {
        super(decoder);
      }
    
    void toString(StringBuffer s, String prefix)
      {
        s.append (getByteNumber ()).append(prefix).append("T61String '").append(value()).append ('\'');
      }
  }
