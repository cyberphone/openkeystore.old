package org.webpki.asn1;

import java.io.IOException;

public class ASN1BMPString extends ASN1String
  {
    ASN1BMPString(String value)
      {
        super(BMPSTRING, value);
      }

    ASN1BMPString(DerDecoder decoder) throws IOException
      {
        super(decoder);
      }
    
    void toString(StringBuffer s, String prefix)
      {
        s.append (getByteNumber ()).append(prefix).append("BMPString    ").append(value());
      }
  }
