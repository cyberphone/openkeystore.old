package org.webpki.asn1;

import java.io.IOException;

public class ASN1IA5String extends ASN1String
  {
    public ASN1IA5String(String value)
      {
        super(IA5STRING, value);
      }

    ASN1IA5String(DerDecoder decoder) throws IOException
      {
        super(decoder);
      }
    
    void toString(StringBuffer s, String prefix)
      {
        s.append (getByteNumber ()).append(prefix).append("IA5String '").append(value()).append('\'');
      }
  }
