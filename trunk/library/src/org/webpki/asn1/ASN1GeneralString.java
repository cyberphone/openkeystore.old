package org.webpki.asn1;

import java.io.IOException;

public class ASN1GeneralString extends ASN1String
  {
    ASN1GeneralString(String value)
      {
        super(GENERALSTRING, value);
      }

    ASN1GeneralString(DerDecoder decoder) throws IOException
      {
        super(decoder);
      }
    
    void toString(StringBuffer s, String prefix)
      {
        s.append (getByteNumber ()).append(prefix).append("GeneralString ").append(value());
      }
  }
