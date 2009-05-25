package org.webpki.asn1;

import java.io.IOException;

public class ASN1NumericString extends ASN1String
  {
    ASN1NumericString(DerDecoder decoder) throws IOException
      {
        super(decoder);
      }
    
    void toString(StringBuffer s, String prefix)
      {
        s.append (getByteNumber ()).append(prefix).append(value()).append("    [NumericString]");
      }
  }
