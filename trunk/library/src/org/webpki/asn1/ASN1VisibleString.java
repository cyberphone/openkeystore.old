package org.webpki.asn1;

import java.io.IOException;

public class ASN1VisibleString extends ASN1String
  {
    ASN1VisibleString(String value)
      {
        super(VISIBLESTRING, value);
      }

    ASN1VisibleString(DerDecoder decoder) throws IOException
      {
        super(decoder);
      }
    
    void toString(StringBuffer s, String prefix)
      {
        s.append (getByteNumber ()).append(prefix).append("VisibleString '").append(value()).append ('\'');
      }
  }
