package org.webpki.asn1;

import java.io.IOException;

public class ASN1GraphicString extends ASN1String
  {
    ASN1GraphicString(String value)
      {
        super(GRAPHICSTRING, value);
      }

    ASN1GraphicString(DerDecoder decoder) throws IOException
      {
        super(decoder);
      }
    
    void toString(StringBuffer s, String prefix)
      {
        s.append (getByteNumber ()).append(prefix).append("GraphicString ").append(value());
      }
  }
