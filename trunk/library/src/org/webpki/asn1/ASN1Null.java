package org.webpki.asn1;

import java.io.IOException;

public final class ASN1Null extends Simple
  {
    public ASN1Null()
      {
        super(NULL, true);
      }
    
    ASN1Null(DerDecoder decoder) throws IOException
      {
        super(decoder);
        // Null has no content.
      }
    
    public void encode(Encoder encoder) throws IOException
      {
        // Null has no content. It shall be primitive.
        encodeHeader(encoder, 0, true);
      }
    
    public boolean deepCompare(BaseASN1Object o)
      {
        return sameType(o);
      }

    public Object objValue()
      {
        return null;
      }

    public boolean diff(BaseASN1Object o, StringBuffer s, String prefix)
      {
        if(!sameType(o))
          {
            s.append(prefix).append("<-------").append("    ");
            toString(s, prefix);
            s.append('\n');
            s.append(prefix).append("------->").append("    ");
            o.toString(s, prefix);
            s.append('\n');
            return true;
          }

        return false;
      }
    
    void toString(StringBuffer s, String prefix)
      {
        s.append (getByteNumber ()).append(prefix).append("NULL");
      }
  }
