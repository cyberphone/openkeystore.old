package org.webpki.asn1;

import java.io.IOException;

public final class ASN1Boolean extends Simple
  {
    boolean value;
    
    public ASN1Boolean(boolean value)
      {
        super(BOOLEAN, true);
        this.value = value;
      }
    
    ASN1Boolean(DerDecoder decoder) throws IOException
      {
        // Boolean encoding shall be primitive
        super(decoder, true);

        if(decoder.length != 1)
          {
            throw new IOException("Boolean value must have length 1.");
          }
        value = decoder.content()[0] != 0;
      }
    
    public void encode(Encoder encoder) throws IOException
      {
        encode(encoder, value ? Encoder.TRUE : Encoder.FALSE);
      }
    
    public boolean deepCompare(BaseASN1Object o)
      {
        return sameType(o) && ((ASN1Boolean)o).value == value;
      }
    
    public boolean value()
      {
        return value;
      }
    
    public Object objValue()
      {
        return new Boolean(value);
      }
    
    void toString(StringBuffer s, String prefix)
      {
        s.append (getByteNumber ()).append(prefix).append("BOOLEAN ").append(value);
      }
  }
