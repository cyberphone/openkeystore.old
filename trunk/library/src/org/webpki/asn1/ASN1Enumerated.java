package org.webpki.asn1;

import java.io.IOException;
import java.math.*;

public final class ASN1Enumerated extends Simple
  {
    BigInteger value;
    
    public ASN1Enumerated(BigInteger value)
      {
        super(ENUMERATED, true);
        this.value = value;
      }
    
    public ASN1Enumerated(String value)
      {
        this(new BigInteger(value));
      }
    
    public ASN1Enumerated(long value)
      {
        this(Long.toString(value));
      }
    
    ASN1Enumerated(DerDecoder decoder) throws IOException
      {
        super(decoder, true);
        value = new BigInteger(decoder.content());
      }
    
    public void encode(Encoder encoder) throws IOException
      {
        byte[] content = value.toByteArray();
        encodeHeader(encoder, content.length, true);
        encoder.write(content);
      }
    
    public boolean deepCompare(BaseASN1Object o)
      {
        return sameType(o) && ((ASN1Enumerated)o).value.equals(value);
      }

    public Object objValue()
      {
        return value();
      }
    
    public BigInteger value()
      {
        return value;
      }
    
    public int intValue()
      {
        return value.intValue();
      }
    
    void toString(StringBuffer s, String prefix)
      {
        s.append (getByteNumber ()).append(prefix).append("ENUMERATED ").append(value);
      }
  }
