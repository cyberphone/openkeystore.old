package org.webpki.asn1;

import java.io.IOException;
import java.util.*;
import org.webpki.util.ArrayUtil;

public final class ASN1OctetString extends Binary
  {
    public ASN1OctetString(byte[] value)
      {
        super(OCTETSTRING, true, value);
      }
    
    ASN1OctetString(DerDecoder decoder) throws IOException
      {
        super(decoder);
        if(isPrimitive())
          {
            value = decoder.content();
          }
        else
          {
            Vector<BaseASN1Object> v = readComponents(decoder);
        
            ASN1OctetString os;

            int length = 0;
            
            for(int i = 0; i < v.size(); i++)
              {
                length += ((ASN1OctetString)v.elementAt(i)).value.length;
              }
            
            value = new byte[length];
            
            int offset = 0;
            
            for(int i = 0; i < v.size(); i++)
              {
                os = (ASN1OctetString)v.elementAt(i);
                System.arraycopy(os.value, 0, value, offset, os.value.length);
                offset += os.value.length;
              }
          }
      }
    
    public void encode(Encoder encoder) throws IOException
      {
        encode(encoder, value);
      }
    
    public boolean deepCompare(BaseASN1Object o)
      {
        return sameType(o) && 
               ArrayUtil.compare(((ASN1OctetString)o).value, value);
      }

    public String stringValue()
      {
        return new String(value);
      }
    
    void toString(StringBuffer s, String prefix)
      {
        s.append (getByteNumber ()).append(prefix).append("OCTET STRING, ");
        extractableStringData (s, prefix);
      }
  }
