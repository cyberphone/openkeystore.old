package org.webpki.asn1;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

public class ASN1UTF8String extends ASN1String
  {
    public ASN1UTF8String(String value)// throws UnsupportedEncodingException
      {
        super(UTF8STRING, getBytesUTF8(value));
      }

    ASN1UTF8String(DerDecoder decoder) throws IOException
      {
        super(decoder);
      }
    
    void toString(StringBuffer s, String prefix)
      {
        s.append (getByteNumber ()).append(prefix).append("UTF8String '").append(value()).append('\'');
      }
    
    private static byte[] getBytesUTF8(String value)
      {
        try
          {
            return value.getBytes("UTF-8");
          }
        catch(UnsupportedEncodingException uee)
          {
            throw new RuntimeException("UTF-8 not supported!");
          }
      
      }
    
    public String value()
      {
        try
          {
            return new String(value, "UTF-8");
          }
        catch(UnsupportedEncodingException uee)
          {
            throw new RuntimeException("UTF-8 not supported!");
          }
      }
  }
