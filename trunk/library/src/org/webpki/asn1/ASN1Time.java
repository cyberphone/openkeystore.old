package org.webpki.asn1;

import java.io.IOException;
import java.util.*;

public abstract class ASN1Time extends Simple
  {
    Date value;
    
    ASN1Time(DerDecoder decoder) throws IOException
      {
        super(decoder);
      }
    
    ASN1Time(int tagNumber, Date value)
      {
        super(tagNumber, false);
        this.value = value;
      }
    
    public Date value()
      {
        return value;
      }
    
    public Object objValue()
      {
        return value();
      }
    
    abstract String encodedForm();
    
    public void encode(Encoder encoder) throws IOException
      {
        String encodedForm = encodedForm();
        encodeHeader(encoder, encodedForm.length(), true);
        encoder.write(encodedForm.getBytes());
      }
  }
