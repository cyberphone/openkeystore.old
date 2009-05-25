package org.webpki.asn1;

import java.io.IOException;
import java.util.*;

public final class ASN1Set extends Composite
  {
    public ASN1Set(BaseASN1Object[] components)
      {
        super(SET, components);
      }
    
    public ASN1Set(Vector<BaseASN1Object> components)
      {
        super(SET, components);
      }
    
    public ASN1Set(BaseASN1Object component)
      {
        super(SET);
        this.components.addElement(component);
      }
    
    ASN1Set(DerDecoder decoder) throws IOException
      {
        super(decoder);
      }

    void toString(StringBuffer s, String prefix)
      {
        s.append (getByteNumber ()).append(prefix).append("SET");
        compositeString (s, prefix);
      }
  }
