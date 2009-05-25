package org.webpki.asn1;

import java.io.IOException;
import java.util.Vector;

/**
 * This needs to be checked.
 */
public final class CompositeContextSpecific extends Composite
  {
    public CompositeContextSpecific(int tagNumber, Vector<BaseASN1Object> components)
      {
        super(CONTEXT, tagNumber, components);
      }
    
    public CompositeContextSpecific(int tagNumber, BaseASN1Object[] components)
      {
        super(CONTEXT, tagNumber, components);
      }
    
    public CompositeContextSpecific(int tagNumber, BaseASN1Object value)
      {
        super(CONTEXT, tagNumber);
        components.addElement(value);
      }
    
    CompositeContextSpecific(DerDecoder decoder) throws IOException
      {
        super(decoder);

        if(!isContext())
          {
            throw new IOException("Internal error: Wrong tag class");
          }
        
        if(components == null || components.size() == 0)
          {
            throw new IOException("Empty CONTEXT_SPECIFIC.");
          }
      }

    public boolean sameType(BaseASN1Object o)
      {
        return o.getClass().equals(CompositeContextSpecific.class) &&
               o.tagNumber == tagNumber;
      }
    
    /**
     * DIRTY fix to be used ONLY when verifying authenticated attributes of PKCS#7/CMS messages.
     */
    public void writeOriginalBlobAs(int tagNumber, java.security.Signature signature)
    throws java.security.GeneralSecurityException, IOException
      {
        if(tagNumber > 30)
          {
            throw new IOException("tagNumber > 30 not supported");
          }

        signature.update((byte)(UNIVERSAL | DerDecoder.CONSTRUCTED | tagNumber));
        signature.update(blob, blobOffset+1, encodedLength-1);
      }
    
    public boolean deepCompare(BaseASN1Object o)
      {
        if(!sameType(o) || 
           o.tagNumber != tagNumber || o.tagEncoding != tagEncoding)
          {
            return false;
          }
        CompositeContextSpecific cs = (CompositeContextSpecific)o;
        return ASN1Util.deepCompare(cs.components, components);
      }
    
    void toString(StringBuffer s, String prefix)
      {
        s.append (getByteNumber ()).append(prefix).append("[").append(tagNumber).append("]");
        compositeString (s, prefix);
      }
  }
