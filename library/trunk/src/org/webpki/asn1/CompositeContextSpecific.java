/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
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
        
        if(components == null)
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
