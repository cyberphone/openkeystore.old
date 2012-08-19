/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
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
package org.webpki.keygen2;

import static org.webpki.keygen2.KeyGen2Constants.*;

import java.io.IOException;
import java.io.Serializable;

import java.security.spec.RSAKeyGenParameterSpec;

import org.webpki.crypto.ECDomains;

import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.DOMWriterHelper;

public abstract class KeySpecifier implements Serializable
  {
    private static final long serialVersionUID = 1L;

    public abstract byte[] getSKSValue () throws IOException;
    
    abstract void writeKeySpecifier (DOMWriterHelper wr) throws IOException;
    
    byte[] short2bytes (int s)
      {
        return new byte[]{(byte)(s >>> 8), (byte)s};
      }


    public static class RSA extends KeySpecifier implements Serializable
      {
        private static final long serialVersionUID = 1L;

        int key_size;
    
        int fixed_exponent = RSAKeyGenParameterSpec.F4.intValue ();
        
        boolean output_exponent;
    
        public RSA (int key_size)
          {
            this.key_size = key_size;
          }

        public RSA (int key_size, int fixed_exponent)
          {
            output_exponent = true;
            this.key_size = key_size;
            this.fixed_exponent = fixed_exponent;
          }
    
    
        public int getKeySize ()
          {
            return key_size;
          }
    
    
        public int getFixedExponent ()
          {
            return fixed_exponent;
          }


        @Override
        void writeKeySpecifier (DOMWriterHelper wr) throws IOException
          {
            wr.addChildElement (RSA_ELEM);
            wr.setIntAttribute (KEY_SIZE_ATTR, key_size);
            if (output_exponent)
              {
                wr.setIntAttribute (EXPONENT_ATTR, fixed_exponent);
              }
            wr.getParent ();
          }


        @Override
        public byte[] getSKSValue () throws IOException
          {
            return ArrayUtil.add (ArrayUtil.add (new byte[]{SecureKeyStore.KEY_ALGORITHM_TYPE_RSA}, short2bytes (key_size)),
                                                 ArrayUtil.add (short2bytes (fixed_exponent >>> 16), short2bytes (fixed_exponent)));
          }
      }


    public static class EC extends KeySpecifier implements Serializable
      {
        private static final long serialVersionUID = 1L;

        ECDomains named_curve;
    
        public EC (ECDomains named_curve)
          {
            this.named_curve = named_curve;
          }
    
    
        public ECDomains getNamedCurve ()
          {
            return named_curve;
          }


        @Override
        void writeKeySpecifier (DOMWriterHelper wr) throws IOException
          {
            wr.addChildElement (EC_ELEM);
            wr.setStringAttribute (NAMED_CURVE_ATTR, named_curve.getURI ());
            wr.getParent ();
          }      
        

        @Override
        public byte[] getSKSValue () throws IOException
          {
            return ArrayUtil.add (new byte[]{SecureKeyStore.KEY_ALGORITHM_TYPE_NAMED_EC}, named_curve.getURI ().getBytes ("UTF-8"));
          }
      }
  }

