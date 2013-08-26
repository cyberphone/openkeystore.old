/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
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
package org.webpki.json.test;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.webpki.crypto.KeyAlgorithms;

import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONEnvelopedSignatureDecoder;
import org.webpki.json.JSONEnvelopedSignatureEncoder;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONReaderHelper;
import org.webpki.json.JSONWriter;
import org.webpki.json.test.Keys.Reader;
import org.webpki.json.test.Keys.Writer;

/**
 * Testing public keys
 */
public class Test
  {
    static final String KEYS="Keys";
    static final String VERSION = "http://keys/test";
    
    private static final String BOOL_TRUE = "boolTrue";
    private static final String BOOL_FALSE = "boolFalse";
    private static final String BOOL_UNKNOWM = "boolUnknown";

    private static final String STRING = "string";
    private static final String STRING_VALUE = "Hi!";
    private static final String STRING_UNKNOWM = "nostring";

    static JSONDecoderCache cache = new JSONDecoderCache ();
    
    public static class Reader extends JSONDecoder
      {
        void test (boolean ok) throws IOException
          {
            if (!ok) throw new IOException ("Bad");
          }

        @Override
        protected void unmarshallJSONData (JSONReaderHelper rd) throws IOException
          {
            test (rd.getBoolean (BOOL_TRUE));
            test (!rd.getBoolean (BOOL_FALSE));
            test (!rd.getBooleanConditional (BOOL_UNKNOWM));
            test (!rd.getBooleanConditional (BOOL_UNKNOWM));
            test (rd.getString (STRING).equals (STRING_VALUE));
            test (rd.getStringConditional (STRING_UNKNOWM) == null);
          }
  
        @Override
        protected String getVersion ()
          {
             return VERSION;
          }
  
        @Override
        protected String getRootProperty ()
          {
            return KEYS;
          }
      }

    static class Writer extends JSONEncoder
      {
        @Override
        protected byte[] getJSONData () throws IOException
          {
            JSONWriter wr = new JSONWriter (KEYS, VERSION);
            wr.setBoolean (BOOL_TRUE, true);
            wr.setBoolean (BOOL_FALSE, false);
            wr.setString (STRING, STRING_VALUE);
            return wr.serializeJSONStructure ();
          }
      }

    public static void main (String[] argc)
      {
        byte[] data = null;
        try
          {
            cache.addToCache (Reader.class);
            data = new Writer ().getJSONData ();
            Reader reader = (Reader) cache.parse (data);
          }
        catch (Exception e)
          {
            try
              {
                System.out.println (new String (data, "UTF-8"));
              }
            catch (UnsupportedEncodingException e1)
              {
                // TODO Auto-generated catch block
                e1.printStackTrace();
              }
            e.printStackTrace ();
          }
      }
  }
