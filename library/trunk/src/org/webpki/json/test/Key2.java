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

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import org.webpki.crypto.KeyAlgorithms;

import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

/**
 * Testing public keys
 */
public class Key2
  {
    static final String CONTEXT = "http://keys/test";
    static final int ROUNDS = 1000;
    static JSONDecoderCache cache = new JSONDecoderCache ();
    static KeyAlgorithms[] ec_curves;
    static int ec_index;
    
    @SuppressWarnings("serial")
    public static class Reader extends JSONDecoder
      {
        PublicKey public_key;

        PublicKey getPublicKey () throws IOException
          {
            return public_key;
          }

        @Override
        protected void unmarshallJSONData (JSONObjectReader rd) throws IOException
          {
            public_key = rd.getPublicKey ();
          }
  
        @Override
        public String getContext ()
          {
             return CONTEXT;
          }
      }

    @SuppressWarnings("serial")
    static class Writer extends JSONEncoder
      {
        PublicKey public_key;
        
        Writer (PublicKey public_key)
          {
            this.public_key = public_key;
          }

        @Override
        protected void writeJSONData (JSONObjectWriter wr) throws IOException
          {
            wr.setPublicKey (public_key);
          }

        @Override
        public String getContext ()
          {
            return CONTEXT;
          }
      }

    static void show ()
      {
        System.out.println ("logging-flag\n");
        System.exit (0);
      }

    static void Run (boolean rsa, boolean list) throws GeneralSecurityException, IOException
      {
        AlgorithmParameterSpec alg_par_spec = rsa ?
            new RSAKeyGenParameterSpec (2048, RSAKeyGenParameterSpec.F4)
                                                  :
            new ECGenParameterSpec (ec_curves[ec_index++ % ec_curves.length].getJCEName ());
        KeyPairGenerator kpg = KeyPairGenerator.getInstance (rsa ? "RSA" : "EC");
        kpg.initialize (alg_par_spec, new SecureRandom ());
        KeyPair key_pair = kpg.generateKeyPair ();
        PublicKey public_key = key_pair.getPublic ();
        byte[] data = new Writer (public_key).serializeJSONDocument (JSONOutputFormats.PRETTY_PRINT);
        Reader reader = (Reader) cache.parse (data);
        if (!ArrayUtil.compare (reader.getPublicKey ().getEncoded (),public_key.getEncoded ()))
          {
            throw new IOException ("Unmatching keys:" + public_key.toString ());
          }
        if (list)
          {
            System.out.println (new String (data, "UTF-8"));
          }
      }

    public static void main (String[] argc)
      {
        if (argc.length != 1)
          {
            show ();
          }
        try
          {
            Sign.installOptionalBCProvider ();
            for (KeyAlgorithms ka : KeyAlgorithms.values ())
              {
                if (ka.isECKey ())
                  {
                    AlgorithmParameterSpec alg_par_spec = new ECGenParameterSpec (ka.getJCEName ());
                    KeyPairGenerator kpg = KeyPairGenerator.getInstance ("EC");
                    kpg.initialize (alg_par_spec, new SecureRandom ());
                    KeyPair key_pair = kpg.generateKeyPair ();
                    byte[] public_key = key_pair.getPublic ().getEncoded ();
                    int i = -1;
                    System.out.print (ka.getURI () + "\nnew byte[]\n{");
                    for (byte b : public_key)
                      {
                        if (++i != 0)
                          {
                            System.out.print (",");
                            if (i % 8 == 0 && i != public_key.length)
                              {
                                System.out.println ();
                              }
                            System.out.print (" ");
                          }
                        System.out.print ("(byte)0x" + DebugFormatter.getHexString (new byte[]{b}));
                      }
                    System.out.println ("}\n");
                  }
              }
          }
        catch (Exception e)
          {
            e.printStackTrace ();
          }
        return;
      }
  }
