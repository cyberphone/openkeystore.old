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

import java.util.Vector;

import org.webpki.crypto.KeyAlgorithms;

import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.json.JSONSignatureEncoder;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONReaderHelper;
import org.webpki.json.JSONObjectWriter;

/**
 * Testing public keys
 */
public class Keys
  {
    static final String CONTEXT = "http://keys/test";
    static final int ROUNDS = 1000;
    static JSONDecoderCache cache = new JSONDecoderCache ();
    static KeyAlgorithms[] ec_curves;
    static int ec_index;
    
    public static class Reader extends JSONDecoder
      {
        PublicKey public_key;

        PublicKey getPublicKey () throws IOException
          {
            return public_key;
          }

        @Override
        protected void unmarshallJSONData (JSONReaderHelper rd) throws IOException
          {
            public_key = JSONSignatureDecoder.readPublicKey (rd);
          }
  
        @Override
        protected String getContext ()
          {
             return CONTEXT;
          }
      }

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
            JSONSignatureEncoder.writePublicKey (wr, public_key);
          }

        @Override
        protected String getContext ()
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
        if (!reader.getPublicKey ().equals (public_key))
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
            Vector<KeyAlgorithms> ecs = new Vector<KeyAlgorithms> ();
            for (KeyAlgorithms ka : KeyAlgorithms.values ())
              {
                if (ka.isECKey ())
                  {
                    ecs.add (ka);
                  }
              }
            ec_curves = ecs.toArray (new KeyAlgorithms[0]);
            Sign.installOptionalBCProvider ();
            cache.addToCache (Reader.class);
            for (int i = 0; i < ROUNDS; i++)
              {
                Run (true, new Boolean (argc[0]));
                Run (false, new Boolean (argc[0]));
              }
          }
        catch (Exception e)
          {
            e.printStackTrace ();
          }
        return;
      }
  }
