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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import java.security.spec.ECGenParameterSpec;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyAlgorithms;

import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONAsymKeyVerifier;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONSignatureDecoder;

/**
 * Demo code for JDOC
 */
public class DemoCode
  {
    static
      {
        Sign.installOptionalBCProvider ();
      }

    public void signAndVerifyJCS (final PublicKey public_key, final PrivateKey private_key) throws IOException
      {
        // Create an empty JSON document
        JSONObjectWriter ow = new JSONObjectWriter ();

        // Fill it with some data
        ow.setString ("MyProperty", "Some data");
        
        // Sign document
        ow.setSignature (new JSONAsymKeySigner (new AsymKeySignerInterface ()
          {
            @Override
            public byte[] signData (byte[] data, AsymSignatureAlgorithms algorithm) throws IOException
              {
                try
                  {
                    Signature signature = Signature.getInstance (algorithm.getJCEName ()) ;
                    signature.initSign (private_key);
                    signature.update (data);
                    return signature.sign ();
                  }
                catch (Exception e)
                  {
                    throw new IOException (e);
                  }
              }
   
            @Override
            public PublicKey getPublicKey () throws IOException
              {
                 return public_key;
              }
          }));
        
        // Serialize document
        byte[] json = ow.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT);

        // Print document on the console
        System.out.println ("Signed doc:\n" + new String (json, "UTF-8"));
        
        // Parse document
        JSONObjectReader or = JSONParser.parse (json);
        
        // Get and verify signature
        JSONSignatureDecoder json_signature = or.getSignature ();
        json_signature.verify (new JSONAsymKeyVerifier (public_key));
        
        // Get document payload
        System.out.println ("Returned data: " + or.getString ("MyProperty"));
      }

    public static void main (String[] argc)
      {
        try
          {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance ("EC");
            kpg.initialize (new ECGenParameterSpec (KeyAlgorithms.NIST_P_256.getJCEName ()), new SecureRandom ());
            KeyPair key_pair = kpg.generateKeyPair ();
            new DemoCode ().signAndVerifyJCS (key_pair.getPublic (), key_pair.getPrivate ());
          }
        catch (Exception e)
          {
            e.printStackTrace();
          }
      }
  }
