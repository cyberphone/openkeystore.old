/*
 *  Copyright 2006-2015 WebPKI.org (http://webpki.org).
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
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.SignatureWrapper;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.json.JSONAlgorithmPreferences;
import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONObjectWriter;

import org.webpki.util.ArrayUtil;

/**
 * JCS sample signature test generator
 */
public class JCSSample
  {
    static class AsymSigner implements AsymKeySignerInterface
      {
        PrivateKey priv_key;
        PublicKey pub_key;
  
        AsymSigner (PrivateKey priv_key, PublicKey pub_key)
          {
            this.priv_key = priv_key;
            this.pub_key = pub_key;
          }
  
        public byte[] signData (byte[] data, AsymSignatureAlgorithms sign_alg) throws IOException
          {
            try
              {
                return new SignatureWrapper (sign_alg, priv_key)
                    .update (data)
                    .sign ();
              }
            catch (GeneralSecurityException e)
              {
                throw new IOException (e);
              }
          }
  
        public PublicKey getPublicKey () throws IOException
          {
            return pub_key;
          }
      }

    static void createAsymmetricKeySignature (JSONObjectWriter wr, String file_name, JSONAlgorithmPreferences jose_alg_pref) throws IOException
      {
        try
          {
            KeyStore ks = DemoKeyStore.getECDSAStore ();
            PrivateKey private_key = (PrivateKey)ks.getKey ("mykey", DemoKeyStore.getSignerPassword ().toCharArray ());
            PublicKey public_key = ks.getCertificate ("mykey").getPublicKey ();
            JSONAsymKeySigner signer = new JSONAsymKeySigner (new AsymSigner (private_key, public_key)).setAlgorithmPreferences (jose_alg_pref);
            wr.setSignature (signer);
            ArrayUtil.writeFile (file_name, signer.getNormalizedData ());
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }
    
    public static void main (final String[] argc)
      {
        try
          {
            if (argc.length != 2)
              {
                throw new IOException ("Normlized-data-file-output jose-flag");
              }
            CustomCryptoProvider.conditionalLoad (true);
            String unormalized_json = 
              "{\n" +
              "  \"now\": \"2015-01-12T09:22:36Z\",\n" +
              "  \"escapeMe\": \"\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\\"\\/\",\n" +
              "  \"numbers\": [1e0, 4.50, 6]\n" +
              "}";
            JSONObjectReader or = JSONParser.parse (unormalized_json);
            JSONObjectWriter wr = new JSONObjectWriter (or);
            createAsymmetricKeySignature (wr,
                                          argc[0], 
                                          Boolean.valueOf (argc[1]) ?
                        JSONAlgorithmPreferences.JOSE_ACCEPT_PREFER : JSONAlgorithmPreferences.SKS);
            String res = new String (wr.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT), "UTF-8");
            res = unormalized_json.substring (0, unormalized_json.indexOf (']')) + res.substring (res.indexOf (']'));
            System.out.println (res);
          }
        catch (Exception e)
          {
            e.printStackTrace ();
          }
      }
  }
