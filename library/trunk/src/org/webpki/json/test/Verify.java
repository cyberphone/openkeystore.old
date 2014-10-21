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
package org.webpki.json.test;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PublicKey;

import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.KeyStoreVerifier;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CustomCryptoProvider;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONAsymKeyVerifier;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONSymKeyVerifier;
import org.webpki.json.JSONTypes;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONX509Verifier;

import org.webpki.util.ArrayUtil;

/**
 * Simple signature verify program
 */
public class Verify
  {
    static
      {
        CustomCryptoProvider.conditionalLoad (true);
      }

    static int count;

    void recurseObject (JSONObjectReader rd) throws IOException
      {
        for (String property : rd.getProperties ())
          {
            switch (rd.getPropertyType (property))
              {
                case OBJECT:
                  if (property.equals (JSONSignatureDecoder.SIGNATURE_JSON))
                    {
                      JSONSignatureDecoder signature = rd.getSignature ();
                      switch (signature.getSignatureType ())
                        {
                          case ASYMMETRIC_KEY:
                            try
                              {
                                KeyStore ks = ((AsymSignatureAlgorithms)signature.getSignatureAlgorithm ()).isRSA () ? 
                                    DemoKeyStore.getMybankDotComKeyStore () : DemoKeyStore.getECDSAStore ();
                                PublicKey public_key = ks.getCertificate ("mykey").getPublicKey ();
                                signature.verify (new JSONAsymKeyVerifier (public_key));
                                debugOutput ("Asymmetric key signature validated for: " + public_key.toString ());
                              }
                            catch (GeneralSecurityException e)
                              {
                                throw new IOException (e);
                              }
                            break;
  
                          case SYMMETRIC_KEY:
                            signature.verify (new JSONSymKeyVerifier (new Sign.SymmetricOperations ()));
                            debugOutput ("Symmetric key signature validated for Key ID: " + signature.getKeyID ());
                            break;
  
                          default:
                            KeyStoreVerifier verifier = new KeyStoreVerifier (DemoKeyStore.getExampleDotComKeyStore ());
                            signature.verify (new JSONX509Verifier (verifier));
                            debugOutput ("X509 signature validated for: " + new CertificateInfo (verifier.getSignerCertificate ()).toString ());
                            break;
                        }
                    }
                  else
                    {
                      recurseObject (rd.getObject (property));
                    }
                  break;

                case ARRAY:
                  recurseArray (rd.getArray (property));
                  break;

                default:
                  rd.scanAway (property);
              }
          }
      }

    void recurseArray (JSONArrayReader array) throws IOException
      {
        while (array.hasMore ())
          {
            if (array.getElementType () == JSONTypes.OBJECT)
              {
                recurseObject (array.getObject ());
              }
            else if (array.getElementType () == JSONTypes.ARRAY)
              {
                recurseArray (array.getArray ());
              }
            else
              {
                array.scanAway ();
              }
          }        
      }

    void debugOutput (String string)
      {
        if (count == 1)
          {
            System.out.println (string);
          }
      }

    public static void main (String[] argc)
      {
        if (argc.length != 1 && argc.length != 2)
          {
            System.out.println ("\ninstance-document-file [normalize-debug-file|-rnnnn]");
            System.exit (0);
          }
        try
          {
            int repeat = 1;
            if (argc.length == 2)
              {
                if (argc[1].startsWith ("-r"))
                  {
                    repeat = Integer.parseInt (argc[1].substring (2));
                  }
                else
                  {
                    JSONObjectWriter.setNormalizationDebugFile (argc[1]);
                  }
              }
            while (count++ < repeat)
              {
                Verify doc = new Verify ();
                doc.recurseObject (JSONParser.parse (ArrayUtil.readFile (argc[0])));
              }
          }
        catch (Exception e)
          {
            System.out.println ("Error: " + e.getMessage ());
            e.printStackTrace ();
          }
      }
  }
