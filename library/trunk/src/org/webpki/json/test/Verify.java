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
import java.security.PublicKey;
import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.webpki.crypto.KeyStoreVerifier;
import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.json.JSONAsymKeyVerifier;
import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONDecoderCache;
import org.webpki.json.JSONEnvelopedSignatureDecoder;
import org.webpki.json.JSONReaderHelper;
import org.webpki.json.JSONSymKeyVerifier;
import org.webpki.json.JSONWriter;
import org.webpki.json.JSONX509Verifier;

import org.webpki.util.ArrayUtil;

/**
 * Simple signature verify program
 */
public class Verify extends JSONDecoder
  {
    @Override
    protected void unmarshallJSONData (JSONReaderHelper rd) throws IOException
      {
        recurse (rd, true);
      }

    void recurse (JSONReaderHelper rd, boolean ignore) throws IOException
      {
        for (String property : rd.getProperties ())
          {
            if (ignore)
              {
                ignore = false;
                continue;
              }
            switch (rd.getPropertyType (property))
              {
                case OBJECT:
                  if (property.equals (JSONEnvelopedSignatureDecoder.ENVELOPED_SIGNATURE_JSON))
                    {
                      JSONEnvelopedSignatureDecoder signature = new JSONEnvelopedSignatureDecoder (rd);
                      switch (signature.getSignatureType ())
                        {
                          case ASYMMETRIC_KEY:
                            try
                              {
                                PublicKey public_key = DemoKeyStore.getECDSAStore ().getCertificate ("mykey").getPublicKey ();
                                signature.verify (new JSONAsymKeyVerifier (public_key));
                                System.out.println ("Asymmetric key signature validated for: " + public_key.toString ());
                              }
                            catch (GeneralSecurityException e)
                              {
                                throw new IOException (e);
                              }
                            break;
  
                          case SYMMETRIC_KEY:
                            signature.verify (new JSONSymKeyVerifier (new Sign.SymmetricOperations ()));
                            System.out.println ("Symmetric key signature validated for Key ID: " + signature.getKeyID ());
                            break;
  
                          default:
                            KeyStoreVerifier verifier = new KeyStoreVerifier (DemoKeyStore.getExampleDotComKeyStore ());
                            signature.verify (new JSONX509Verifier (verifier));
                            System.out.println ("X509 signature validated for: " + verifier.getSignerCertificateInfo ().toString ());
                            break;
                        }
                    }
                  else
                    {
                      recurse (rd.getObject (property), false);
                    }
                  break;

                case OBJECT_ARRAY:
                  for (JSONReaderHelper next : rd.getObjectArray (property))
                    {
                      recurse (next, false);
                    }
                  break;

                default:
                  rd.scanAway (property);
              }
          }
      }

    @Override
    protected String getVersion ()
      {
        return Sign.VERSION;
      }

    @Override
    protected String getRootProperty ()
      {
        return Sign.ROOT_PROPERTY;
      }

    public static void main (String[] argc)
      {
        if (argc.length != 1 && argc.length != 2)
          {
            System.out.println ("\ninstance-document-file [canonicalize-debug-file|-rnnnn]");
            System.exit (0);
          }
        try
          {
            Security.insertProviderAt (new BouncyCastleProvider(), 1);
            int repeat = 1;
            if (argc.length == 2)
              {
                if (argc[1].startsWith ("-r"))
                  {
                    repeat = Integer.parseInt (argc[1].substring (2));
                  }
                else
                  {
                    JSONWriter.setCanonicalizationDebugFile (argc[1]);
                  }
              }
            JSONDecoderCache parser = new JSONDecoderCache ();
            parser.addToCache (Verify.class);
            while (repeat-- > 0)
              {
                parser.parse (ArrayUtil.readFile (argc[0]));
              }
          }
        catch (Exception e)
          {
            System.out.println ("Error: " + e.getMessage ());
            e.printStackTrace ();
          }
      }
  }
