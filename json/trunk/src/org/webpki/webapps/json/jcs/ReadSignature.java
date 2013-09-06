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
package org.webpki.webapps.json.jcs;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PublicKey;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.KeyStoreVerifier;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.json.JSONAsymKeyVerifier;
import org.webpki.json.JSONDecoder;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.json.JSONReaderHelper;
import org.webpki.json.JSONSymKeyVerifier;
import org.webpki.json.JSONTypes;
import org.webpki.json.JSONX509Verifier;

import org.webpki.util.DebugFormatter;

/**
 * Simple signature verify program
 */
public class ReadSignature extends JSONDecoder
  {
    private StringBuffer result = new StringBuffer ();

    @Override
    protected void unmarshallJSONData (JSONReaderHelper rd) throws IOException
      {
        recurse (rd);
      }

    void recurse (JSONReaderHelper rd) throws IOException
      {
        for (String property : rd.getProperties ())
          {
            switch (rd.getPropertyType (property))
              {
                case OBJECT:
                  if (property.equals (JSONSignatureDecoder.SIGNATURE_JSON))
                    {
                      JSONSignatureDecoder signature = new JSONSignatureDecoder (rd);
                      switch (signature.getSignatureType ())
                        {
                          case ASYMMETRIC_KEY:
                            try
                              {
                                KeyStore ks = signature.getSignatureAlgorithm ().getURI ().contains ("rsa") ? 
                                        DemoKeyStore.getMybankDotComKeyStore () : DemoKeyStore.getECDSAStore ();
                                PublicKey public_key = ks.getCertificate ("mykey").getPublicKey ();
                                signature.verify (new JSONAsymKeyVerifier (public_key));
                                debugOutput ("Asymmetric key signature validated for:\n" + public_key.toString ());
                              }
                            catch (GeneralSecurityException e)
                              {
                                throw new IOException (e);
                              }
                            break;
  
                          case SYMMETRIC_KEY:
                            signature.verify (new JSONSymKeyVerifier (new MySignature.SymmetricOperations ()));
                            debugOutput ("Symmetric key signature validated for Key ID: " + signature.getKeyID () + "\nValue=" + DebugFormatter.getHexString (MySignature.SYM_KEY));
                            break;
  
                          default:
                            KeyStoreVerifier verifier = new KeyStoreVerifier (DemoKeyStore.getExampleDotComKeyStore ());
                            signature.verify (new JSONX509Verifier (verifier));
                            debugOutput ("X509 signature validated for:\n" + new CertificateInfo (verifier.getSignerCertificate ()).toString ());
                            break;
                        }
                    }
                  else
                    {
                      recurse (rd.getObject (property));
                    }
                  break;

                case ARRAY:
                  if (rd.getArrayType (property) == JSONTypes.OBJECT)
                    {
                      for (JSONReaderHelper next : rd.getObjectArray (property))
                        {
                          recurse (next);
                        }
                      break;
                    }

                default:
                  rd.scanAway (property);
              }
          }
      }

    void debugOutput (String string)
      {
        result.append ('\n').append (string).append ('\n');
      }
    
    String getResult ()
      {
        return result.length () == 0 ? "No signature(s) found!\n" : result.toString ();
      }

    @Override
    protected String getContext ()
      {
        return MySignature.CONTEXT;
      }
   }
