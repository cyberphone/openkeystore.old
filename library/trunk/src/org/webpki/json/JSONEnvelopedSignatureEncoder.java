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
package org.webpki.json;

import java.io.IOException;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECPoint;

import java.util.Vector;

import org.webpki.crypto.KeyAlgorithms;

/**
 * Encoder for enveloped JSON signatures.
 */
public class JSONEnvelopedSignatureEncoder extends JSONEnvelopedSignature
  {
    JSONHolder signature;
    
    JSONHolder signature_info;
    
    String referenced_name;
    
    String referenced_value;

    JSONSigner signer;
    
    static void writeCryptoBinary (JSONWriter wr, BigInteger value, String name) throws IOException
      {
        byte[] crypto_binary = value.toByteArray ();
        if (crypto_binary[0] == 0x00)
          {
            byte[] wo_zero = new byte[crypto_binary.length - 1];
            System.arraycopy (crypto_binary, 1, wo_zero, 0, wo_zero.length);
            crypto_binary = wo_zero;
          }
        wr.setBinary (name, crypto_binary);
      }

    public static void writePublicKey (JSONWriter wr, final PublicKey public_key) throws IOException
      {
        wr.setObject (PUBLIC_KEY_JSON, new JSONObject ()
          {
            @Override
            public void writeObject (JSONWriter wr) throws IOException
              {
                final KeyAlgorithms key_alg = KeyAlgorithms.getKeyAlgorithm (public_key);
                if (key_alg.isRSAKey ())
                  {
                    wr.setObject (RSA_JSON, new JSONObject ()
                      {
                        @Override
                        public void writeObject (JSONWriter wr) throws IOException
                          {
                            RSAPublicKey rsa_public = (RSAPublicKey)public_key;
                            writeCryptoBinary (wr, rsa_public.getModulus (), MODULUS_JSON);
                            writeCryptoBinary (wr, rsa_public.getPublicExponent (), EXPONENT_JSON);
                          }
                      });
                  }
                else
                  {
                    wr.setObject (EC_JSON, new JSONObject ()
                      {
                        @Override
                        public void writeObject (JSONWriter wr) throws IOException
                          {
                            wr.setString (NAMED_CURVE_JSON, key_alg.getURI ());
                            ECPoint ec_point = ((ECPublicKey)public_key).getW ();
                            writeCryptoBinary (wr, ec_point.getAffineX (), X_JSON);
                            writeCryptoBinary (wr, ec_point.getAffineY (), Y_JSON);
                          }
                      });
                  }
              }
          });
      }

    public static void writeX509CertificatePath (JSONWriter wr, X509Certificate[] certificate_path) throws IOException
      {
        X509Certificate last_certificate = null;
        Vector<byte[]> certificates = new Vector<byte[]> ();
        for (X509Certificate certificate : certificate_path)
          {
            try
              {
                certificates.add (pathCheck (last_certificate, last_certificate = certificate).getEncoded ());
              }
            catch (GeneralSecurityException e)
              {
                throw new IOException (e);
              }
          }
        wr.setBinaryArray (X509_CERTIFICATE_PATH_JSON, certificates);
      }

    public JSONEnvelopedSignatureEncoder (JSONSigner signer)
      {
        this.signer = signer;
      }

    public void sign (JSONWriter wr, String name, String value) throws IOException
      {
        referenced_name = name;
        referenced_value = value;
        wr.setObject (ENVELOPED_SIGNATURE_JSON, new JSONObject ()
          {
            @Override
            public void writeObject (JSONWriter wr) throws IOException
              {
                signature = wr.current;
                signature_info = wr.localSetObject (SIGNATURE_INFO_JSON, new JSONObject ()
                  {
                    @Override
                    public void writeObject (JSONWriter wr) throws IOException
                      {
                        wr.setString (ALGORITHM_JSON, signer.getAlgorithm ().getURI ());
                        wr.setObject (REFERENCE_JSON, new JSONObject ()
                          {
                            @Override
                            public void writeObject (JSONWriter wr) throws IOException
                              {
                                wr.setString (NAME_JSON, referenced_name);
                                wr.setString (VALUE_JSON, referenced_value);
                              }
                          });
                        wr.setObject (KEY_INFO_JSON, new JSONObject ()
                          {
                            @Override
                            public void writeObject (JSONWriter wr) throws IOException
                              {
                                signer.writeKeyInfoData (wr);
                              }
                          });
                      }
                  });
              }
          });
        signature.addProperty (SIGNATURE_VALUE_JSON, 
                               new JSONValue (true, 
                                              true,
                                              JSONWriter.getBase64 (signer.signData (wr.getCanonicalizedSubset (signature_info, name, value)))));
      }
  }
