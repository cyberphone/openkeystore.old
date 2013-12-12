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
 * Encoder for JSON signatures.
 * Only used internally.
 * 
 */
class JSONSignatureEncoder extends JSONSignature
  {
    private static final long serialVersionUID = 1L;

    static void writeCryptoBinary (JSONObjectWriter wr, BigInteger value, String name) throws IOException
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

    static void setPublicKey (JSONObjectWriter wr, PublicKey public_key) throws IOException
      {
        JSONObjectWriter public_key_writer = wr.setObject (PUBLIC_KEY_JSON);
        KeyAlgorithms key_alg = KeyAlgorithms.getKeyAlgorithm (public_key);
        if (key_alg.isRSAKey ())
          {
            JSONObjectWriter rsa_key_writer = public_key_writer.setObject (RSA_JSON);
            RSAPublicKey rsa_public = (RSAPublicKey)public_key;
            writeCryptoBinary (rsa_key_writer, rsa_public.getModulus (), MODULUS_JSON);
            writeCryptoBinary (rsa_key_writer, rsa_public.getPublicExponent (), EXPONENT_JSON);
          }
        else
          {
            JSONObjectWriter ec_key_writer = public_key_writer.setObject (EC_JSON);
            ec_key_writer.setString (NAMED_CURVE_JSON, key_alg.getURI ());
            ECPoint ec_point = ((ECPublicKey)public_key).getW ();
            writeCryptoBinary (ec_key_writer, ec_point.getAffineX (), X_JSON);
            writeCryptoBinary (ec_key_writer, ec_point.getAffineY (), Y_JSON);
          }
      }

    static void setX509CertificatePath (JSONObjectWriter wr, X509Certificate[] certificate_path) throws IOException
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

    JSONSignatureEncoder (JSONSigner signer, JSONObjectWriter wr) throws IOException
      {
        JSONObjectWriter signature_writer = wr.setObject (SIGNATURE_JSON);
        signature_writer.setString (ALGORITHM_JSON, signer.getAlgorithm ().getURI ());
        signer.writeKeyInfoData (signature_writer.setObject (KEY_INFO_JSON));
        signature_writer.setBinary (SIGNATURE_VALUE_JSON, signer.signData (JSONObjectWriter.getCanonicalizedSubset (wr.root)));
      }
  }
