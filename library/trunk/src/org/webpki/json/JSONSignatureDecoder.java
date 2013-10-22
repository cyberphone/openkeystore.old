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

import java.io.ByteArrayInputStream;
import java.io.IOException;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;

import java.util.Vector;

import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.KeyAlgorithms;

/**
 * Decoder for JSON signatures.
 */
public class JSONSignatureDecoder extends JSONSignature
  {
    private static final long serialVersionUID = 1L;

    SignatureAlgorithms algorithm;
    
    String algorithm_string;
    
    byte[] canonicalized_data;
    
    byte[] signature_value;
    
    X509Certificate[] certificate_path;

    PublicKey public_key;

    String key_id;
    
    JSONSignatureDecoder (JSONObjectReader rd) throws IOException
      {
        JSONObjectReader signature = rd.getObject (SIGNATURE_JSON);
        String version = signature.getStringConditional (VERSION_JSON, SIGNATURE_VERSION_ID);
        if (!version.equals (SIGNATURE_VERSION_ID))
          {
            throw new IOException ("Unknown \"" + SIGNATURE_JSON + "\" version: " + version);
          }
        algorithm_string = signature.getString (ALGORITHM_JSON);
        getKeyInfo (signature.getObject (KEY_INFO_JSON));
        signature_value = signature.getBinary (SIGNATURE_VALUE_JSON);
        JSONValue save = signature.json.properties.get (SIGNATURE_VALUE_JSON);
        signature.json.properties.remove (SIGNATURE_VALUE_JSON);
        canonicalized_data = JSONObjectWriter.getCanonicalizedSubset (rd.json);
        signature.json.properties.put (SIGNATURE_VALUE_JSON, save);
        switch (getSignatureType ())
          {
            case X509_CERTIFICATE:
              asymmetricSignatureVerification (certificate_path[0].getPublicKey ());
              break;

            case ASYMMETRIC_KEY:
              asymmetricSignatureVerification (public_key);
              break;

            default:
              algorithm = MACAlgorithms.getAlgorithmFromURI (algorithm_string);
          }
      }

    void getKeyInfo (JSONObjectReader rd) throws IOException
      {
        if (rd.hasProperty (X509_CERTIFICATE_PATH_JSON))
          {
            readX509CertificateEntry (rd);
          }
        else if (rd.hasProperty (PUBLIC_KEY_JSON))
          {
            public_key = getPublicKey (rd);
          }
        else if (rd.hasProperty (KEY_ID_JSON))
          {
            key_id = rd.getString (KEY_ID_JSON);
          }
        else
          {
            throw new IOException ("\"" + URL_JSON + "\" not yet implemented");
          }
      }

    static BigInteger readCryptoBinary (JSONObjectReader rd, String property) throws IOException
      {
        byte[] crypto_binary = rd.getBinary (property);
        if (crypto_binary[0] == 0x00)
          {
            throw new IOException ("Public key parameters must not contain leading zeroes");
          }
        return new BigInteger (1, crypto_binary);
      }

    static PublicKey getPublicKey (JSONObjectReader rd) throws IOException
      {
        rd = rd.getObject (PUBLIC_KEY_JSON);
        try
          {
            if (rd.hasProperty (RSA_JSON))
              {
                rd = rd.getObject (RSA_JSON);
                return KeyFactory.getInstance ("RSA").generatePublic (new RSAPublicKeySpec (readCryptoBinary (rd, MODULUS_JSON),
                                                                                            readCryptoBinary (rd, EXPONENT_JSON)));
              }
            rd = rd.getObject (EC_JSON);
              {
                KeyAlgorithms ec = KeyAlgorithms.getKeyAlgorithmFromURI (rd.getString (NAMED_CURVE_JSON));
                ECPoint w = new ECPoint (readCryptoBinary (rd, X_JSON), readCryptoBinary (rd, Y_JSON));
                return KeyFactory.getInstance ("EC").generatePublic (new ECPublicKeySpec (w, ec.getECParameterSpec ()));
              }
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }

    static X509Certificate[] getX509CertificatePath (JSONObjectReader rd) throws IOException
      {
        X509Certificate last_certificate = null;
        Vector<X509Certificate> certificates = new Vector<X509Certificate> ();
        for (byte[] certificate_blob : rd.getBinaryArray (JSONSignature.X509_CERTIFICATE_PATH_JSON))
          {
            try
              {
                CertificateFactory cf = CertificateFactory.getInstance ("X.509");
                X509Certificate certificate = (X509Certificate)cf.generateCertificate (new ByteArrayInputStream (certificate_blob));
                certificates.add (pathCheck (last_certificate, last_certificate = certificate));
              }
            catch (GeneralSecurityException e)
              {
                throw new IOException (e);
              }
          }
        return certificates.toArray (new X509Certificate[0]);
      }

    void readX509CertificateEntry (JSONObjectReader rd) throws IOException
      {
        certificate_path = getX509CertificatePath (rd);
        if (rd.hasProperty (SIGNATURE_CERTIFICATE_JSON))
          {
            rd = rd.getObject (SIGNATURE_CERTIFICATE_JSON);
            String issuer = rd.getString (ISSUER_JSON);
            BigInteger serial_number = rd.getBigInteger (SERIAL_NUMBER_JSON);
            String subject = rd.getString (SUBJECT_JSON);
            X509Certificate signature_certificate = certificate_path[0];
            if (!signature_certificate.getIssuerX500Principal ().getName ().equals (issuer) ||
                !signature_certificate.getSerialNumber ().equals (serial_number) ||
                !signature_certificate.getSubjectX500Principal ().getName ().equals (subject))
              {
                throw new IOException ("\"" + SIGNATURE_CERTIFICATE_JSON + "\" doesn't match actual certificate");
              }
          }
      }

    void checkVerification (boolean success) throws IOException
      {
        if (!success)
          {
            String key;
            switch (getSignatureType ())
              {
                case X509_CERTIFICATE:
                  key = certificate_path[0].getPublicKey ().toString ();
                  break;
  
                case ASYMMETRIC_KEY:
                  key = public_key.toString ();
                  break;
  
                default:
                  key = getKeyID ();
               }
            throw new IOException ("Bad signature for key: " + key);
          }
      }

    void asymmetricSignatureVerification (PublicKey public_key) throws IOException
      {
        algorithm = AsymSignatureAlgorithms.getAlgorithmFromURI (algorithm_string);
        try
          {
            Signature sig = Signature.getInstance (algorithm.getJCEName ());
            sig.initVerify (public_key);
            sig.update (canonicalized_data);
            checkVerification (sig.verify (signature_value));
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }

    public byte[] getSignatureValue ()
      {
        return signature_value;
      }

    public SignatureAlgorithms getSignatureAlgorithm ()
      {
        return algorithm;
      }

    void checkRequest (JSONSignatureTypes signature_type) throws IOException
      {
        if (signature_type != getSignatureType ())
          {
            throw new IOException ("Request doesn't match received signature: " + getSignatureType ().toString ());
          }
      }

    public X509Certificate[] getX509CertificatePath () throws IOException
      {
        checkRequest (JSONSignatureTypes.X509_CERTIFICATE);
        return certificate_path;
      }

    public PublicKey getPublicKey () throws IOException
      {
        checkRequest (JSONSignatureTypes.ASYMMETRIC_KEY);
        return public_key;
      }

    public String getKeyID () throws IOException
      {
        checkRequest (JSONSignatureTypes.SYMMETRIC_KEY);
        return key_id;
      }

    public JSONSignatureTypes getSignatureType ()
      {
        if (certificate_path != null)
          {
            return JSONSignatureTypes.X509_CERTIFICATE;
          }
        return public_key == null ? JSONSignatureTypes.SYMMETRIC_KEY : JSONSignatureTypes.ASYMMETRIC_KEY;
      }

    public void verify (JSONVerifier verifier) throws IOException
      {
        if (verifier.getVerifierType () != getSignatureType ())
          {
            throw new IOException ("Verifier type doesn't match the received signature");
          }
        verifier.verify (this);
      }
  }
