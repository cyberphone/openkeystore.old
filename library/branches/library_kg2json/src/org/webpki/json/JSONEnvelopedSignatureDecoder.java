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
import java.security.Signature;
import java.security.cert.X509Certificate;

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.VerifierInterface;

/**
 * Decoder for enveloped JSON signatures.
 */
public class JSONEnvelopedSignatureDecoder extends JSONEnvelopedSignature
  {
    String algorithm;
    
    String name;
    
    String value;
    
    byte[] canonicalized_data;
    
    byte[] signature_value;
    
    X509Certificate[] certificate_path;
    
    public JSONEnvelopedSignatureDecoder (JSONReaderHelper rd) throws IOException
      {
        rd = rd.getObject (ENVELOPED_SIGNATURE_JSON);
        JSONReaderHelper signature_info = rd.getObject (SIGNATURE_INFO_JSON);
        getSignatureInfo (signature_info);
        signature_value = rd.getBinary (SIGNATURE_VALUE_JSON);
        JSONWriter writer = new JSONWriter (rd.root);
        canonicalized_data = writer.getCanonicalizedSubset (signature_info.current, name, value);
        try
          {
            Signature sig = Signature.getInstance (SignatureAlgorithms.getAlgorithmFromURI (algorithm).getJCEName ());
            sig.initVerify (certificate_path[0].getPublicKey ());
            sig.update (canonicalized_data);
            if (sig.verify (signature_value))
              {
                System.out.println ("DID IT");
              }
            else throw new IOException ("BADD");
          }
        catch (GeneralSecurityException e)
          {
            
          }
      }

    void getSignatureInfo (JSONReaderHelper rd) throws IOException
      {
        algorithm = rd.getString (ALGORITHM_JSON);
        getReference (rd.getObject (REFERENCE_JSON));
        getKeyInfo (rd.getObject (KEY_INFO_JSON));
      }

    void getKeyInfo (JSONReaderHelper rd) throws IOException
      {
        if (rd.hasProperty (SIGNATURE_CERTIFICATE_JSON))
          {
            getSignatureCertificate (rd.getObject (SIGNATURE_CERTIFICATE_JSON));
            getX509CertificatePath (rd);
          }
        else if (rd.hasProperty (X509_CERTIFICATE_PATH_JSON))
          {
            getX509CertificatePath (rd);
          }
      }

    void getX509CertificatePath (JSONReaderHelper rd) throws IOException
      {
        certificate_path = CertificateUtil.getSortedPathFromBlobs (rd.getBinaryList (X509_CERTIFICATE_PATH_JSON));
      }

    void getSignatureCertificate (JSONReaderHelper rd) throws IOException
      {
        String issuer = rd.getString (ISSUER_JSON);
        BigInteger serial_number = rd.getBigInteger (SERIAL_NUMBER_JSON);
        String subject = rd.getString (SUBJECT_JSON);
      }

    void getReference (JSONReaderHelper rd) throws IOException
      {
        name = rd.getString (NAME_JSON);
        value = rd.getString (VALUE_JSON);
      }

    public static JSONEnvelopedSignatureDecoder read (JSONReaderHelper rd, String expected_name, String expected_value) throws IOException
      {
        JSONEnvelopedSignatureDecoder verifier = new JSONEnvelopedSignatureDecoder (rd);
        if (!expected_name.equals (verifier.name) || !expected_value.equals (verifier.value))
          {
            throw new IOException ("Non-matching \"" + REFERENCE_JSON + "\" to signature");
          }
        return verifier;
      }

    public void validate (VerifierInterface verifier) throws IOException
      {
        verifier.verifyCertificatePath (certificate_path);
      }
  }
