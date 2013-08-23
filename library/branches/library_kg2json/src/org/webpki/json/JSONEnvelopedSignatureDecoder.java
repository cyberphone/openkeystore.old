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

import org.webpki.crypto.VerifierInterface;

/**
 * Decoder for enveloped JSON signatures.
 */
public class JSONEnvelopedSignatureDecoder extends JSONEnvelopedSignature
  {
    String algorithm;
    
    public JSONEnvelopedSignatureDecoder (JSONReaderHelper rd) throws IOException
      {
        getSignatureInfo (rd.getObject (SIGNATURE_INFO_JSON));
        rd.getString (SIGNATURE_VALUE_JSON);
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
        String[] certificates_in_bas64 = rd.getList (X509_CERTIFICATE_PATH_JSON);
      }

    void getSignatureCertificate (JSONReaderHelper rd) throws IOException
      {
        String issuer = rd.getString (ISSUER_JSON);
        BigInteger serial_number = rd.getBigInteger (SERIAL_NUMBER_JSON);
        String subject = rd.getString (SUBJECT_JSON);
      }

    void getReference (JSONReaderHelper rd) throws IOException
      {
        String name = rd.getString (NAME_JSON);
        String value = rd.getString (VALUE_JSON);
      }

    public static JSONEnvelopedSignatureDecoder read (JSONReaderHelper rd, String element, String value) throws IOException
      {
        // TODO Auto-generated method stub
        return null;
      }

    public void validate (VerifierInterface verifier)
      {
        // TODO Auto-generated method stub
        
      }
  }
