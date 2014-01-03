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
package org.webpki.json;

import java.io.IOException;

import java.security.cert.X509Certificate;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignerInterface;

/**
 * Initiatiator object for X.509 signatures.
 */
public class JSONX509Signer extends JSONSigner
  {
    private static final long serialVersionUID = 1L;

    AsymSignatureAlgorithms algorithm;

    SignerInterface signer;
    
    X509Certificate[] certificate_path;
    
    boolean output_signature_certificate_attributes;
    
    public JSONX509Signer setSignatureAlgorithm (AsymSignatureAlgorithms algorithm)
      {
        this.algorithm = algorithm;
        return this;
      }

    public JSONX509Signer setSignatureCertificateAttributes (boolean flag)
      {
        output_signature_certificate_attributes = flag;
        return this;
      }

    public JSONX509Signer (SignerInterface signer) throws IOException
      {
        this.signer = signer;
        certificate_path = signer.getCertificatePath ();
        algorithm = KeyAlgorithms.getKeyAlgorithm (certificate_path[0].getPublicKey ()).getRecommendedSignatureAlgorithm ();
      }

    @Override
    AsymSignatureAlgorithms getAlgorithm ()
      {
        return algorithm;
      }

    @Override
    byte[] signData (byte[] data) throws IOException
      {
        return signer.signData (data, algorithm);
      }

    @Override
    void writeKeyInfoData (JSONObjectWriter wr) throws IOException
      {
        if (output_signature_certificate_attributes)
          {
            X509Certificate signer_cert = certificate_path[0];
            JSONObjectWriter signature_certificate_info_writer = wr.setObject (JSONSignatureDecoder.SIGNATURE_CERTIFICATE_JSON);
            signature_certificate_info_writer.setString (JSONSignatureDecoder.ISSUER_JSON, signer_cert.getIssuerX500Principal ().getName ());
            signature_certificate_info_writer.setBigInteger (JSONSignatureDecoder.SERIAL_NUMBER_JSON, signer_cert.getSerialNumber ());
            signature_certificate_info_writer.setString (JSONSignatureDecoder.SUBJECT_JSON, signer_cert.getSubjectX500Principal ().getName ());
          }
        wr.setX509CertificatePath (certificate_path);
      }
  }
