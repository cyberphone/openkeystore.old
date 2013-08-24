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

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import java.util.Vector;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SignerInterface;

/**
 * Initiatiator object for X.509 signatures.
 */
public class JSONX509Signer implements JSONSigner
  {
    AsymSignatureAlgorithms algorithm;

    SignerInterface signer;
    
    X509Certificate[] certificate_path;
    
    class SignatureCertificate implements JSONObject
      {
        @Override
        public void writeObject (JSONWriter wr) throws IOException
          {
            X509Certificate signer_cert = certificate_path[0];
            wr.setString (JSONEnvelopedSignatureEncoder.ISSUER_JSON, signer_cert.getIssuerX500Principal ().getName ());
            wr.setBigInteger (JSONEnvelopedSignatureEncoder.SERIAL_NUMBER_JSON, signer_cert.getSerialNumber ());
            wr.setString (JSONEnvelopedSignatureEncoder.SUBJECT_JSON, signer_cert.getSubjectX500Principal ().getName ());
          }
      }

    public void setSignatureAlgorithm (AsymSignatureAlgorithms algorithm)
      {
        this.algorithm = algorithm;
      }

    public JSONX509Signer (SignerInterface signer) throws IOException
      {
        this.signer = signer;
        certificate_path = CertificateUtil.getSortedPath (signer.prepareSigning (true));
        algorithm = KeyAlgorithms.getKeyAlgorithm (certificate_path[0].getPublicKey ()).getRecommendedSignatureAlgorithm ();
      }

    public static void writeX509CertificatePath (JSONWriter wr, X509Certificate[] certificate_path) throws IOException
      {
        Vector<byte[]> certificates = new Vector<byte[]> ();
        for (X509Certificate certificate : certificate_path)
          {
            try
              {
                certificates.add (certificate.getEncoded ());
              }
            catch (GeneralSecurityException e)
              {
                throw new IOException (e);
              }
          }
        wr.setBinaryArray (JSONEnvelopedSignatureEncoder.X509_CERTIFICATE_PATH_JSON, certificates);
      }

    @Override
    public void writeObject (JSONWriter wr) throws IOException
      {
        wr.setObject (JSONEnvelopedSignatureEncoder.SIGNATURE_CERTIFICATE_JSON, new SignatureCertificate ());
        writeX509CertificatePath (wr, certificate_path);
      }

    @Override
    public SignatureAlgorithms getAlgorithm ()
      {
        return algorithm;
      }

    @Override
    public byte[] signData (byte[] data) throws IOException
      {
        return signer.signData (data, algorithm);
      }
  }
