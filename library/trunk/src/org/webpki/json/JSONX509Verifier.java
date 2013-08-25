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

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.VerifierInterface;

/**
 * Initiatiator object for X.509 signature verifiers.
 */
public class JSONX509Verifier extends JSONVerifier
  {
    VerifierInterface verifier;

    public JSONX509Verifier (VerifierInterface verifier) throws IOException
      {
        this.verifier = verifier;
      }

    public static X509Certificate[] readX509CertificatePath (JSONReaderHelper rd) throws IOException
      {
        X509Certificate last_certificate = null;
        Vector<X509Certificate> certificates = new Vector<X509Certificate> ();
        for (byte[] certificate_blob : rd.getBinaryList (JSONEnvelopedSignature.X509_CERTIFICATE_PATH_JSON))
          {
            X509Certificate certificate = CertificateUtil.getCertificateFromBlob (certificate_blob);
            if (last_certificate != null)
              {
                String issuer = last_certificate.getIssuerX500Principal ().getName ();
                String subject = certificate.getSubjectX500Principal ().getName ();
                if (!issuer.equals (subject))
                  {
                    throw new IOException ("Path issuer order error, '" + issuer + "' versus '" + subject + "'");
                  }
                try
                  {
                    last_certificate.verify (certificate.getPublicKey ());
                  }
                catch (GeneralSecurityException e)
                  {
                    throw new IOException (e);
                  }
              }
            certificates.add (last_certificate = certificate);
          }
        return certificates.toArray (new X509Certificate[0]);
      }

    @Override
    void verify (JSONEnvelopedSignatureDecoder signature_decoder) throws IOException
      {
        verifier.verifyCertificatePath (signature_decoder.certificate_path);
      }

    @Override
    JSONEnvelopedSignatureDecoder.SIGNATURE getValidatorType () throws IOException
      {
        return JSONEnvelopedSignatureDecoder.SIGNATURE.X509_CERTIFICATE;
      }
  }
