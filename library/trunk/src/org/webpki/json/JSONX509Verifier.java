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

    @Override
    void verify (JSONEnvelopedSignatureDecoder signature_decoder) throws IOException
      {
        verifier.verifyCertificatePath (signature_decoder.certificate_path);
      }

    @Override
    JSONEnvelopedSignatureDecoder.SIGNATURE getVerifierType () throws IOException
      {
        return JSONEnvelopedSignatureDecoder.SIGNATURE.X509_CERTIFICATE;
      }
  }