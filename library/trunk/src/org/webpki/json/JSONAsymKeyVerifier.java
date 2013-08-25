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

import java.security.PublicKey;

/**
 * Initiatiator object for asymmetric key signature verifiers.
 */
public class JSONAsymKeyVerifier extends JSONVerifier
  {
    PublicKey public_key;

    public JSONAsymKeyVerifier (PublicKey public_key) throws IOException
      {
        this.public_key = public_key;
      }

    @Override
    void verify (JSONEnvelopedSignatureDecoder signature_decoder) throws IOException
      {
        if (!public_key.equals (signature_decoder.public_key))
          {
            throw new IOException ("Provided public key differs from the signature key");
          }
       }

    @Override
    JSONEnvelopedSignatureDecoder.SIGNATURE getVerifierType () throws IOException
      {
        return JSONEnvelopedSignatureDecoder.SIGNATURE.ASYMMETRIC_KEY;
      }
  }
