/*
 *  Copyright 2006-2015 WebPKI.org (http://webpki.org).
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

import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SymKeyVerifierInterface;

/**
 * Initiatiator object for symmetric key signature verifiers.
 */
public class JSONSymKeyVerifier extends JSONVerifier
  {
    private static final long serialVersionUID = 1L;

    SymKeyVerifierInterface verifier;
    
    /**
     * Verifier for symmetric keys.
     * Note that you can access the received KeyID from {@link JSONSignatureDecoder}.
     * @param verifier Verifies that the key and signature value match.
     */
    public JSONSymKeyVerifier (SymKeyVerifierInterface verifier)
      {
        this.verifier = verifier;
      }

    @Override
    void verify (JSONSignatureDecoder signature_decoder) throws IOException
      {
        signature_decoder.checkVerification (verifier.verifyData (signature_decoder.normalized_data,
                                                                  signature_decoder.signature_value,
                                                                  (MACAlgorithms)signature_decoder.algorithm,
                                                                  signature_decoder.key_id));
      }

    @Override
    JSONSignatureTypes getVerifierType () throws IOException
      {
        return JSONSignatureTypes.SYMMETRIC_KEY;
      }
  }
