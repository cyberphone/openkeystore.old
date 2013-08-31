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

import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SymKeyVerifierInterface;

/**
 * Initiatiator object for symmetric key signature verifiers.
 */
public class JSONSymKeyVerifier extends JSONVerifier
  {
    SymKeyVerifierInterface verifier;
    
    public JSONSymKeyVerifier (SymKeyVerifierInterface verifier) throws IOException
      {
        this.verifier = verifier;
      }

    @Override
    void verify (JSONSignatureDecoder signature_decoder) throws IOException
      {
        signature_decoder.checkVerification (verifier.verifyData (signature_decoder.canonicalized_data,
                                                                  signature_decoder.signature_value,
                                                                  (MACAlgorithms)signature_decoder.algorithm));
      }

    @Override
    JSONSignatureTypes getVerifierType () throws IOException
      {
        return JSONSignatureTypes.SYMMETRIC_KEY;
      }
  }
