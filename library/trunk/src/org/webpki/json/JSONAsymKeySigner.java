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

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyAlgorithms;

/**
 * Initiatiator object for asymmetric key signatures.
 */
public class JSONAsymKeySigner extends JSONSigner
  {
    AsymSignatureAlgorithms algorithm;

    AsymKeySignerInterface signer;
    
    PublicKey public_key;
    
    public void setSignatureAlgorithm (AsymSignatureAlgorithms algorithm)
      {
        this.algorithm = algorithm;
      }

    public JSONAsymKeySigner (AsymKeySignerInterface signer) throws IOException
      {
        this.signer = signer;
        public_key = signer.getPublicKey ();
        algorithm = KeyAlgorithms.getKeyAlgorithm (public_key).getRecommendedSignatureAlgorithm ();
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
    void writeKeyInfoData (JSONWriter wr) throws IOException
      {
        JSONEnvelopedSignatureEncoder.writePublicKey (wr, public_key);
      }
  }