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

import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;

/**
 * Initiatiator object for symmetric key signatures.
 */
public class JSONSymKeySigner extends JSONSigner
  {
    private static final long serialVersionUID = 1L;

    MACAlgorithms algorithm;

    SymKeySignerInterface signer;
    
    String key_id = "symmetric-key";

    public JSONSymKeySigner setKeyId (String key_id)
      {
        this.key_id = key_id;
        return this;
      }

    public JSONSymKeySigner (SymKeySignerInterface signer) throws IOException
      {
        this.signer = signer;
        algorithm = signer.getMacAlgorithm ();
      }

    @Override
    SignatureAlgorithms getAlgorithm ()
      {
        return algorithm;
      }

    @Override
    byte[] signData (byte[] data) throws IOException
      {
        return signer.signData (data);
      }

    @Override
    void writeKeyInfoData (JSONObjectWriter wr) throws IOException
      {
        wr.setString (JSONSignatureDecoder.KEY_ID_JSON, key_id);
      }
  }
