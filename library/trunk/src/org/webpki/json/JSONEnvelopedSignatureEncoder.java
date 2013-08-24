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

/**
 * Encoder for enveloped JSON signatures.
 */
public class JSONEnvelopedSignatureEncoder extends JSONEnvelopedSignature
  {
    JSONHolder signature;
    
    JSONHolder signature_info;
    
    String name;
    
    String value;

    JSONSigner signer;
    
    class Reference implements JSONObject
      {
        @Override
        public void writeObject (JSONWriter wr) throws IOException
          {
            wr.setString (NAME_JSON, name);
            wr.setString (VALUE_JSON, value);
          }
      }
    
    class SignatureInfo implements JSONObject
      {
        @Override
        public void writeObject (JSONWriter wr) throws IOException
          {
            wr.setString (ALGORITHM_JSON, signer.getAlgorithm ().getURI ());
            wr.setObject (REFERENCE_JSON, new Reference ());
            wr.setObject (KEY_INFO_JSON, signer);
          }
      }

    class EnvelopedSignature implements JSONObject
      {
        @Override
        public void writeObject (JSONWriter wr) throws IOException
          {
            signature = wr.current;
            signature_info = wr.localSetObject (SIGNATURE_INFO_JSON, new SignatureInfo ());
          }
      }

    public JSONEnvelopedSignatureEncoder (JSONSigner signer)
      {
        this.signer = signer;
      }

    public void sign (JSONWriter wr, String name, String value) throws IOException
      {
        this.name = name;
        this.value = value;
        wr.setObject (ENVELOPED_SIGNATURE_JSON, new EnvelopedSignature ());
        signature.addProperty (SIGNATURE_VALUE_JSON, 
                               new JSONValue (true, 
                                              true,
                                              JSONWriter.getBase64 (signer.signData (wr.getCanonicalizedSubset (signature_info, name, value)))));
      }
  }
