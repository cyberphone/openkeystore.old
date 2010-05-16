/*
 *  Copyright 2006-2010 WebPKI.org (http://webpki.org).
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
package org.webpki.crypto;

import java.io.IOException;


public enum SymEncryptionAlgorithms implements EncryptionAlgorithms
  {
    AES128_CBC      ("http://www.w3.org/2001/04/xmlenc#aes128-cbc", "AES/CBC/PKCS5Padding", true),
    AES192_CBC      ("http://www.w3.org/2001/04/xmlenc#aes192-cbc", "AES/CBC/PKCS5Padding", true),
    AES256_CBC      ("http://www.w3.org/2001/04/xmlenc#aes256-cbc", "AES/CBC/PKCS5Padding", true),
    KW_AES128       ("http://www.w3.org/2001/04/xmlenc#kw-aes128",  "AESWrap",              false),
    KW_AES256       ("http://www.w3.org/2001/04/xmlenc#kw-aes256",  "AESWrap",              false),
    AES_ECB_NP      ("internal:AES/ECB/NoPadding",                  "AES/ECB/NoPadding",    false),  // SecurID
    AES_ECB_P5      ("internal:AES/ECB/PKCS5Padding",               "AES/ECB/PKCS5Padding", false),
    AES_CBC_NP      ("internal:AES/CBC/NoPadding",                  "AES/CBC/NoPadding",    true),
    AES_CBC_P5      ("internal:AES/CBC/PKCS5Padding",               "AES/CBC/PKCS5Padding", true);

    private final String         uri;             // As expressed in XML
    private final String         jcename;         // As expressed for JCE
    private final boolean        iv_mode;         // CBC

    private SymEncryptionAlgorithms (String uri, String jcename, boolean iv_mode)
      {
        this.uri = uri;
        this.jcename = jcename;
        this.iv_mode = iv_mode;
      }


    public String getJCEName ()
      {
        return jcename;
      }


    public String getURI ()
      {
        return uri;
      }


    public boolean needsIV ()
      {
        return iv_mode;
      }


    public static SymEncryptionAlgorithms getAlgorithmFromURI (String uri) throws IOException
      {
        for (SymEncryptionAlgorithms alg : values ())
          {
            if (uri.equals (alg.uri))
              {
                return alg;
              }
          }
        throw new IOException ("Unknown algorithm: " + uri);
      }
  }
