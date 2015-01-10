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
package org.webpki.crypto;

import java.io.IOException;

public enum SymEncryptionAlgorithms implements EncryptionAlgorithms
  {
    AES128_CBC      ("http://www.w3.org/2001/04/xmlenc#aes128-cbc", 
                        "AES/CBC/PKCS5Padding", 16, true,  true, true, false),
                        
    AES192_CBC      ("http://www.w3.org/2001/04/xmlenc#aes192-cbc",
                        "AES/CBC/PKCS5Padding", 24, true,  true, true, false),
                        
    AES256_CBC      ("http://www.w3.org/2001/04/xmlenc#aes256-cbc",
                        "AES/CBC/PKCS5Padding", 32, true,  true, true, false),
                        
    KW_AES128       ("http://www.w3.org/2001/04/xmlenc#kw-aes128",
                        "AESWrap",              16, false, false, false, true),
                        
    KW_AES256       ("http://www.w3.org/2001/04/xmlenc#kw-aes256",
                        "AESWrap",              32, false, false, false, true),
                        
    AES_ECB_NOPAD   ("http://xmlns.webpki.org/sks/algorithm#aes.ecb.nopad",
                        "AES/ECB/NoPadding",    0,  false, false, true,  true),  // SecurID
                        
    AES_ECB_PAD     ("http://xmlns.webpki.org/sks/algorithm#aes.ecb",
                        "AES/ECB/PKCS5Padding", 0,  false, false, false, false),
                        
    AES_CBC_NOPAD   ("http://xmlns.webpki.org/sks/algorithm#aes.cbc.nopad",
                        "AES/CBC/NoPadding",    0,  true,  false, false,  true),
                        
    AES_CBC_PAD     ("http://xmlns.webpki.org/sks/algorithm#aes.cbc",
                        "AES/CBC/PKCS5Padding", 0,  true,  false, true,   false);
    

    private final String         sks_id;          // As (typically) expressed in protocols
    private final String         jcename;         // As expressed for JCE
    private final int            key_length;      // 0 => 16, 24 and 32 are ok
    private final boolean        iv_mode;         // CBC
    private final boolean        internal_iv;     // XML Encryption
    private final boolean        sks_mandatory;   // If required
    private final boolean        needs_padding;   // If that is the case

    private SymEncryptionAlgorithms (String sks_id, String jcename, int key_length, boolean iv_mode, boolean internal_iv, boolean sks_mandatory, boolean needs_padding)
      {
        this.sks_id = sks_id;
        this.jcename = jcename;
        this.key_length = key_length;
        this.iv_mode = iv_mode;
        this.internal_iv = internal_iv;
        this.sks_mandatory = sks_mandatory;
        this.needs_padding = needs_padding;
      }


    @Override
    public boolean isSymmetric ()
      {
        return true;
      }


    @Override
    public boolean isMandatorySKSAlgorithm ()
      {
        return sks_mandatory;
      }


    @Override
    public String getJCEName ()
      {
        return jcename;
      }


    @Override
    public String getURI ()
      {
        return sks_id;
      }


    @Override
    public String getOID ()
      {
        return null;
      }


    @Override
    public String getJOSEName ()
      {
        return null;
      }


    public int getKeyLength ()
      {
        return key_length;
      }

    
    public boolean needsIV ()
      {
        return iv_mode;
      }

    
    public boolean internalIV ()
      {
        return internal_iv;
      }
 

    public boolean needsPadding ()
      {
        return needs_padding;
      }

    
    public static SymEncryptionAlgorithms getAlgorithmFromID (String algorithm_id) throws IOException
      {
        for (SymEncryptionAlgorithms alg : values ())
          {
            if (algorithm_id.equals (alg.sks_id))
              {
                return alg;
              }
          }
        throw new IOException ("Unknown algorithm: " + algorithm_id);
      }
  }
