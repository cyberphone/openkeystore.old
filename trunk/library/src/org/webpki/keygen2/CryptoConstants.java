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
package org.webpki.keygen2;

public interface CryptoConstants
  {
    /////////////////////////////////////////////////////////////////////////////////////////////
    // Strings that are used as key modifiers to HMAC operations are used "as is"
    /////////////////////////////////////////////////////////////////////////////////////////////
    public static final byte[] CRYPTO_STRING_DEVICE_ATTEST   = new byte[] {'D','e','v','i','c','e',' ','A','t','t','e','s','t','a','t','i','o','n'};

    public static final byte[] CRYPTO_STRING_ENCRYPTION      = new byte[] {'E','n','c','r','y','p','t','i','o','n',' ','K','e','y'};

    public static final byte[] CRYPTO_STRING_SIGNATURE       = new byte[] {'E','x','t','e','r','n','a','l',' ','S','i','g','n','a','t','u','r','e'};

    /////////////////////////////////////////////////////////////////////////////////////////////
    // Strings that are used in HMAC arguments include a length-indicator as well
    /////////////////////////////////////////////////////////////////////////////////////////////
    public static final byte[] CRYPTO_STRING_SUCCESS         = new byte[] {(byte)0x00, (byte)0x07, 'S','u','c','c','e','s','s'};

    /////////////////////////////////////////////////////////////////////////////////////////////
    // If there is no ServerSeed, this is the default
    /////////////////////////////////////////////////////////////////////////////////////////////
    public static final byte[] DEFAULT_SEED = new byte[]{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    
    /////////////////////////////////////////////////////////////////////////////////////////////
    // SKS key algorithm ids
    /////////////////////////////////////////////////////////////////////////////////////////////
    public static final byte RSA_KEY = (byte) 0x00;

    public static final byte ECC_KEY = (byte) 0x01;
    
    /////////////////////////////////////////////////////////////////////////////////////////////
    // Predefined PIN and PUK policy IDs for MAC operations
    /////////////////////////////////////////////////////////////////////////////////////////////
    public static final String CRYPTO_STRING_NOT_AVAILABLE   = "#N/A";

    public static final String CRYPTO_STRING_PIN_DEVICE      = "#Device PIN";
    
  }
