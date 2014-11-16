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
package org.webpki.webapps.wcppsignaturedemo;

public interface BaseProperties
  {
    String PAYMENT_REQUEST_JSON       = "PaymentRequest";
    String AMOUNT_JSON                = "Amount";
    String ERROR_JSON                 = "Error";
    String CURRENCY_JSON              = "Currency";
    String DATE_TIME_JSON             = "DateTime";
    String TRANSACTION_ID_JSON        = "TransactionID";
    String CLIENT_IP_ADDRESS_JSON     = "ClientIPAddress";
    String REFERENCE_ID_JSON          = "ReferenceID";
    String COMMON_NAME_JSON           = "CommonName";
    String CARD_TYPES_JSON            = "CardTypes";
    String AUTH_DATA_JSON             = "AuthData";          // Encrypted authorization data
    String AUTH_URL_JSON              = "AuthURL";           // URL to payment provider
    String PAN_JSON                   = "PAN";               // Card number
    String CARD_TYPE_JSON             = "CardType";          // Card type
    String REFERENCE_PAN_JSON         = "ReferencePAN";      // Truncated card number given to merchant
    String PAYMENT_TOKEN_JSON         = "PaymentToken";      // EMV tokenization result
    String REQUEST_HASH_JSON          = "RequestHash";
    String VALUE_JSON                 = "Value";
    String DOMAIN_NAME_JSON           = "DomainName";
    String ENCRYPTED_DATA_JSON        = "EncryptedData";
    String ENCRYPTED_KEY_JSON         = "EncryptedKey";
    String PAYMENT_PROVIDER_KEY_JSON  = "PaymentProviderKey";
    String EPHEMERAL_CLIENT_KEY_JSON  = "EphemeralClientKey";
    String ALGORITHM_JSON             = "Algorithm";
    String HASH_ALGORITHM_JSON        = "HashAlgorithm";
    String ALGORITHM_ID_JSON          = "AlgorithmID";
    String PARTY_U_INFO_JSON          = "PartyUInfo";
    String PARTY_V_INFO_JSON          = "PartyVInfo";
    String KEY_DERIVATION_METHOD_JSON = "KeyDerivationMethod";
    String IV_JSON                    = "IV";
    String CIPHER_TEXT_JSON           = "CipherText";
    String OBJECT_TO_SIGN_JSON        = "ObjectToSign";
    String MIME_TYPE_JSON             = "MIMEType";
    String DOCUMENT_JSON              = "Document";
    String DOCUMENT_DATA_JSON         = "DocumentData";
    String DOCUMENT_HASH_JSON         = "DocumentHash";
    String REQUEST_DATA_JSON          = "RequestData";
    String ORIGIN_JSON                = "Origin";
    
    String SIGNATURE_TYPE_JSON        = "SignatureType";
    // Argument to the above
    String SIGNATURE_TYPE_DETACHED    = "Detached";
    String SIGNATURE_TYPE_EMBEDDED    = "Embedded";
    
    String SIGNATURE_FORMAT_JSON      = "SignatureFormat";
    // Argument to the above
    String SIGNATURE_FORMAT_JCS       = "JCS";
    String SIGNATURE_FORMAT_XML       = "XML";

    String WCPP_DEMO_CONTEXT_URI      = "http://xmlns.webpki.org/wcpp-signature-demo";
    String ECDH_ALGORITHM_URI         = "http://www.w3.org/2009/xmlenc11#ECDH-ES";
    String CONCAT_ALGORITHM_URI       = "http://www.w3.org/2009/xmlenc11#ConcatKDF";
  }
