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
package org.webpki.webapps.wcpppaymentdemo;

public interface BaseProperties
  {
    String PAYMENT_REQUEST_JSON       = "paymentRequest";
    String AMOUNT_JSON                = "amount";
    String ERROR_JSON                 = "error";
    String CURRENCY_JSON              = "currency";
    String DATE_TIME_JSON             = "dateTime";
    String TRANSACTION_ID_JSON        = "transactionId";
    String CLIENT_IP_ADDRESS_JSON     = "clientIpAddress";
    String REFERENCE_ID_JSON          = "referenceId";
    String COMMON_NAME_JSON           = "commonName";
    String CARD_TYPES_JSON            = "cardTypes";
    String AUTH_DATA_JSON             = "authData";          // Encrypted authorization data
    String AUTH_URL_JSON              = "authUrl";           // URL to payment provider
    String PAN_JSON                   = "pan";               // Card number
    String CARD_TYPE_JSON             = "cardType";          // Card type
    String REFERENCE_PAN_JSON         = "referencePan";      // Truncated card number given to merchant
    String PAYMENT_TOKEN_JSON         = "paymentToken";      // EMV tokenization result
    String REQUEST_HASH_JSON          = "requestHash";
    String VALUE_JSON                 = "value";
    String DOMAIN_NAME_JSON           = "domainName";
    String ENCRYPTED_DATA_JSON        = "encryptedData";
    String ENCRYPTED_KEY_JSON         = "encryptedKey";
    String PAYMENT_PROVIDER_KEY_JSON  = "paymentProviderKey";
    String EPHEMERAL_CLIENT_KEY_JSON  = "ephemeralClientKey";
    String ALGORITHM_JSON             = "algorithm";
    String HASH_ALGORITHM_JSON        = "hashAlgorithm";
    String ALGORITHM_ID_JSON          = "algorithmId";
    String PARTY_U_INFO_JSON          = "partyUIinfo";
    String PARTY_V_INFO_JSON          = "partyVInfo";
    String KEY_DERIVATION_METHOD_JSON = "keyDerivationMethod";
    String IV_JSON                    = "iv";
    String CIPHER_TEXT_JSON           = "cipherText";
    
    String WCPP_DEMO_CONTEXT_URI      = "http://xmlns.webpki.org/wcpp-payment-demo";
    String ECDH_ALGORITHM_URI         = "http://www.w3.org/2009/xmlenc11#ECDH-ES";
    String CONCAT_ALGORITHM_URI       = "http://www.w3.org/2009/xmlenc11#ConcatKDF";
  }
