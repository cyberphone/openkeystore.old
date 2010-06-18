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

public interface KeyGen2Constants
  {

    String KEYGEN2_NS                        = "http://xmlns.webpki.org/keygen2/alpha/20100402#";

    String KEYGEN2_SCHEMA_FILE               = "keygen2.xsd";


    // XML attributes

    String ID_ATTR                           = "ID";

    String TYPE_ATTR                         = "Type";

    String NONCE_ATTR                        = "Nonce";

    String KEY_USAGE_ATTR                    = "KeyUsage";

    String EXPONENT_ATTR                     = "Exponent";

    String SERVER_SESSION_ID_ATTR            = "ServerSessionID";

    String CLIENT_SESSION_ID_ATTR            = "ClientSessionID";

    String SUBMIT_URL_ATTR                   = "SubmitURL";

    String ERROR_URL_ATTR                    = "ErrorURL";

    String SUCCESS_URL_ATTR                  = "SuccessURL";

    String SERVER_TIME_ATTR                  = "ServerTime";

    String CLIENT_TIME_ATTR                  = "ClientTime";

    String SESSION_KEY_LIMIT_ATTR            = "SessionKeyLimit";

    String SESSION_KEY_ALGORITHM_ATTR        = "SessionKeyAlgorithm";

    String SESSION_LIFE_TIME_ATTR            = "SessionLifeTime";

    String UPDATABLE_ATTR                    = "Updatable";

    String EXPORTABLE_ATTR                   = "Exportable";

    String NAMED_CURVE_ATTR                  = "NamedCurve";

    String SERVER_SEED_ATTR                  = "ServerSeed";
    
    String LANGUAGES_ATTR                    = "Languages";

    String EXPIRES_ATTR                      = "Expires";

    String SERVER_CERT_FP_ATTR               = "ServerCertificateFingerprint";

    String CERTIFICATE_FINGERPRINT_ATTR      = "CertificateFingerprint";

    String MIME_TYPE_ATTR                    = "MimeType";

    String MAC_ATTR                          = "MAC";

    String CLOSE_SESSION_MAC_ATTR            = "CloseSessionMAC";

    String DEFERRED_CERTIFICATION_ATTR       = "DeferredCertification";

    String ENDORSED_ALGORITHMS_ATTR          = "EndorsedAlgorithms";

    String KEY_ATTESTATION_ALGORITHM_ATTR    = "KeyAttestationAlgorithm";

    String KEY_ATTESTATION_ATTR              = "KeyAttestation";

    String SESSION_ATTESTATION_ATTR          = "SessionAttestation";

    String CLOSE_SESSION_ATTESTATION_ATTR    = "CloseSessionAttestation";

    String KEY_SIZE_ATTR                     = "KeySize";

    String PRIVATE_KEY_BACKUP_ATTR           = "PrivateKeyBackup";

    String MAX_LENGTH_ATTR                   = "MaxLength";

    String MIN_LENGTH_ATTR                   = "MinLength";

    String RETRY_LIMIT_ATTR                  = "RetryLimit";

    String GROUPING_ATTR                     = "Grouping";

    String FORMAT_ATTR                       = "Format";

    String ENABLE_PIN_CACHING_ATTR           = "EnablePINCaching";

    String INPUT_METHOD_ATTR                 = "InputMethod";

    String USER_MODIFIABLE_ATTR              = "UserModifiable";

    String PATTERN_RESTRICTIONS_ATTR         = "PatternRestrictions";

    String SUBJECT_ATTR                      = "Subject";

    String FRIENDLY_NAME_ATTR                = "FriendlyName";

    String SERIAL_ATTR                       = "Serial";

    String EMAIL_ATTR                        = "Email";

    String POLICY_ATTR                       = "Policy";

    String ISSUED_BEFORE_ATTR                = "IssuedBefore";

    String ISSUED_AFTER_ATTR                 = "IssuedAfter";

    String EXCLUDED_POLICIES_ATTR            = "ExcludedPolicies";

    String NAME_ATTR                         = "Name";

    String VALUE_ATTR                        = "Value";

    String WRITABLE_ATTR                     = "Writable";


    // XML elements

    String SERVER_EPHEMERAL_KEY_ELEM         = "ServerEphemeralKey";

    String DEVICE_CERTIFICATE_ELEM           = "DeviceCertificate";

    String CLIENT_EPHEMERAL_KEY_ELEM         = "ClientEphemeralKey";

    String GENERATED_PUBLIC_KEY_ELEM         = "GeneratedPublicKey";

    String CERTIFIED_PUBLIC_KEY_ELEM         = "CertifiedPublicKey";

    String SYMMETRIC_KEY_ELEM                = "SymmetricKey";

    String PRIVATE_KEY_ELEM                  = "PrivateKey";

    String KEY_PAIR_ELEM                     = "KeyPair";       

    String PIN_POLICY_ELEM                   = "PINPolicy";       

    String PUK_POLICY_ELEM                   = "PUKPolicy";       

    String PRESET_PIN_ELEM                   = "PresetPIN";
       
    String DEVICE_PIN_ELEM                   = "DevicePIN";

    String EXTENSION_ELEM                    = "Extension";

    String ENCRYPTED_EXTENSION_ELEM          = "EncryptedExtension";

    String LOGOTYPE_ELEM                     = "Logotype";

    String ISSUER_LOGOTYPE_ELEM              = "IssuerLogotype";       

    String PROPERTY_ELEM                     = "Property";       

    String PROPERTY_BAG_ELEM                 = "PropertyBag";       

    String RSA_ELEM                          = "RSA";

    String EC_ELEM                           = "EC";
    
    String UPDATE_KEY_ELEM                   = "UpdateKey";

    String CLONE_KEY_PROTECTION_ELEM         = "CloneKeyProtection";
    
    String DELETE_KEY_ELEM                   = "DeleteKey";

  }
