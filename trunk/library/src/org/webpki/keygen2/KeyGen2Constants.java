/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
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
    String KEYGEN2_NS                                = "http://xmlns.webpki.org/keygen2/beta/20121203#";

    String KEYGEN2_SCHEMA_FILE                       = "keygen2.xsd";


    // XML attributes

    String ABORT_URL_ATTR                            = "AbortURL";

    String ACTION_ATTR                               = "Action";

    String ALGORITHMS_ATTR                           = "Algorithms";

    String APP_USAGE_ATTR                            = "AppUsage";

    String ATTESTATION_ATTR                          = "Attestation";

    String AUTHORIZATION_ATTR                        = "Authorization";

    String BIOMETRIC_PROTECTION_ATTR                 = "BiometricProtection";

    String CERTIFICATE_FINGERPRINT_ATTR              = "CertificateFingerprint";

    String CLIENT_SESSION_ID_ATTR                    = "ClientSessionID";

    String CLIENT_TIME_ATTR                          = "ClientTime";

    String DEFERRED_CERTIFICATION_ATTR               = "DeferredCertification";

    String DELETE_PROTECTION_ATTR                    = "DeleteProtection";

    String EMAIL_ATTR                                = "Email";

    String ENDORSED_ALGORITHMS_ATTR                  = "EndorsedAlgorithms";

    String ENABLE_PIN_CACHING_ATTR                   = "EnablePINCaching";

    String ERROR_URL_ATTR                            = "ErrorURL";

    String EXCLUDED_POLICIES_ATTR                    = "ExcludedPolicies";

    String EXPIRES_ATTR                              = "Expires";

    String EXPORT_PROTECTION_ATTR                    = "ExportProtection";

    String EXTENSIONS_ATTR                           = "Extensions";

    String CLIENT_ATTRIBUTES_ATTR                    = "ClientAttributes";

    String FORMAT_ATTR                               = "Format";

    String FRIENDLY_NAME_ATTR                        = "FriendlyName";

    String GROUPING_ATTR                             = "Grouping";

    String HEIGHT_ATTR                               = "Height";

    String ID_ATTR                                   = "ID";

    String ISSUER_ATTR                               = "Issuer";

    String INPUT_METHOD_ATTR                         = "InputMethod";

    String ISSUED_BEFORE_ATTR                        = "IssuedBefore";

    String ISSUED_AFTER_ATTR                         = "IssuedAfter";

    String KEY_ALGORITHM_ATTR                        = "KeyAlgorithm";

    String KEY_PARAMETERS_ATTR                       = "KeyParameters";

    String KEY_SIZE_ATTR                             = "KeySize";

    String KEY_SIZES_ATTR                            = "KeySizes";

    String LANGUAGES_ATTR                            = "Languages";

    String LOCKED_ATTR                               = "Locked";

    String MAC_ATTR                                  = "MAC";

    String MAX_LENGTH_ATTR                           = "MaxLength";

    String MIME_TYPE_ATTR                            = "MIMEType";

    String MIN_LENGTH_ATTR                           = "MinLength";

    String NAME_ATTR                                 = "Name";

    String NONCE_ATTR                                = "Nonce";

    String PATTERN_RESTRICTIONS_ATTR                 = "PatternRestrictions";

    String PRIVACY_ENABLED_ATTR                      = "PrivacyEnabled";

    String POLICY_ATTR                               = "Policy";

    String RETRY_LIMIT_ATTR                          = "RetryLimit";

    String SERIAL_ATTR                               = "Serial";

    String SERVER_CERT_FP_ATTR                       = "ServerCertificateFingerprint";

    String SERVER_SEED_ATTR                          = "ServerSeed";
    
    String SERVER_SESSION_ID_ATTR                    = "ServerSessionID";

    String SERVER_TIME_ATTR                          = "ServerTime";

    String SESSION_KEY_LIMIT_ATTR                    = "SessionKeyLimit";

    String SESSION_LIFE_TIME_ATTR                    = "SessionLifeTime";

    String SETTABLE_EXPONENT_ATTR                    = "SettableExponent";

    String SUBJECT_ATTR                              = "Subject";

    String SUBMIT_URL_ATTR                           = "SubmitURL";

    String SUCCESS_URL_ATTR                          = "SuccessURL";

    String TRUST_ANCHOR_ATTR                         = "TrustAnchor";

    String TYPE_ATTR                                 = "Type";

    String USER_MODIFIABLE_ATTR                      = "UserModifiable";

    String VALUE_ATTR                                = "Value";

    String WIDTH_ATTR                                = "Width";

    String WRITABLE_ATTR                             = "Writable";


    // XML elements
    
    String CERTIFICATE_PATH_ELEM                     = "CertificatePath";

    String CLIENT_ATTRIBUTE_ELEM                     = "ClientAttribute";

    String CLIENT_EPHEMERAL_KEY_ELEM                 = "ClientEphemeralKey";

    String CLONE_KEY_PROTECTION_ELEM                 = "CloneKeyProtection";
    
    String CREDENTIAL_DISCOVERY_REQUEST_ELEM         = "CredentialDiscoveryRequest";

    String CREDENTIAL_DISCOVERY_RESPONSE_ELEM        = "CredentialDiscoveryResponse";
    
    String DELETE_KEY_ELEM                           = "DeleteKey";
    
    String DEVICE_CERTIFICATE_PATH_ELEM              = "DeviceCertificatePath";

    String DEVICE_PIN_PROTECTION_ELEM                = "DevicePINProtection";

    String EXTENSION_ELEM                            = "Extension";

    String ENCRYPTED_EXTENSION_ELEM                  = "EncryptedExtension";

    String IMAGE_PREFERENCE_ELEM                     = "ImagePreference";

    String KEY_CREATION_REQUEST_ELEM                 = "KeyCreationRequest";
    
    String KEY_CREATION_RESPONSE_ELEM                = "KeyCreationResponse";

    String KEY_ENTRY_ELEM                            = "KeyEntry";       

    String KEY_MANAGEMENT_KEY_ELEM                   = "KeyManagementKey";

    String MATCHING_CREDENTIAL_ELEM                  = "MatchingCredential";

    String LOGOTYPE_ELEM                             = "Logotype";

    String LOOKUP_RESULT_ELEM                        = "LookupResult";

    String LOOKUP_SPECIFIER_ELEM                     = "LookupSpecifier";

    String PIN_POLICY_ELEM                           = "PINPolicy";       

    String PLATFORM_NEGOTIATION_REQUEST_ELEM         = "PlatformNegotiationRequest";
    
    String PLATFORM_NEGOTIATION_RESPONSE_ELEM        = "PlatformNegotiationResponse";
    
    String PRESET_PIN_ELEM                           = "PresetPIN";
    
    String PRIVATE_KEY_ELEM                          = "PrivateKey";

    String PROPERTY_BAG_ELEM                         = "PropertyBag";       

    String PROPERTY_ELEM                             = "Property";       

    String PROVISIONING_INITIALIZATION_REQUEST_ELEM  = "ProvisioningInitializationRequest";
    
    String PROVISIONING_INITIALIZATION_RESPONSE_ELEM = "ProvisioningInitializationResponse";

    String PROVISIONING_FINALIZATION_REQUEST_ELEM    = "ProvisioningFinalizationRequest";
    
    String PROVISIONING_FINALIZATION_RESPONSE_ELEM   = "ProvisioningFinalizationResponse";

    String PUBLIC_KEY_ELEM                           = "PublicKey";

    String PUK_POLICY_ELEM                           = "PUKPolicy";       

    String SERVER_EPHEMERAL_KEY_ELEM                 = "ServerEphemeralKey";

    String SYMMETRIC_KEY_ELEM                        = "SymmetricKey";

    String SEARCH_FILTER_ELEM                        = "SearchFilter";

    String UNLOCK_KEY_ELEM                           = "UnlockKey";

    String UPDATE_KEY_ELEM                           = "UpdateKey";
  }
