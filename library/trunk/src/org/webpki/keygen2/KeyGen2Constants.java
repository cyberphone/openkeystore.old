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
package org.webpki.keygen2;

public interface KeyGen2Constants
  {
    String KEYGEN2_NS                                = "http://xmlns.webpki.org/keygen2/beta/20131201";

    // JSON properties

    String ABORT_URL_JSON                            = "AbortURL";

    String ACTION_JSON                               = "Action";

    String APP_USAGE_JSON                            = "AppUsage";

    String AUTHORIZATION_JSON                        = "Authorization";

    String BIOMETRIC_PROTECTION_JSON                 = "BiometricProtection";

    String CHALLENGE_JSON                            = "Challenge";

    String CLIENT_ATTRIBUTES_JSON                    = "ClientAttributes";

    String CLIENT_EPHEMERAL_KEY_JSON                 = "ClientEphemeralKey";

    String CLIENT_SESSION_ID_JSON                    = "ClientSessionID";

    String CLIENT_TIME_JSON                          = "ClientTime";

    String CLONE_KEY_PROTECTION_JSON                 = "CloneKeyProtection";
    
    String CLOSE_ATTESTATION_JSON                    = "CloseAttestation";

    String CONFIGURATION_JSON                        = "Configuration";

    String CREDENTIAL_DISCOVERY_REQUEST_JSON         = "CredentialDiscoveryRequest";

    String CREDENTIAL_DISCOVERY_RESPONSE_JSON        = "CredentialDiscoveryResponse";
    
    String EXTENSION_DATA_JSON                       = "ExtensionData";
    
    String DEFERRED_ISSUANCE_JSON                    = "DeferredIssuance";

    String DELETE_KEYS_JSON                          = "DeleteKeys";
    
    String DELETE_PROTECTION_JSON                    = "DeleteProtection";

    String DEVICE_CERTIFICATE_JSON                   = "DeviceCertificate";

    String DEVICE_PIN_PROTECTION_JSON                = "DevicePINProtection";

    String ENDORSED_ALGORITHMS_JSON                  = "EndorsedAlgorithms";

    String ENABLE_PIN_CACHING_JSON                   = "EnablePINCaching";

    String ENCRYPTED_EXTENSIONS_JSON                 = "EncryptedExtensions";

    String ENCRYPTED_KEY_JSON                        = "EncryptedKey";

    String ENCRYPTED_PRESET_PIN_JSON                 = "EncryptedPresetPIN";
    
    String ENCRYPTED_PUK_JSON                        = "EncryptedPUK";

    String EXPORT_PROTECTION_JSON                    = "ExportProtection";

    String EXTENSIONS_JSON                           = "Extensions";

    String FORMAT_JSON                               = "Format";

    String FRIENDLY_NAME_JSON                        = "FriendlyName";

    String GROUPING_JSON                             = "Grouping";

    String HEIGHT_JSON                               = "Height";

    String ID_JSON                                   = "ID";

    String IMAGE_PREFERENCES_JSON                    = "ImagePreferences";
    
    String IMPORT_PRIVATE_KEY_JSON                   = "ImportPrivateKey";

    String IMPORT_SYMMETRIC_KEY_JSON                 = "ImportSymmetricKey";

    String INPUT_METHOD_JSON                         = "InputMethod";

    String ISSUED_AFTER_JSON                         = "IssuedAfter";

    String ISSUED_BEFORE_JSON                        = "IssuedBefore";

    String ISSUED_CREDENTIALS_JSON                   = "IssuedCredentials";

    String KEY_ALGORITHM_JSON                        = "KeyAlgorithm";

    String KEY_ATTESTATION_JSON                      = "KeyAttestation";

    String KEY_CREATION_REQUEST_JSON                 = "KeyCreationRequest";
    
    String KEY_CREATION_RESPONSE_JSON                = "KeyCreationResponse";

    String KEY_ENTRY_ALGORITHM_JSON                  = "KeyEntryAlgorithm";       

    String KEY_ENTRY_SPECIFIERS_JSON                 = "KeyEntrySpecifiers";       

    String KEY_MANAGEMENT_KEY_JSON                   = "KeyManagementKey";

    String KEY_PARAMETERS_JSON                       = "KeyParameters";

    String LOCKED_JSON                               = "Locked";

    String LOGOTYPES_JSON                            = "Logotypes";

    String LOOKUP_RESULTS_JSON                       = "LookupResults";

    String LOOKUP_SPECIFIERS_JSON                    = "LookupSpecifiers";

    String MAC_JSON                                  = "MAC";

    String MATCHING_CREDENTIALS_JSON                 = "MatchingCredentials";

    String MAX_LENGTH_JSON                           = "MaxLength";

    String MIME_TYPE_JSON                            = "MimeType";

    String MIN_LENGTH_JSON                           = "MinLength";

    String NAME_JSON                                 = "Name";

    String NONCE_JSON                                = "Nonce";

    String PATTERN_RESTRICTIONS_JSON                 = "PatternRestrictions";

    String PIN_POLICY_SPECIFIERS_JSON                = "PINPolicySpecifiers";       

    String PLATFORM_NEGOTIATION_REQUEST_JSON         = "PlatformNegotiationRequest";
    
    String PLATFORM_NEGOTIATION_RESPONSE_JSON        = "PlatformNegotiationResponse";
    
    String PREFERREDD_LANGUAGES_JSON                 = "PreferredLanguages";

    String PRIVACY_ENABLED_JSON                      = "PrivacyEnabled";

    String PROPERTIES_JSON                           = "Properties";       

    String PROPERTY_BAGS_JSON                        = "PropertyBags";       

    String PROVISIONING_INITIALIZATION_REQUEST_JSON  = "ProvisioningInitializationRequest";
    
    String PROVISIONING_INITIALIZATION_RESPONSE_JSON = "ProvisioningInitializationResponse";

    String PROVISIONING_FINALIZATION_REQUEST_JSON    = "ProvisioningFinalizationRequest";
    
    String PROVISIONING_FINALIZATION_RESPONSE_JSON   = "ProvisioningFinalizationResponse";

    String GENERATED_KEYS_JSON                       = "GeneratedKeys";

    String PUK_POLICY_SPECIFIERS_JSON                = "PUKPolicySpecifiers";       

    String REQUESTED_CLIENT_ATTRIBUTES_JSON          = "RequestedClientAttributes";

    String RETRY_LIMIT_JSON                          = "RetryLimit";

    String SEARCH_FILTER_JSON                        = "SearchFilter";

    String SERVER_EPHEMERAL_KEY_JSON                 = "ServerEphemeralKey";

    String SERVER_CERT_FP_JSON                       = "ServerCertificateFingerPrint";

    String SERVER_SEED_JSON                          = "ServerSeed";
    
    String SERVER_SESSION_ID_JSON                    = "ServerSessionID";

    String SERVER_TIME_JSON                          = "ServerTime";

    String SESSION_ATTESTATION_JSON                  = "SessionAttestation";

    String SESSION_KEY_ALGORITHM_JSON                = "SessionKeyAlgorithm";

    String SESSION_KEY_LIMIT_JSON                    = "SessionKeyLimit";

    String SESSION_LIFE_TIME_JSON                    = "SessionLifeTime";

    String SUBMIT_URL_JSON                           = "SubmitURL";

    String TRUST_ANCHOR_JSON                         = "TrustAnchor";

    String TYPE_JSON                                 = "Type";

    String UNLOCK_KEYS_JSON                          = "UnlockKeys";

    String UPDATABLE_KEY_MANAGEMENT_KEYS_JSON        = "UpdatableKeyManagementKeys";

    String UPDATE_KEY_JSON                           = "UpdateKey";

    String USER_MODIFIABLE_JSON                      = "UserModifiable";

    String VALUE_JSON                                = "Value";

    String VALUES_JSON                               = "Values";

    String VIRTUAL_MACHINE_JSON                      = "VirtualMachine";

    String WIDTH_JSON                                = "Width";

    String WRITABLE_JSON                             = "Writable";
  }
