package org.webpki.keygen2;


public interface KeyGen2Constants
  {

    String KEYGEN2_NS                  = "http://xmlns.webpki.org/keygen2/beta/20090301#";

    String XML_ENC_NS                  = "http://www.w3.org/2001/04/xmlenc#";

    String KEYGEN2_SCHEMA_FILE         = "keygen2.xsd";

    String REDUCED_XML_ENC_SCHEMA_FILE = "reduced-xenc-schema.xsd";

    String XML_ENC_NS_PREFIX           = "xenc";


    // Various global XML attributes

    String ID_ATTR                           = "ID";

    String TYPE_ATTR                         = "Type";

    String NONCE_ATTR                        = "Nonce";

    String KEY_USAGE_ATTR                    = "KeyUsage";

    String FIXED_EXPONENT_ATTR               = "FixedExponent";

    String SERVER_SESSION_ID_ATTR            = "ServerSessionID";

    String CLIENT_SESSION_ID_ATTR            = "ClientSessionID";

    String SUBMIT_URL_ATTR                   = "SubmitURL";

    String REQUEST_URL_ATTR                  = "RequestURL";

    String ERROR_URL_ATTR                    = "ErrorURL";

    String SUCCESS_URL_ATTR                  = "SuccessURL";

    String SERVER_TIME_ATTR                  = "ServerTime";

    String EXPORTABLE_ATTR                   = "Exportable";

    String NAMED_CURVE_ATTR                  = "NamedCurve";

    String CLIENT_TIME_ATTR                  = "ClientTime";

    String LANGUAGES_ATTR                    = "Languages";

    String EXPIRES_ATTR                      = "Expires";

    String SERVER_CERT_FP_ATTR               = "ServerCertificateFingerprint";

    String CERTIFICATE_SHA1_ATTR             = "CertificateSHA1";

    String VALUE_REFERENCE_ID_ATTR           = "ValueReferenceID";

    String MIME_TYPE_ATTR                    = "MimeType";

    String MAC_ATTR                          = "MAC";

    String DEFERRED_CERTIFICATION_ATTR       = "DeferredCertification";

    String ENDORSED_ALGORITHMS_ATTR          = "EndorsedAlgorithms";

    String KEY_ATTESTATION_ALGORITHM_ATTR    = "KeyAttestationAlgorithm";

    String CONDITIONAL_ATTR                  = "Conditional";

    String KEY_ATTESTATION_ATTR              = "KeyAttestation";

    String MAC_ALGORITHM_ATTR                = "MACAlgorithm";

    String KEY_SIZE_ATTR                     = "KeySize";

    String MAX_LENGTH_ATTR                   = "MaxLength";

    String MIN_LENGTH_ATTR                   = "MinLength";

    String RETRY_LIMIT_ATTR                  = "RetryLimit";

    String GROUPING_ATTR                     = "Grouping";

    String FORMAT_ATTR                       = "Format";

    String CACHING_SUPPORT_ATTR              = "CachingSupport";

    String INPUT_METHOD_ATTR                 = "InputMethod";

    String HIDDEN_ATTR                       = "Hidden";

    String USER_MODIFIABLE_ATTR              = "UserModifiable";

    String PATTERN_RESTRICTIONS_ATTR         = "PatternRestrictions";

    String FORCE_NEW_PIN_ATTR                = "ForceNewPIN";

    String NOTIFY_DAYS_BEFORE_EXPIRY_ATTR    = "NotifyDaysBeforeExpiry";

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

    // Top elements

    String GENERATED_PUBLIC_KEY_ELEM         = "GeneratedPublicKey";

    String PRESET_VALUES_ELEM                = "PresetValues";

    String PIGGYBACKED_SYMMETRIC_KEY_ELEM    = "PiggybackedSymmetricKey";

    String ENCRYPTED_PRIVATE_KEY_ELEM        = "EncryptedPrivateKey";

    String KEY_PAIR_ELEM                     = "KeyPair";       

    String MANAGE_OBJECT_ELEM                = "ManageObject";       

    String CREATE_OBJECT_ELEM                = "CreateObject";       

    String PIN_POLICY_ELEM                   = "PINPolicy";       

    String PUK_POLICY_ELEM                   = "PUKPolicy";       

    String PRESET_PIN_ELEM                   = "PresetPIN";
       
    String DEVICE_SYNCHRONIZED_PIN_ELEM      = "DeviceSynchronizedPIN";

    String CERTIFIED_PUBLIC_KEY_ELEM         = "CertifiedPublicKey";
       
    // Sub elements

    String ISSUER_KEY_EXCHANGE_KEY_ELEM      = "IssuerKeyExchangeKey";

    String PRIVATE_KEY_ARCHIVAL_KEY_ELEM     = "PrivateKeyArchivalKey";

    String EXTENSION_ELEM                    = "Extension";

    String DEVICE_ENCRYPTION_KEY_ELEM        = "DeviceEncryptionKey";

    String DEVICE_KEY_ATTESTATION_KEY_ELEM   = "DeviceKeyAttestationKey";

    String LOGO_TYPE_ELEM                    = "Logotype";

    String CLONE_KEY_ELEM                    = "CloneKey";

    String REPLACE_KEY_ELEM                  = "ReplaceKey";

    String DELETE_KEY_ELEM                   = "DeleteKey";

    String DELETE_KEYS_BY_CONTENT_ELEM       = "DeleteKeysByContent";

    String UPDATE_PIN_POLICY_ELEM            = "UpdatePINPolicy";

    String UPDATE_PUK_POLICY_ELEM            = "UpdatePUKPolicy";

    String UPDATE_PRESET_PIN_ELEM            = "UpdatePresetPIN";

    String ISSUER_LOGOTYPE_ELEM              = "IssuerLogotype";       

    String PROPERTY_ELEM                     = "Property";       

    String PROPERTY_BAG_ELEM                 = "PropertyBag";       

    String RENEWAL_SERVICE_ELEM              = "RenewalService";

    String ENDORSEMENT_KEY_ELEM              = "EndorsementKey";

    String RSA_ELEM                          = "RSA";

    String ECC_ELEM                          = "ECC";

    String URL_ELEM                          = "URL";

    String DNS_LOOKUP_ELEM                   = "DNSLookup";

    // XML Encryption

    String ENCRYPTED_KEY_ELEM                = "EncryptedKey";

    String ENCRYPTED_DATA_ELEM               = "EncryptedData";

    String ENCRYPTION_METHOD_ELEM            = "EncryptionMethod";

    String CARRIED_KEY_NAME_ELEM             = "CarriedKeyName";

    String CIPHER_DATA_ELEM                  = "CipherData";

    String CIPHER_VALUE_ELEM                 = "CipherValue";

  }
