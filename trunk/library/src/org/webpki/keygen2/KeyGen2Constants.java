package org.webpki.keygen2;


public interface KeyGen2Constants
  {

    String KEYGEN2_NS                  = "http://xmlns.webpki.org/keygen2/beta/20100402#";

    String KEYGEN2_SCHEMA_FILE         = "keygen2.xsd";


    // Various global XML attributes

    String ID_ATTR                           = "ID";

    String TYPE_ATTR                         = "Type";

    String NONCE_ATTR                        = "Nonce";

    String KEY_USAGE_ATTR                    = "KeyUsage";

    String FIXED_EXPONENT_ATTR               = "FixedExponent";

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

    String LANGUAGES_ATTR                    = "Languages";

    String EXPIRES_ATTR                      = "Expires";

    String SERVER_CERT_FP_ATTR               = "ServerCertificateFingerprint";

    String CERTIFICATE_FINGERPRINT_ATTR      = "CertificateFingerprint";

    String MIME_TYPE_ATTR                    = "MimeType";

    String MAC_ATTR                          = "MAC";

    String DEFERRED_CERTIFICATION_ATTR       = "DeferredCertification";

    String ENDORSED_ALGORITHMS_ATTR          = "EndorsedAlgorithms";

    String KEY_ATTESTATION_ALGORITHM_ATTR    = "KeyAttestationAlgorithm";

    String KEY_ATTESTATION_ATTR              = "KeyAttestation";

    String SESSION_ATTESTATION_ATTR          = "SessionAttestation";

    String KEY_SIZE_ATTR                     = "KeySize";

    String MAX_LENGTH_ATTR                   = "MaxLength";

    String MIN_LENGTH_ATTR                   = "MinLength";

    String RETRY_LIMIT_ATTR                  = "RetryLimit";

    String GROUPING_ATTR                     = "Grouping";

    String FORMAT_ATTR                       = "Format";

    String CACHING_SUPPORT_ATTR              = "CachingSupport";

    String INPUT_METHOD_ATTR                 = "InputMethod";

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

    String SERVER_EPHEMERAL_KEY_ELEM         = "ServerEphemeralKey";

    String DEVICE_CERTIFICATE_ELEM           = "DeviceCertificate";

    String CLIENT_EPHEMERAL_KEY_ELEM         = "ClientEphemeralKey";

    String GENERATED_PUBLIC_KEY_ELEM         = "GeneratedPublicKey";

    String CERTIFIED_PUBLIC_KEY_ELEM         = "CertifiedPublicKey";

    String PRESET_VALUES_ELEM                = "PresetValues";

    String SYMMETRIC_KEY_ELEM                = "SymmetricKey";

    String PRIVATE_KEY_ELEM                  = "PrivateKey";

    String KEY_PAIR_ELEM                     = "KeyPair";       

    String MANAGE_OBJECT_ELEM                = "ManageObject";       

    String PIN_POLICY_ELEM                   = "PINPolicy";       

    String PUK_POLICY_ELEM                   = "PUKPolicy";       

    String PRESET_PIN_ELEM                   = "PresetPIN";
       
    String DEVICE_SYNCHRONIZED_PIN_ELEM      = "DeviceSynchronizedPIN";

       
    // Sub elements

    String EXTENSION_ELEM                    = "Extension";

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

    String EC_ELEM                           = "EC";

    String URL_ELEM                          = "URL";

    String DNS_LOOKUP_ELEM                   = "DNSLookup";


  }
