package org.webpki.wasp;

import org.webpki.crypto.KeyContainerTypes;


public interface WASPConstants
  {

    String WASP_NS             = "http://xmlns.webpki.org/wasp/1.0/core#";

    String WASP_SCHEMA_FILE    = "wasp-core.xsd";

    String DOC_SIGN_CN_ALG     = "http://xmlns.webpki.org/wasp/1.0/core#cn";

    String[] TEXT_TYPES        = new String[]{"text/plain",
                                              "text/html", 
                                              "text/xml",
                                              "application/xhtml+xml",
                                              "application/xml",
                                              "text/css"};

    boolean[] MARKUP_TYPES     = new boolean[]{false,
                                               true,
                                               true,
                                               true,
                                               true,
                                               false};


    String WEBAUTH_SCHEMA_FILE = "webauth.xsd";

    String WEBAUTH_NS          = "http://xmlns.webpki.org/webauth/1.0#";


    // Package only definitions

    String CERTIFICATE_FILTER_ELEM = "CertificateFilter";

    String IDP_ASSERTIONS_ELEM     = "IdentityProviderAssertions";

    KeyContainerTypes[] KEYCONTAINER2NAME  = new KeyContainerTypes[] {KeyContainerTypes.FILE,
                                                                      KeyContainerTypes.TPM,
                                                                      KeyContainerTypes.SIM,
                                                                      KeyContainerTypes.EXTERNAL};

    String[] NAME2KEYCONTAINER             = new String[] {"File", 
                                                           "TPM", 
                                                           "SIM",
                                                           "External"};

    // Various global XML attributes

    String ID_ATTR                         = "ID";

    String SUBMIT_URL_ATTR                 = "SubmitURL";

    String REQUEST_URL_ATTR                = "RequestURL";

    String CANCEL_URL_ATTR                 = "CancelURL";

    String SERVER_TIME_ATTR                = "ServerTime";

    String CLIENT_TIME_ATTR                = "ClientTime";

    String LANGUAGES_ATTR                  = "Languages";

    String EXPIRES_ATTR                    = "Expires";

    String SIGNATURE_GUI_POLICY_ATTR       = "SignatureGUIPolicy";

    String COPY_DATA_ATTR                  = "CopyData";

    String SERVER_CERT_SHA1_ATTR           = "ServerCertificateSHA1";

    String MIME_TYPE_ATTR                  = "MIMEType";

    String CONTENT_ID_ATTR                 = "ContentID";

    String DIGEST_ALG_ATTR                 = "DigestAlgorithm";

    String SIGNATURE_ALG_ATTR              = "SignatureAlgorithm";

    String CN_ALG_ATTR                     = "CanonicalizationAlgorithm";

    String DOC_CN_ALG_ATTR                 = "DocumentCanonicalizationAlgorithm";
 
    String EXTENDED_CERT_PATH_ATTR         = "ExtendedCertPath";

    String SIGNED_KEY_INFO_ATTR            = "SignedKeyInfo";


    // Sub elements

    String MAIN_DOCUMENT_SUB_ELEM          = "MainDocument";

    String EMBEDDED_OBJECT_SUB_ELEM        = "EmbeddedObject";

    String BINARY_SUB_ELEM                 = "Binary";

    String TEXT_SUB_ELEM                   = "Text";

  }
