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
package org.webpki.webauth;

import org.webpki.crypto.KeyContainerTypes;


public interface WebAuthConstants
  {
    String WEBAUTH_NS          = "http://xmlns.webpki.org/webauth/beta/20130604#";
    
    int MAX_ID_LENGTH          = 32;


    // Package only definitions

    String CERTIFICATE_FILTER_ELEM = "CertificateFilter";

    KeyContainerTypes[] KEYCONTAINER2NAME  = new KeyContainerTypes[] {KeyContainerTypes.FILE,
                                                                      KeyContainerTypes.TPM,
                                                                      KeyContainerTypes.SIM,
                                                                      KeyContainerTypes.EXTERNAL};

    String[] NAME2KEYCONTAINER             = new String[] {"File", 
                                                           "TPM", 
                                                           "SIM",
                                                           "External"};

    // JSON properties

    String ID_ATTR                         = "ID";

    String SUBMIT_URL_ATTR                 = "SubmitURL";

    String REQUEST_URL_ATTR                = "RequestURL";

    String ABORT_URL_ATTR                  = "AbortURL";

    String SERVER_TIME_ATTR                = "ServerTime";

    String CLIENT_TIME_ATTR                = "ClientTime";

    String LANGUAGES_ATTR                  = "Languages";

    String EXPIRES_ATTR                    = "Expires";

    String SERVER_CERT_FP_ATTR             = "ServerCertificateFingerprint";

    String REQUESTED_CLIENT_FEATURES_ATTR  = "RequestedClientFeatures";

    String CLIENT_FEATURES_ATTR            = "ClientFeatures";

    String SIGNATURE_ALG_ATTR              = "SignatureAlgorithm";
    
    String TYPE_ATTR                       = "Type";

    String VALUES_ATTR                     = "Values";

    String EXTENDED_CERT_PATH_ATTR         = "ExtendedCertPath";
  }
