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
    String WEBAUTH_NS          = "http://xmlns.webpki.org/webauth/beta/20131016#";
    
    int MAX_ID_LENGTH          = 32;


    // JSON properties

    String ABORT_URL_JSON                  = "AbortURL";

    String AUTHENTICATION_REQUEST_JSON     = "AuthenticationRequest";

    String AUTHENTICATION_RESPONSE_JSON    = "AuthenticationResponse";

    String CERTIFICATE_FILTERS_JSON        = "CertificateFilters";

    String CLIENT_FEATURES_JSON            = "ClientFeatures";

    String CLIENT_TIME_JSON                = "ClientTime";

    String EXPIRES_JSON                    = "Expires";

    String EXTENDED_CERT_PATH_JSON         = "ExtendedCertPath";

    String ID_JSON                         = "ID";

    String LANGUAGES_JSON                  = "Languages";

    String REQUESTED_CLIENT_FEATURES_JSON  = "RequestedClientFeatures";

    String REQUEST_URL_JSON                = "RequestURL";

    String SERVER_CERT_FP_JSON             = "ServerCertificateFingerprint";

    String SERVER_TIME_JSON                = "ServerTime";

    String SIGNATURE_ALGORITHMS_JSON       = "SignatureAlgorithms";
    
    String SUBMIT_URL_JSON                 = "SubmitURL";

    String TYPE_JSON                       = "Type";

    String VALUES_JSON                     = "Values";
  }
