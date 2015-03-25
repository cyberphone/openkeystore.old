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
    String DATE_TIME_JSON             = "dateTime";
    String REFERENCE_ID_JSON          = "referenceId";
    String CERTIFICATE_FILTERS_JSON   = "certificateFilters";
    String VALUE_JSON                 = "value";
    String DOMAIN_NAME_JSON           = "domainName";
    String ALGORITHM_JSON             = "algorithm";
    String SIGNATURE_ALGORITHMS_JSON  = "signatureAlgorithms";
    String HASH_ALGORITHM_JSON        = "hashAlgorithm";
    String OBJECT_TO_SIGN_JSON        = "objectToSign";
    String MIME_TYPE_JSON             = "mimeType";
    String DOCUMENT_JSON              = "document";
    String DOCUMENT_DATA_JSON         = "documentData";
    String DOCUMENT_HASH_JSON         = "documentHash";
    String REQUEST_DATA_JSON          = "requestData";
    String ORIGIN_JSON                = "origin";
    
    String SIGNATURE_TYPE_JSON        = "signatureType";
    // Argument to the above
    String SIGNATURE_TYPE_DETACHED    = "detached";
    String SIGNATURE_TYPE_EMBEDDING   = "embedding";
    
    String SIGNATURE_FORMAT_JSON      = "signatureFormat";
    // Argument to the above
    String SIGNATURE_FORMAT_JCS       = "JCS";
    String SIGNATURE_FORMAT_XML_DSIG  = "XMLDSig";
    String SIGNATURE_FORMAT_JWS_COMP  = "JWS/C";

    String WCPP_DEMO_CONTEXT_URI      = "http://xmlns.webpki.org/wcpp-signature-demo";
    String ECDH_ALGORITHM_URI         = "http://www.w3.org/2009/xmlenc11#ECDH-ES";
    String CONCAT_ALGORITHM_URI       = "http://www.w3.org/2009/xmlenc11#ConcatKDF";
  }
