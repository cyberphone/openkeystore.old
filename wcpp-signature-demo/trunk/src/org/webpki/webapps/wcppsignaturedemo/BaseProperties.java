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
    String DATE_TIME_JSON             = "DateTime";
    String REFERENCE_ID_JSON          = "ReferenceID";
    String CERTIFICATE_FILTERS_JSON   = "CertificateFilters";
    String COMMON_NAME_JSON           = "CommonName";
    String VALUE_JSON                 = "Value";
    String DOMAIN_NAME_JSON           = "DomainName";
    String ALGORITHM_JSON             = "Algorithm";
    String SIGNATURE_ALGORITHMS_JSON  = "SignatureAlgorithms";
    String HASH_ALGORITHM_JSON        = "HashAlgorithm";
    String OBJECT_TO_SIGN_JSON        = "ObjectToSign";
    String MIME_TYPE_JSON             = "MIMEType";
    String DOCUMENT_JSON              = "Document";
    String DOCUMENT_DATA_JSON         = "DocumentData";
    String DOCUMENT_HASH_JSON         = "DocumentHash";
    String REQUEST_DATA_JSON          = "RequestData";
    String ORIGIN_JSON                = "Origin";
    
    String SIGNATURE_TYPE_JSON        = "SignatureType";
    // Argument to the above
    String SIGNATURE_TYPE_DETACHED    = "Detached";
    String SIGNATURE_TYPE_EMBEDDING   = "Embedding";
    
    String SIGNATURE_FORMAT_JSON      = "SignatureFormat";
    // Argument to the above
    String SIGNATURE_FORMAT_JCS       = "JCS";
    String SIGNATURE_FORMAT_XML_DSIG  = "XMLDSig";
    String SIGNATURE_FORMAT_JWS       = "JWS";

    String WCPP_DEMO_CONTEXT_URI      = "http://xmlns.webpki.org/wcpp-signature-demo";
    String ECDH_ALGORITHM_URI         = "http://www.w3.org/2009/xmlenc11#ECDH-ES";
    String CONCAT_ALGORITHM_URI       = "http://www.w3.org/2009/xmlenc11#ConcatKDF";
  }
