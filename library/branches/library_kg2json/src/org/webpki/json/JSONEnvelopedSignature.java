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
package org.webpki.json;

/**
 * Common class for enveloped JSON signatures.
 */
class JSONEnvelopedSignature
  {
    public static final String ENVELOPED_SIGNATURE_JSON   = "EnvelopedSignature";

    public static final String ALGORITHM_JSON             = "Algorithm";

    public static final String REFERENCE_JSON             = "Reference";

    public static final String NAME_JSON                  = "Name";

    public static final String VALUE_JSON                 = "Value";
    
    public static final String SIGNATURE_VALUE_JSON       = "SignatureValue";

    public static final String SIGNATURE_INFO_JSON        = "SignatureInfo";

    public static final String KEY_INFO_JSON              = "KeyInfo";

    public static final String X509_CERTIFICATE_PATH_JSON = "X509CertificatePath";

    public static final String SIGNATURE_CERTIFICATE_JSON = "SignatureCertificate";

    public static final String ISSUER_JSON                = "Issuer";

    public static final String SERIAL_NUMBER_JSON         = "SerialNumber";

    public static final String SUBJECT_JSON               = "Subject";
  }
