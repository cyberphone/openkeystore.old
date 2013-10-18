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

abstract class CertificateFilterIOBase
  {
    static final String CF_FINGER_PRINT_ATTR          = "FingerPrint";
    static final String CF_ISSUER_REG_EX_ATTR         = "IssuerRegEx";
    static final String CF_SUBJECT_REG_EX_ATTR        = "SubjectRegEx";
    static final String CF_EMAIL_REG_EX_ATTR          = "EmailRegEx";
    static final String CF_SERIAL_NUMBER_ATTR         = "SerialNumber";
    static final String CF_POLICY_REG_EX_ATTR         = "PolicyRegEx";
    static final String CF_CONTAINERS_ATTR            = "Containers";
    static final String CF_KEY_USAGE_ATTR             = "KeyUsage";
    static final String CF_EXT_KEY_USAGE_REG_EX_ATTR  = "ExtKeyUsageRegEx";
  }
