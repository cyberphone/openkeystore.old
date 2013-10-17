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
    static final String CF_SHA1_FP_ATTR         = "SHA1FingerPrint";
    static final String CF_ISSUER_ATTR          = "Issuer";
    static final String CF_SUBJECT_ATTR         = "Subject";
    static final String CF_EMAIL_ATTR           = "Email";
    static final String CF_SERIAL_ATTR          = "Serial";
    static final String CF_POLICY_ATTR          = "Policy";
    static final String CF_CONTAINERS_ATTR      = "Containers";
    static final String CF_KEY_USAGE_ATTR       = "KeyUsage";
    static final String CF_EXT_KEY_USAGE_ATTR   = "ExtKeyUsage";
  }
