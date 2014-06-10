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
package org.webpki.android.crypto;


public enum CertificateExtensions
  {
    SUBJECT_KEY_IDENTIFIER      ("2.5.29.14"),
    KEY_USAGE                   ("2.5.29.15"),
    SUBJECT_ALT_NAME            ("2.5.29.17"),
    BASIC_CONSTRAINTS           ("2.5.29.19"),
    CRL_DISTRIBUTION_POINTS     ("2.5.29.31"),
    CERTIFICATE_POLICIES        ("2.5.29.32"),
    AUTHORITY_KEY_IDENTIFIER    ("2.5.29.35"),
    AUTHORITY_INFO_ACCESS       ("1.3.6.1.5.5.7.1.1"),
    LOGOTYPES                   ("1.3.6.1.5.5.7.1.12");

    private final String oid;

    private CertificateExtensions (String oid)
      {
        this.oid = oid;
      }


    public String getOID ()
      {
        return oid;
      }

  }
