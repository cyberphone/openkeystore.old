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
package org.webpki.webauth.test;

import java.security.KeyStore;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.test.DemoKeyStore;
import org.webpki.crypto.KeyContainerTypes;
import org.webpki.crypto.KeyUsageBits;


public class SreqEnc
  {
    static CertificateFilter[] createCertificateFilters () throws Exception
      {
        KeyStore ks = DemoKeyStore.getMarionKeyStore ();
        Certificate[]certs = ks.getCertificateChain ("mykey");
        CertificateInfo ci = new CertificateInfo ((X509Certificate) certs[1]);
        
        CertificateFilter cf1 = new CertificateFilter ()
              .setPolicy ("1.25.453.22.22.88")
              .setKeyUsage (new CertificateFilter.KeyUsage ().require (KeyUsageBits.digitalSignature))
              .setSha1 (ci.getCertificateHash ())  // CA
              .setIssuerDN (ci.getIssuer ());

        CertificateFilter cf2 = new CertificateFilter ()
              .setSha1 (new byte[]{1,4,5,3,6,7,8,3,0,3,5,6,1,4,5,3,6,7,8,3})
              .setIssuerDN ("CN=SuckerTrust GlobalCA, emailaddress=boss@fire.hell, c=TV")
              .setContainers (new KeyContainerTypes[]{KeyContainerTypes.TPM, KeyContainerTypes.SIM})
              .setExtendedKeyUsage ("1.56.245.123")
              .setKeyUsage (new CertificateFilter.KeyUsage ().require (KeyUsageBits.nonRepudiation)
                                                             .disAllow (KeyUsageBits.keyEncipherment))
              .setEmailAddress ("try@this.com");
        return new CertificateFilter[] {cf1, cf2};
      }

  }
