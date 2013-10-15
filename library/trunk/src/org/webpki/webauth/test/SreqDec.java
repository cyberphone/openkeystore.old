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


import org.webpki.util.DebugFormatter;

import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.KeyContainerTypes;


public class SreqDec
  {

    static void printcf (CertificateFilter cf, StringBuffer s)
      {
        s.append ("\nCERTFILTER:");
        if (cf.getSha1 () != null) s.append ("\nSha1=" +  DebugFormatter.getHexString(cf.getSha1 ()));
        if (cf.getIssuerRegEx () != null) s.append ("\nIssuer=" + cf.getIssuerRegEx ());
        if (cf.getSubjectRegEx () != null) s.append ("\nSubject=" + cf.getSubjectRegEx ());
        if (cf.getSerial () != null) s.append ("\nSerial=" + cf.getSerial ());
        if (cf.getPolicy () != null) s.append ("\nPolicy=" + cf.getPolicy ());
        if (cf.getContainers () != null)
          {
            s.append ("\nContainers=");
            boolean next = false;
            for (KeyContainerTypes kct : cf.getContainers ())
              {
                if (next)
                  {
                    s.append (", ");
                  }
                next = true;
                s.append (kct.toString ());
              }
          }
        if (cf.getKeyUsage () != null) s.append ("\nKeyUsage=" + cf.getKeyUsage ());
        if (cf.getExtKeyUsage () != null) s.append ("\nExtKeyUsage=" + cf.getExtKeyUsage ());
        s.append ("\nCERTFILTER\n");
      }

  }
