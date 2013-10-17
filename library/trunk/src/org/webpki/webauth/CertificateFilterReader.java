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

import java.io.IOException;

import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.KeyContainerTypes;
import org.webpki.crypto.KeyUsageBits;

import org.webpki.json.JSONObjectReader;

import static org.webpki.webauth.WebAuthConstants.*;


class CertificateFilterReader extends CertificateFilterIOBase
  {
    static CertificateFilter read (JSONObjectReader rd) throws IOException
      {
        CertificateFilter cf = new CertificateFilter ();
        cf.setSha1 (rd.getBinaryConditional (CF_SHA1_FP_ATTR));
        cf.setIssuerRegEx (rd.getStringConditional (CF_ISSUER_ATTR));
        cf.setSubjectRegEx (rd.getStringConditional (CF_SUBJECT_ATTR));
        cf.setEmailAddress (rd.getStringConditional (CF_EMAIL_ATTR));
        cf.setSerial (InputValidator.getBigIntegerConditional (rd, CF_SERIAL_ATTR));
        cf.setPolicy (rd.getStringConditional (CF_POLICY_ATTR));
        String[] scontainers = InputValidator.getListConditional (rd, CF_CONTAINERS_ATTR);
        KeyContainerTypes[] containers = null;
        if (scontainers != null)
          {
            containers = new KeyContainerTypes[scontainers.length];
            for (int q = 0; q < scontainers.length; q++)
              {
                boolean found = false;
                for (int i = 0; i < NAME2KEYCONTAINER.length; i++)
                  {
                    if (NAME2KEYCONTAINER[i].equals (scontainers[q]))
                      {
                        found = true;
                        containers[q] = KEYCONTAINER2NAME[i];
                        break;
                      }
                  }
                if (!found) throw new IOException ("Unknown container: " + scontainers[q]);
              }
          }
        cf.setContainers (containers);
        CertificateFilter.KeyUsage key_usage = null;
        String key_usage_string = rd.getStringConditional (CF_KEY_USAGE_ATTR);
        if (key_usage_string != null)
          {
            key_usage = new CertificateFilter.KeyUsage ();
            for (int i = 0; i < key_usage_string.length (); i++)
              {
                switch (key_usage_string.charAt (i))
                  {
                    case '1':
                      key_usage.require (KeyUsageBits.values ()[i]);
                      break;

                    case '0':
                      key_usage.disAllow (KeyUsageBits.values ()[i]);
                      break;
                  }
              }
          }
        cf.setKeyUsage (key_usage);
        cf.setExtendedKeyUsage (rd.getStringConditional (CF_EXT_KEY_USAGE_ATTR));
        return cf;
      }
  }
