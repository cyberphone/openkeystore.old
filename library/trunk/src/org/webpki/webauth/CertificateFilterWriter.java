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

import org.webpki.json.JSONObjectWriter;

import static org.webpki.webauth.WebAuthConstants.*;

class CertificateFilterWriter extends CertificateFilterIOBase
  {
    static void write (JSONObjectWriter wr, CertificateFilter cf) throws IOException
      {
        if (cf.getSha1 () != null)
          {
            wr.setBinary (CF_SHA1_ATTR, cf.getSha1 ());
          }
        writeOptionalString (wr, CF_ISSUER_ATTR, cf.getIssuerRegEx ());
        writeOptionalString (wr, CF_SUBJECT_ATTR, cf.getSubjectRegEx ());
        writeOptionalString (wr, CF_EMAIL_ATTR, cf.getEmailAddress ());
        if (cf.getSerial () != null)
          {
            wr.setBigInteger (CF_SERIAL_ATTR, cf.getSerial ());
          }
        writeOptionalString (wr, CF_POLICY_ATTR, cf.getPolicy ());
        if (cf.getContainers () != null)
          {
            KeyContainerTypes[] containers = cf.getContainers ();
            String[] scontainers = new String[containers.length];
            for (int q = 0; q < containers.length; q++)
              {
                for (int i = 0; i < KEYCONTAINER2NAME.length; i++)
                  {
                    if (KEYCONTAINER2NAME[i] == containers[q])
                      {
                        scontainers[q] = NAME2KEYCONTAINER[i];
                        break;
                      }
                  }
              }
            wr.setStringArray (CF_CONTAINERS_ATTR, scontainers);
          }
        if (cf.getKeyUsage () != null)
          {
            StringBuffer coded_key_usage = new StringBuffer ();
            int i = 0;
            for (KeyUsageBits ku : KeyUsageBits.values ())
              {
                if (cf.getKeyUsage ().getRequiredBits ().contains (ku))
                  {
                    i = ku.ordinal ();
                    coded_key_usage.append ('1');
                  }
                else if (cf.getKeyUsage ().getDisAllowedBits ().contains (ku))
                  {
                    i = ku.ordinal ();
                    coded_key_usage.append ('0');
                  }
                else
                  {
                    coded_key_usage.append ('X');
                  }
              }
            wr.setString (CF_KEY_USAGE_ATTR, coded_key_usage.toString ().substring (0, i + 1));
          }
        writeOptionalString (wr, CF_EXT_KEY_USAGE_ATTR, cf.getExtKeyUsage ());
      }

    static void writeOptionalString (JSONObjectWriter wr, String name, String optional_value) throws IOException
      {
    	if (optional_value != null)
    	  {
    		wr.setString (name, optional_value);
    	  }
	  }
  }
