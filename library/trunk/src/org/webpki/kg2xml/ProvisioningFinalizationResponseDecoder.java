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
package org.webpki.kg2xml;

import java.io.IOException;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;

import static org.webpki.kg2xml.KeyGen2Constants.*;

public class ProvisioningFinalizationResponseDecoder extends ProvisioningFinalizationResponse
  {
      
    String client_session_id;

    String server_session_id;
    
    byte[] attestation;


    public byte[] getAttestation ()
      {
        return attestation;
      }

    
    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        client_session_id = ah.getString (ID_ATTR);

        server_session_id = ah.getString (SERVER_SESSION_ID_ATTR);
        
        attestation = ah.getBinary (CLOSE_ATTESTATION_ATTR);

        rd.getChild ();
      }
  }
