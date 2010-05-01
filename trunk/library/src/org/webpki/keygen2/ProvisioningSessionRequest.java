/*
 *  Copyright 2006-2010 WebPKI.org (http://webpki.org).
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
package org.webpki.keygen2;

import java.io.IOException;

import java.security.interfaces.ECPublicKey;
import java.util.Date;

import org.webpki.xml.ServerCookie;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;

import static org.webpki.keygen2.KeyGen2Constants.*;


abstract class ProvisioningSessionRequest extends XMLObjectWrapper
  {
    ProvisioningSessionRequest () {}

    String server_session_id;

    Date server_time;

    String submit_url;
    
    ECPublicKey server_ephemeral_key;

    int session_life_time;

    int session_key_limit;

    ServerCookie server_cookie;

    boolean session_updatable_flag = false;

    String session_key_algorithm = KeyGen2URIs.ALGORITHMS.SESSION_KEY_1;


    public void init () throws IOException
      {
        addWrapper (XMLSignatureWrapper.class);
        addSchema (KEYGEN2_SCHEMA_FILE);
      }


    protected boolean hasQualifiedElements ()
      {
        return true;
      }


    public String namespace ()
      {
        return KEYGEN2_NS;
      }

    
    public String element ()
      {
        return "ProvisioningSessionRequest";
      }


    protected void fromXML (DOMReaderHelper helper) throws IOException
      {
        throw new IOException ("Should have been implemented in derived class");
      }


    protected void toXML (DOMWriterHelper helper) throws IOException
      {
        throw new IOException ("Should have been implemented in derived class");
      }

  }
