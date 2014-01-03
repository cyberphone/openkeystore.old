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
package org.webpki.kg2xml;

import java.io.IOException;
import java.util.Date;

import org.w3c.dom.Document;

import org.webpki.sks.SecureKeyStore;
import org.webpki.util.Base64URL;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.SignerInterface;
import org.webpki.kg2xml.ServerState.ProtocolPhase;

import static org.webpki.kg2xml.KeyGen2Constants.*;

public class PlatformNegotiationRequestEncoder extends PlatformNegotiationRequest
  {
    private String prefix;  // Default: no prefix
    
    Action action = Action.MANAGE;

    boolean needs_dsig_ns;

    private ServerState server_state;

    // Constructors

    public PlatformNegotiationRequestEncoder (ServerState server_state,
                                              String submit_url,
                                              String server_session_id) throws IOException
      {
        server_state.checkState (true, ProtocolPhase.PLATFORM_NEGOTIATION);
        this.server_state = server_state;
        this.submit_url = submit_url;
        if (server_session_id == null)
          {
            server_session_id = Long.toHexString (new Date().getTime());
            server_session_id += Base64URL.generateURLFriendlyRandom (SecureKeyStore.MAX_LENGTH_ID_TYPE - server_session_id.length ());
          }
        this.server_session_id = server_state.server_session_id = server_session_id;
      }
    
    public BasicCapabilities getBasicCapabilities ()
      {
        return server_state.basic_capabilities;
      }
   
    public void setAction (Action action)
      {
        this.action = action;
      }

    public void setAbortURL (String abort_url)
      {
        this.abort_url = abort_url;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        needs_dsig_ns = true;
        XMLSigner ds = new XMLSigner (signer);
        ds.removeXMLSignatureNS ();
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, server_session_id);
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        wr.initializeRootObject (prefix);

        //////////////////////////////////////////////////////////////////////////
        // Set top-level attributes
        //////////////////////////////////////////////////////////////////////////
        wr.setStringAttribute (ACTION_ATTR, action.getXMLName ());

        wr.setStringAttribute (ID_ATTR, server_session_id);

        wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);
        
        if (abort_url != null)
          {
            wr.setStringAttribute (ABORT_URL_ATTR, abort_url);
          }
        
        ////////////////////////////////////////////////////////////////////////
        // Basic capabilities
        ////////////////////////////////////////////////////////////////////////
        BasicCapabilities.write (wr, server_state.basic_capabilities, true);

        if (server_state.privacy_enabled_set)
          {
            wr.setBooleanAttribute (PRIVACY_ENABLED_ATTR, server_state.privacy_enabled);
          }
        
        if (needs_dsig_ns) XMLSignatureWrapper.addXMLSignatureNS (wr);
      }
  }
