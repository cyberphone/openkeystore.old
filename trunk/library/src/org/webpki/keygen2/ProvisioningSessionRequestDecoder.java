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

import java.util.Date;

import java.security.interfaces.ECPublicKey;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLVerifier;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.VerifierInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningSessionRequestDecoder extends ProvisioningSessionRequest
  {
    private XMLSignatureWrapper signature;  // Optional


    public String getServerSessionID ()
      {
        return server_session_id;
      }


    public Date getServerTime ()
      {
        return server_time;
      }


    public String getSubmitURL ()
      {
        return submit_url;
      }

    
    public ECPublicKey getServerEphemeralKey ()
      {
        return server_ephemeral_key;
      }

    
    public String getSessionKeyAlgorithm ()
      {
        return session_key_algorithm;
      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }


    public int getSessionLifeTime ()
      {
        return session_life_time;
      }

    
    public int getSessionKeyLimit ()
      {
        return session_key_limit;
      }


    public void verifySignature (VerifierInterface verifier) throws IOException
      {
        new XMLVerifier (verifier).validateEnvelopedSignature (this, null, signature, server_session_id);
      }


    public boolean isSigned ()
      {
        return signature != null;
      }


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        server_session_id = ah.getString (ID_ATTR);

        server_time = ah.getDateTime (SERVER_TIME_ATTR).getTime ();

        submit_url = ah.getString (SUBMIT_URL_ATTR);
        
        session_key_algorithm = ah.getString (SESSION_KEY_ALGORITHM_ATTR);
        
        session_updatable_flag = ah.getBooleanConditional (UPDATABLE_ATTR, session_updatable_flag);
        
        session_key_limit = ah.getInt (SESSION_KEY_LIMIT_ATTR);
        
        session_life_time = ah.getInt (SESSION_LIFE_TIME_ATTR);

        rd.getChild ();


        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the server key
        /////////////////////////////////////////////////////////////////////////////////////////
        rd.getNext (SERVER_EPHEMERAL_KEY_ELEM);
        rd.getChild ();
        server_ephemeral_key = (ECPublicKey) XMLSignatureWrapper.readPublicKey (rd);
        rd.getParent ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional server cookie
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (ServerCookie.SERVER_COOKIE_ELEM))
          {
            server_cookie = ServerCookie.read (rd);
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional signature
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext ()) // Must be a Signature otherwise schema validation has gone wrong...
          {
            signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
          }
      }

  }

