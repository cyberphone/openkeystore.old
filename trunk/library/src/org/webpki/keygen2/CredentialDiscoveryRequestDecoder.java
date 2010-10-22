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

import java.util.Vector;

import org.w3c.dom.Element;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLAsymKeyVerifier;
import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLVerifier;

import org.webpki.crypto.VerifierInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class CredentialDiscoveryRequestDecoder extends CredentialDiscoveryRequest
  {

    public class LookupSpecifier
      {
        String id;

        byte[] nonce;
        
        XMLSignatureWrapper signature;
        
        Element element;

        LookupSpecifier () { }


        LookupSpecifier (DOMReaderHelper rd) throws IOException
          {
            DOMAttributeReaderHelper ah = rd.getAttributeHelper ();
            element = rd.getNext (LOOKUP_SPECIFIER_ELEM);
            id = ah.getString (ID_ATTR);
            nonce = ah.getBinary (NONCE_ATTR);
            rd.getChild ();
            signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
            rd.getParent ();
          }


        public String getID ()
          {
            return id;
          }
      }

    private Vector<LookupSpecifier> lookup_specifiers = new Vector<LookupSpecifier> ();
    
    private String client_session_id;

    private String server_session_id;

    private String submit_url;

    private ServerCookie server_cookie;                     // Optional

    private XMLSignatureWrapper signature;                  // Optional


    public String getServerSessionID ()
      {
        return server_session_id;
      }


    public String getClientSessionID ()
      {
        return client_session_id;
      }


    public String getSubmitURL ()
      {
        return submit_url;
      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }


    public LookupSpecifier[] getLookupSpecifiers ()
      {
        return lookup_specifiers.toArray (new LookupSpecifier[0]);
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

        client_session_id = ah.getString (CLIENT_SESSION_ID_ATTR);

        server_session_id = ah.getString (ID_ATTR);

        submit_url = ah.getString (SUBMIT_URL_ATTR);
        
        rd.getChild ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the lookup_specifiers [1..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        do 
          {
            LookupSpecifier o = new LookupSpecifier (rd);
            lookup_specifiers.add (o);
            XMLAsymKeyVerifier verifier = new XMLAsymKeyVerifier ();
            verifier.validateEnvelopedSignature (this, o.element, o.signature, o.id);
          }
        while (rd.hasNext (LOOKUP_SPECIFIER_ELEM));

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get optional server cookie
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (ServerCookie.SERVER_COOKIE_ELEM))
          {
            server_cookie = ServerCookie.read (rd);
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get optional signature
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext ())// Must be a Signature otherwise schema validation has gone wrong...
          {
            signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
          }
      }
  }
