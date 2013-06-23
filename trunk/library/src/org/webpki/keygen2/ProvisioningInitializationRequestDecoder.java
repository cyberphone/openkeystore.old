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
package org.webpki.keygen2;

import java.io.IOException;

import java.util.Date;

import java.security.GeneralSecurityException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;

import org.webpki.xmldsig.XMLVerifier;
import org.webpki.xmldsig.XMLSignatureWrapper;

import org.webpki.crypto.VerifierInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningInitializationRequestDecoder extends ProvisioningInitializationRequest
  {
    private XMLSignatureWrapper signature;  // Optional

    String algorithm;
    
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
        return algorithm;
      }


    public int getSessionLifeTime ()
      {
        return session_life_time;
      }

    
    public short getSessionKeyLimit ()
      {
        return session_key_limit;
      }


    public PublicKey getKeyManagementKey ()
      {
        return key_management_key;
      }

    
    public String getVirtualMachineFriendlyName ()
      {
        return virtual_machine_friendly_name;
      }


    public String[] getClientAttributes ()
      {
        return client_attributes.toArray (new String[0]);
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
        
        algorithm = ah.getString (XMLSignatureWrapper.ALGORITHM_ATTR);
        
        session_key_limit = (short)ah.getInt (SESSION_KEY_LIMIT_ATTR);
        
        session_life_time = ah.getInt (SESSION_LIFE_TIME_ATTR);
        
        String[] attrs = ah.getListConditional (CLIENT_ATTRIBUTES_ATTR);
        if (attrs != null)
          {
            for (String attr : attrs)
              {
                client_attributes.add (attr);
              }
          }
        
        rd.getChild ();


        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the server key
        /////////////////////////////////////////////////////////////////////////////////////////
        rd.getNext (SERVER_EPHEMERAL_KEY_ELEM);
        rd.getChild ();
        server_ephemeral_key = (ECPublicKey) XMLSignatureWrapper.readPublicKey (rd);
        rd.getParent ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional key management key
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (KEY_MANAGEMENT_KEY_ELEM))
          {
            rd.getNext (KEY_MANAGEMENT_KEY_ELEM);
            rd.getChild ();
            key_management_key = XMLSignatureWrapper.readPublicKey (rd);
            if (rd.hasNext (VIRTUAL_MACHINE_ELEM))
              {
                rd.getNext ();
                try
                  {
                    Signature km_verify = Signature.getInstance (key_management_key instanceof RSAPublicKey ? 
                                                                                            "SHA256WithRSA" : "SHA256WithECDSA");
                    km_verify.initVerify (key_management_key);
                    km_verify.update (server_ephemeral_key.getEncoded ());
                    if (!km_verify.verify (ah.getBinary (AUTHORIZATION_ATTR)))
                      {
                        throw new IOException ("Virtual Machine \"" + AUTHORIZATION_ATTR + "\" signature error");
                      }
                  }
                catch (GeneralSecurityException e)
                  {
                    throw new IOException (e);
                  }
                virtual_machine_friendly_name = ah.getString (FRIENDLY_NAME_ATTR);
              }
            rd.getParent ();
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

