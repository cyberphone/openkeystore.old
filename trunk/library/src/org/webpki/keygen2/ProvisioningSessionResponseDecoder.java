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

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;

import org.webpki.util.ArrayUtil;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSymKeyVerifier;

import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymKeyVerifierInterface;

import static org.webpki.keygen2.KeyGen2Constants.*;


public class ProvisioningSessionResponseDecoder extends ProvisioningSessionResponse
  {
    private XMLSignatureWrapper signature;


    public String getServerSessionID ()
      {
        return server_session_id;
      }

    
    public String getClientSessionID ()
      {
        return client_session_id;
      }


    public Date getServerTime ()
      {
        return server_time;
      }

    
    public Date getClientTime ()
      {
        return client_time;
      }

    
    public ECPublicKey getClientEphemeralKey ()
      {
        return client_ephemeral_key;
      }


    public ServerCookie getServerCookie ()
      {
        return server_cookie;
      }


    public byte[] getSessionAttestation ()
      {
        return session_attestation;
      }


    public X509Certificate[] getDeviceCertificatePath ()
      {
        return device_certificate_path;
      }


    public void verifyAndGenerateSessionKey (final ServerSessionKeyInterface session_key_operations,
                                             ProvisioningSessionRequestEncoder prov_sess_request) throws IOException
      {
        try
          {
            ServerCredentialStore.MacGenerator kdf = new ServerCredentialStore.MacGenerator ();
            kdf.addString (client_session_id);
            kdf.addString (server_session_id);
            kdf.addString (prov_sess_request.submit_url);
            kdf.addArray (device_certificate_path[0].getEncoded ());

            ServerCredentialStore.MacGenerator session_key_mac_data = new ServerCredentialStore.MacGenerator ();
            session_key_mac_data.addString (client_session_id);
            session_key_mac_data.addString (server_session_id);
            session_key_mac_data.addString (prov_sess_request.submit_url);
            session_key_mac_data.addArray (prov_sess_request.server_ephemeral_key.getEncoded ());
            session_key_mac_data.addArray (client_ephemeral_key.getEncoded ());
            session_key_mac_data.addBool (prov_sess_request.session_updatable_flag);
            session_key_mac_data.addInt ((int) (client_time.getTime () / 1000));
            session_key_mac_data.addInt (prov_sess_request.session_life_time);
            session_key_mac_data.addShort (prov_sess_request.session_key_limit);

            session_key_operations.generateAndVerifySessionKey (client_ephemeral_key,
                                                                kdf.getResult (),
                                                                session_key_mac_data.getResult (),
                                                                device_certificate_path[0].getPublicKey (),
                                                                session_attestation,
                                                                SignatureAlgorithms.RSA_SHA256);
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
        new XMLSymKeyVerifier (new SymKeyVerifierInterface ()
          {

            @Override
            public boolean verifyData (byte[] data, byte[] digest, MacAlgorithms algorithm) throws IOException, GeneralSecurityException
              {
                return ArrayUtil.compare (session_key_operations.mac (data, CryptoConstants.CRYPTO_STRING_SIGNATURE), digest);
              }
          
          }).validateEnvelopedSignature (this, null, signature, client_session_id);
      }


    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Read the top level attributes
        /////////////////////////////////////////////////////////////////////////////////////////

        client_session_id = ah.getString (ID_ATTR);

        server_session_id = ah.getString (SERVER_SESSION_ID_ATTR);

        server_time = ah.getDateTime (SERVER_TIME_ATTR).getTime ();

        client_time = ah.getDateTime (CLIENT_TIME_ATTR).getTime ();

        session_attestation = ah.getBinary (SESSION_ATTESTATION_ATTR);
        
        rd.getChild ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the ephemeral client key
        /////////////////////////////////////////////////////////////////////////////////////////
        rd.getNext (CLIENT_EPHEMERAL_KEY_ELEM);
        rd.getChild ();
        client_ephemeral_key = (ECPublicKey) XMLSignatureWrapper.readPublicKey (rd);
        rd.getParent ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the device certificate path
        /////////////////////////////////////////////////////////////////////////////////////////
        rd.getNext (DEVICE_CERTIFICATE_ELEM);
        rd.getChild ();
        device_certificate_path = XMLSignatureWrapper.readSortedX509DataSubset (rd);
        rd.getParent ();

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the optional ServerCookie
        /////////////////////////////////////////////////////////////////////////////////////////
        if (rd.hasNext (ServerCookie.SERVER_COOKIE_ELEM))
          {
            server_cookie = ServerCookie.read (rd);
          }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the mandatory provisioning session data signature
        /////////////////////////////////////////////////////////////////////////////////////////
        signature = (XMLSignatureWrapper)wrap (rd.getNext (XMLSignatureWrapper.SIGNATURE_ELEM));
      }

  }
