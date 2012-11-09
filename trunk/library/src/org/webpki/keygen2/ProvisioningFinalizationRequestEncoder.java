/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
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


import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import org.webpki.sks.SecureKeyStore;

import org.webpki.util.Base64;

import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.ServerCookie;

import org.webpki.xmldsig.XMLSignatureWrapper;
import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.CertificateUtil;
import org.webpki.keygen2.ServerState.PostProvisioningTargetKey;
import org.webpki.keygen2.ServerState.ProtocolPhase;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class ProvisioningFinalizationRequestEncoder extends ProvisioningFinalizationRequest
  {
    String submit_url;

    private String prefix;  // Default: no prefix

    ServerCookie server_cookie;

    ServerState server_state;
    
   
    // Constructors

    public ProvisioningFinalizationRequestEncoder (ServerState server_state, String submit_url) throws IOException
      {
        this.server_state = server_state;
        this.submit_url = submit_url;
        server_state.checkState (true, server_state.current_phase == ProtocolPhase.KEY_CREATION? ProtocolPhase.KEY_CREATION : ProtocolPhase.PROVISIONING_FINALIZATION);
        server_state.current_phase = ProtocolPhase.PROVISIONING_FINALIZATION;
      }


    public ServerCookie setServerCookie (ServerCookie server_cookie)
      {
        return this.server_cookie = server_cookie;
      }


    public void setPrefix (String prefix)
      {
        this.prefix = prefix;
      }


    public void signRequest (SignerInterface signer) throws IOException
      {
        XMLSigner ds = new XMLSigner (signer);
        ds.removeXMLSignatureNS ();
        Document doc = getRootDocument ();
        ds.createEnvelopedSignature (doc, server_state.server_session_id);
      }
    
    
    private byte[] mac (byte[] data, byte[] method) throws IOException, GeneralSecurityException
      {
        return server_state.mac (data, method);
      }
    
    
    private void mac (DOMWriterHelper wr, byte[] data, byte[] method) throws IOException, GeneralSecurityException
      {
        wr.setBinaryAttribute (MAC_ATTR, mac (data, method));
      }
    
    
    private void writePostOp (DOMWriterHelper wr,
                              PostProvisioningTargetKey target_key,
                              MacGenerator post_op_mac) throws IOException, GeneralSecurityException
      {
        wr.addChildElement (target_key.post_operation.getXMLElem ());
        wr.setStringAttribute (CLIENT_SESSION_ID_ATTR, target_key.client_session_id);
        wr.setStringAttribute (SERVER_SESSION_ID_ATTR, target_key.server_session_id);
        wr.setBinaryAttribute (CERTIFICATE_FINGERPRINT_ATTR, HashAlgorithms.SHA256.digest (target_key.certificate_data));
        byte[] device_id = server_state.device_certificate == null ? SecureKeyStore.KDF_ANONYMOUS : server_state.device_certificate.getEncoded ();
        byte[] key_id = server_state.server_crypto_interface.mac (target_key.certificate_data, device_id);
        byte[] authorization = server_state.server_crypto_interface.generateKeyManagementAuthorization (target_key.key_management_key, key_id);
        wr.setBinaryAttribute (AUTHORIZATION_ATTR, authorization);
        post_op_mac.addArray (authorization);
        mac (wr, post_op_mac.getResult (), target_key.post_operation.getMethod ());
        wr.getParent ();
      }


    protected void toXML (DOMWriterHelper wr) throws IOException
      {
        Element top = wr.initializeRootObject (prefix);

        try
          {
            //////////////////////////////////////////////////////////////////////////
            // Set top-level attributes
            //////////////////////////////////////////////////////////////////////////
            wr.setStringAttribute (CLIENT_SESSION_ID_ATTR, server_state.client_session_id);
    
            wr.setStringAttribute (ID_ATTR, server_state.server_session_id);
    
            wr.setStringAttribute (SUBMIT_URL_ATTR, submit_url);
    
            byte[] nonce;
            wr.setBinaryAttribute (NONCE_ATTR, nonce = server_state.server_crypto_interface.generateNonce ());
    
            XMLSignatureWrapper.addXMLSignatureNS (wr);
    
            ////////////////////////////////////////////////////////////////////////
            // Write [0..n] Credentials
            ////////////////////////////////////////////////////////////////////////
            for (ServerState.Key key : server_state.getKeys ())
              {
                wr.addChildElement (CERTIFICATE_PATH_ELEM);
                wr.setStringAttribute (ID_ATTR, key.id);
                if (key.trust_anchor_set)
                  {
                    wr.setBooleanAttribute (TRUST_ANCHOR_ATTR, key.trust_anchor);
                  }

                ////////////////////////////////////////////////////////////////////////
                // Always: the X509 Certificate(s)
                ////////////////////////////////////////////////////////////////////////
                MacGenerator set_certificate = new MacGenerator ();
                set_certificate.addArray (key.public_key.getEncoded ());
                set_certificate.addString (key.id);
                X509Certificate[] certificate_path = CertificateUtil.getSortedPath (key.certificate_path);
                if (key.trust_anchor_set && !CertificateUtil.isTrustAnchor (certificate_path[certificate_path.length - 1]))
                  {
                    throw new IOException ("Invalid \"" + TRUST_ANCHOR_ATTR + "\"");
                  }
                for (X509Certificate certificate : certificate_path)
                  {
                    set_certificate.addArray (certificate.getEncoded ());
                  }
                mac (wr, set_certificate.getResult (), SecureKeyStore.METHOD_SET_CERTIFICATE_PATH);
                XMLSignatureWrapper.writeX509DataSubset (wr, certificate_path);
                byte[] ee_cert = certificate_path[0].getEncoded ();
                
                ////////////////////////////////////////////////////////////////////////
                // Optional: "piggybacked" symmetric key
                ////////////////////////////////////////////////////////////////////////
                if (key.encrypted_symmetric_key != null)
                  {
                    wr.addBinary (SYMMETRIC_KEY_ELEM, key.encrypted_symmetric_key);
                    MacGenerator set_symkey = new MacGenerator ();
                    set_symkey.addArray (ee_cert);
                    set_symkey.addArray (key.encrypted_symmetric_key);
                    mac (wr, set_symkey.getResult (), SecureKeyStore.METHOD_IMPORT_SYMMETRIC_KEY);
                  }
 
                ////////////////////////////////////////////////////////////////////////
                // Optional: private key
                ////////////////////////////////////////////////////////////////////////
                if (key.encrypted_private_key != null)
                  {
                    wr.addBinary (PRIVATE_KEY_ELEM, key.encrypted_private_key);
                    MacGenerator restore_privkey = new MacGenerator ();
                    restore_privkey.addArray (ee_cert);
                    restore_privkey.addArray (key.encrypted_private_key);
                    mac (wr, restore_privkey.getResult (), SecureKeyStore.METHOD_IMPORT_PRIVATE_KEY);
                  }
 
                ////////////////////////////////////////////////////////////////////////
                // Optional: property bags, extensions, and logotypes
                ////////////////////////////////////////////////////////////////////////
                for (ServerState.ExtensionInterface ei : key.extensions.values ())
                  {
                    MacGenerator add_ext = new MacGenerator ();
                    add_ext.addArray (ee_cert);
                    add_ext.addString (ei.type);
                    add_ext.addByte (ei.getSubType ());
                    add_ext.addString (ei.getQualifier ());
                    add_ext.addBlob (ei.getExtensionData ());
                    ei.writeExtension (wr, mac (add_ext.getResult (), SecureKeyStore.METHOD_ADD_EXTENSION));
                  }

                ////////////////////////////////////////////////////////////////////////
                // Optional: post operation associated with the provisioned key
                ////////////////////////////////////////////////////////////////////////
                if (key.clone_or_update_operation != null)
                  {
                    MacGenerator set_post_mac = new MacGenerator ();
                    set_post_mac.addArray (ee_cert);
                    writePostOp (wr, key.clone_or_update_operation, set_post_mac);
                  }
 
                wr.getParent ();
              }
            
            ////////////////////////////////////////////////////////////////////////
            // Optional: post provisioning unlock operations
            ////////////////////////////////////////////////////////////////////////
            for (ServerState.PostProvisioningTargetKey pptk : server_state.post_operations)
              {
                if (pptk.post_operation == ServerState.PostOperation.UNLOCK_KEY)
                  {
                    writePostOp (wr, pptk, new MacGenerator ());
                  }
              }
            
            ////////////////////////////////////////////////////////////////////////
            // Optional: post provisioning delete operations
            ////////////////////////////////////////////////////////////////////////
            for (ServerState.PostProvisioningTargetKey pptk : server_state.post_operations)
              {
                if (pptk.post_operation == ServerState.PostOperation.DELETE_KEY)
                  {
                    writePostOp (wr, pptk, new MacGenerator ());
                  }
              }

            ////////////////////////////////////////////////////////////////////////
            // Done with the crypto, now set the "closeProvisioningSession" MAC
            ////////////////////////////////////////////////////////////////////////
            MacGenerator close = new MacGenerator ();
            close.addString (server_state.client_session_id);
            close.addString (server_state.server_session_id);
            close.addString (server_state.issuer_uri);
            close.addArray (server_state.saved_close_nonce = nonce);
            top.setAttribute (MAC_ATTR,
                              new Base64 ().getBase64StringFromBinary (mac (close.getResult (),
                                                                            SecureKeyStore.METHOD_CLOSE_PROVISIONING_SESSION)));
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }

        ////////////////////////////////////////////////////////////////////////
        // Optional ServerCookie
        ////////////////////////////////////////////////////////////////////////
        if (server_cookie != null)
          {
            server_cookie.write (wr);
          }
      }
  }
