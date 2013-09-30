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

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.CertificateUtil;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONSignatureEncoder;

import org.webpki.keygen2.ServerState.Key;
import org.webpki.keygen2.ServerState.PostProvisioningTargetKey;
import org.webpki.keygen2.ServerState.ProtocolPhase;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class ProvisioningFinalizationRequestEncoder extends ServerEncoder
  {
    String submit_url;

    ServerState server_state;
    
   
    // Constructors

    public ProvisioningFinalizationRequestEncoder (ServerState server_state, String submit_url) throws IOException
      {
        this.server_state = server_state;
        this.submit_url = submit_url;
        server_state.checkState (true, server_state.current_phase == ProtocolPhase.KEY_CREATION? ProtocolPhase.KEY_CREATION : ProtocolPhase.PROVISIONING_FINALIZATION);
        server_state.current_phase = ProtocolPhase.PROVISIONING_FINALIZATION;
      }


    private byte[] mac (byte[] data, byte[] method) throws IOException, GeneralSecurityException
      {
        return server_state.mac (data, method);
      }
    
    
    private void mac (JSONObjectWriter wr, byte[] data, byte[] method) throws IOException, GeneralSecurityException
      {
        wr.setBinary (MAC_JSON, mac (data, method));
      }
    
    
    private void writePostOp (JSONObjectWriter wr,
                              PostProvisioningTargetKey target_key,
                              MacGenerator post_op_mac) throws IOException, GeneralSecurityException
      {
        wr.addChildElement (target_key.post_operation.getXMLElem ());
        wr.setString (CLIENT_SESSION_ID_JSON, target_key.client_session_id);
        wr.setString (SERVER_SESSION_ID_JSON, target_key.server_session_id);
        wr.setBinary (CERTIFICATE_FINGERPRINT_JSON, HashAlgorithms.SHA256.digest (target_key.certificate_data));
        byte[] device_id = server_state.device_certificate == null ? SecureKeyStore.KDF_ANONYMOUS : server_state.device_certificate.getEncoded ();
        byte[] key_id = server_state.server_crypto_interface.mac (target_key.certificate_data, device_id);
        byte[] authorization = server_state.server_crypto_interface.generateKeyManagementAuthorization (target_key.key_management_key,
                                                                                                        ArrayUtil.add (SecureKeyStore.KMK_TARGET_KEY_REFERENCE,
                                                                                                                       key_id));
        wr.setBinary (AUTHORIZATION_JSON, authorization);
        post_op_mac.addArray (authorization);
        mac (wr, post_op_mac.getResult (), target_key.post_operation.getMethod ());
        wr.getParent ();
      }


    @Override
    void writeServerRequest (JSONObjectWriter wr) throws IOException
      {
        try
          {
            //////////////////////////////////////////////////////////////////////////
            // Set top-level attributes
            //////////////////////////////////////////////////////////////////////////
            wr.setString (SERVER_SESSION_ID_JSON, server_state.server_session_id);
            
            wr.setString (CLIENT_SESSION_ID_JSON, server_state.client_session_id);
    
            wr.setString (SUBMIT_URL_JSON, submit_url);
    
            byte[] nonce;
            wr.setBinary (NONCE_JSON, nonce = server_state.server_crypto_interface.generateNonce ());
    
            ////////////////////////////////////////////////////////////////////////
            // Write [0..n] Credentials
            ////////////////////////////////////////////////////////////////////////
            if (!server_state.requested_keys.isEmpty ())
              {
                JSONArrayWriter key_arr = wr.setArray (ISSUED_KEYS_JSON);
                for (ServerState.Key key : server_state.getKeys ())
                  {
                    issueKey (key_arr.setObject (), key);
                  }
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
            top.set (MAC_JSON,
                              new Base64 ().getBase64StringFromBinary (mac (close.getResult (),
                                                                            SecureKeyStore.METHOD_CLOSE_PROVISIONING_SESSION)));
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }


    private void issueKey (JSONObjectWriter wr, Key key) throws IOException, GeneralSecurityException
      {
        ////////////////////////////////////////////////////////////////////////
        // Always: the ID, X509 Certificate(s) and MAC
        ////////////////////////////////////////////////////////////////////////
        wr.setString (ID_JSON, key.id);

        MacGenerator set_certificate = new MacGenerator ();
        set_certificate.addArray (key.public_key.getEncoded ());
        set_certificate.addString (key.id);
        X509Certificate[] certificate_path = key.certificate_path;
        if (key.trust_anchor_set && !CertificateUtil.isTrustAnchor (certificate_path[certificate_path.length - 1]))
          {
            throw new IOException ("Invalid \"" + TRUST_ANCHOR_JSON + "\"");
          }
        for (X509Certificate certificate : certificate_path)
          {
            set_certificate.addArray (certificate.getEncoded ());
          }
        JSONSignatureEncoder.writeX509CertificatePath (wr, certificate_path);
        mac (wr, set_certificate.getResult (), SecureKeyStore.METHOD_SET_CERTIFICATE_PATH);
        byte[] ee_cert = certificate_path[0].getEncoded ();
        
        ////////////////////////////////////////////////////////////////////////
        // Optional: A certificate path may also contain a TA
        ////////////////////////////////////////////////////////////////////////
        if (key.trust_anchor_set)
          {
            wr.setBoolean (TRUST_ANCHOR_JSON, key.trust_anchor);
          }

        ////////////////////////////////////////////////////////////////////////
        // Optional: "piggybacked" symmetric key
        ////////////////////////////////////////////////////////////////////////
        if (key.encrypted_symmetric_key != null)
          {
            MacGenerator set_symkey = new MacGenerator ();
            set_symkey.addArray (ee_cert);
            set_symkey.addArray (key.encrypted_symmetric_key);
            mac (wr.setObject (SYMMETRIC_KEY_JSON).setBinary (ENCRYPTED_KEY_JSON, key.encrypted_symmetric_key),
                 set_symkey.getResult (), SecureKeyStore.METHOD_IMPORT_SYMMETRIC_KEY);
          }

        ////////////////////////////////////////////////////////////////////////
        // Optional: private key
        ////////////////////////////////////////////////////////////////////////
        if (key.encrypted_private_key != null)
          {
            MacGenerator set_privkey = new MacGenerator ();
            set_privkey.addArray (ee_cert);
            set_privkey.addArray (key.encrypted_private_key);
            mac (wr.setObject (PRIVATE_KEY_JSON).setBinary (ENCRYPTED_KEY_JSON, key.encrypted_private_key),
                set_privkey.getResult (), SecureKeyStore.METHOD_IMPORT_PRIVATE_KEY);
          }

        ////////////////////////////////////////////////////////////////////////
        // Optional: property bags, extensions, and logotypes.
        // Note: Order must be followed!
        ////////////////////////////////////////////////////////////////////////
        writeExtensions (wr, key, ee_cert, SecureKeyStore.SUB_TYPE_PROPERTY_BAG);
        writeExtensions (wr, key, ee_cert, SecureKeyStore.SUB_TYPE_LOGOTYPE);
        writeExtensions (wr, key, ee_cert, SecureKeyStore.SUB_TYPE_EXTENSION);
        writeExtensions (wr, key, ee_cert, SecureKeyStore.SUB_TYPE_ENCRYPTED_EXTENSION);

        ////////////////////////////////////////////////////////////////////////
        // Optional: post operation associated with the provisioned key
        ////////////////////////////////////////////////////////////////////////
        if (key.clone_or_update_operation != null)
          {
            MacGenerator set_post_mac = new MacGenerator ();
            set_post_mac.addArray (ee_cert);
            writePostOp (wr, key.clone_or_update_operation, set_post_mac);
          }
      }


    void writeExtensions (JSONObjectWriter wr, Key key, byte[] ee_cert, byte sub_type) throws IOException, GeneralSecurityException
      {
        JSONArrayWriter arr = null;
        for (ServerState.ExtensionInterface ei : key.extensions.values ())
          {
            if (ei.getSubType () == sub_type)
              {
                if (arr == null)
                  {
                    arr = wr.setArray (ei.getJSONArrayString ());
                  }
                MacGenerator add_ext = new MacGenerator ();
                add_ext.addArray (ee_cert);
                add_ext.addString (ei.type);
                add_ext.addByte (ei.getSubType ());
                add_ext.addString (ei.getQualifier ());
                add_ext.addBlob (ei.getExtensionData ());
                ei.writeExtension (arr.setObject (), mac (add_ext.getResult (), SecureKeyStore.METHOD_ADD_EXTENSION));
              }
          }
      }
  }
