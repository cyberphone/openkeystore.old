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

import static org.webpki.keygen2.KeyGen2Constants.*;

import java.io.IOException;

import org.webpki.crypto.CertificateFilter;

import org.webpki.json.JSONBaseHTML;
import org.webpki.json.JSONBaseHTML.ProtocolTable.Row.Column;
import org.webpki.json.JSONSignatureEncoder;

import org.webpki.sks.SecureKeyStore;

/**
 * Create an HTML description of the current KeyGen2 protocol.
 * 
 * @author Anders Rundgren
 */
public class KeyGen2HTMLReference implements JSONBaseHTML.Types
  {
    static final String KEYGEN2_NAME_SPACE            = "KeyGen2 name space";
    static final String OBJECT_ID                     = "Actual KeyGen2 message type";
    static final String NOT_READY                     = "DOCUMENTATION NOT READY!!!";
    
    static JSONBaseHTML json;
    
    static class MAC implements JSONBaseHTML.Extender
      {
        String sks_method;
        MAC (String sks_method)
          {
            this.sks_method = sks_method;
          }

        @Override
        public Column execute (Column column) throws IOException
          {
            return column
              .newRow ()
                .newColumn ()
                  .addProperty (MAC_JSON)
                  .addSymbolicValue (MAC_JSON)
                .newColumn ()
                  .setType (JSON_TYPE_BASE64)
                .newColumn ()
                .newColumn ()
                  .addString ("Caller authentication. See <code>SKS:")
                  .addString (sks_method)
                  .addString ("</code>");
          }
      }
    
    static class TargetKeyReference implements JSONBaseHTML.Extender
      {
        String sks_method;
        String json_tag;
        boolean optional_group;
        boolean array_flag;
        
        TargetKeyReference (String json_tag, boolean array_flag, String sks_method, boolean optional_group)
          {
            this.sks_method = sks_method;
            this.json_tag = json_tag;
            this.optional_group = optional_group;
            this.array_flag = array_flag;
          }
  
        @Override
        public Column execute (Column column) throws IOException
          {
            column = column
              .newRow ()
                .newColumn ()
                  .addProperty (json_tag);
            column = (array_flag ? column.addArrayLink (json_tag) : column.addLink (json_tag))
                .newColumn ()
                  .setType (JSON_TYPE_OBJECT)
                .newColumn ();
            if (optional_group)
              {
                column.setChoice (false, 2);
              }
            return column
                .newColumn ()
                  .addString ("See <code>SKS:")
                  .addString (sks_method)
                  .addString ("</code>");
          }
      }

    static class ServerSessionID implements JSONBaseHTML.Extender
      {
        @Override
        public Column execute (Column column) throws IOException
          {
            return column
              .newRow ()
                .newColumn ()
                  .addProperty (SERVER_SESSION_ID_JSON)
                  .addSymbolicValue (SERVER_SESSION_ID_JSON)
                .newColumn ()
                .newColumn ()
                .newColumn ()
                  .addString ("See <code>SKS:createProvisioningSession." +
                              SERVER_SESSION_ID_JSON + "</code> and ")
                  .addLink (PLATFORM_NEGOTIATION_REQUEST_JSON);
          }
      }

    static class OptionalSignature implements JSONBaseHTML.Extender
      {
        @Override
        public Column execute (Column column) throws IOException
          {
            return column
              .newRow ()
                .newColumn ()
                  .addProperty (JSONSignatureEncoder.SIGNATURE_JSON)
                  .addLink (JSONSignatureEncoder.SIGNATURE_JSON)
                .newColumn ()
                  .setType (JSON_TYPE_OBJECT)
                .newColumn ()
                  .setUsage (false)
                .newColumn ()
                  .addString ("<i>Optional</i> X509-based signature covering the request. See ")
                  .addLink (JSONSignatureEncoder.KEY_INFO_JSON);
          }
      }

    static Column preAmble (String qualifier) throws IOException
      {
        return json.addProtocolTable (qualifier)
          .newRow ()
            .newColumn ()
              .addContext (KEYGEN2_NS)
            .newColumn ()
              .setType (JSON_TYPE_URI)
            .newColumn ()
            .newColumn ()
              .addString (KEYGEN2_NAME_SPACE)
          .newRow ()
            .newColumn ()
              .addQualifier (qualifier)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString (OBJECT_ID);
      }

    static class StandardServerClientSessionIDs implements JSONBaseHTML.Extender
      {
        @Override
        public Column execute (Column column) throws IOException
          {
            return column.newExtensionRow (new ServerSessionID ())
              .newRow ()
                .newColumn ()
                  .addProperty (CLIENT_SESSION_ID_JSON)
                  .addSymbolicValue (CLIENT_SESSION_ID_JSON)
                .newColumn ()
                .newColumn ()
                .newColumn ()
                  .addString ("See <code>SKS:createProvisioningSession." +
                              CLIENT_SESSION_ID_JSON + "</code>");
          }
      }
    
    static class SubmitURL implements JSONBaseHTML.Extender
      {
        @Override
        public Column execute (Column column) throws IOException
          {
            return column
              .newRow ()
                .newColumn ()
                  .addProperty (SUBMIT_URL_JSON)
                  .addSymbolicValue (SUBMIT_URL_JSON)
                .newColumn ()
                  .setType (JSON_TYPE_URI)
                .newColumn ()
                .newColumn ()
                  .addString ("Where to POST the response");
          }
      }

    public static void main (String args[]) throws IOException
      {
        if (args.length != 1)
          {
            new RuntimeException ("Missing file argument");
          }
        json = new JSONBaseHTML ();
        preAmble (PROVISIONING_INITIALIZATION_REQUEST_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (SESSION_KEY_ALGORITHM_JSON)
              .addValue (SecureKeyStore.ALGORITHM_SESSION_ATTEST_1)
            .newColumn ()
              .setType (JSON_TYPE_URI)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createProvisioningSession." +
                          SESSION_KEY_ALGORITHM_JSON + "</code>")
          .newExtensionRow (new ServerSessionID ())
          .newRow ()
            .newColumn ()
              .addProperty (SERVER_TIME_JSON)
              .addSymbolicValue (SERVER_TIME_JSON)
            .newColumn ()
              .setType (JSON_TYPE_DATE)
            .newColumn ()
            .newColumn ()
              .addString ("Server time which the client can verify for &quot;sanity&quot;")
          .newExtensionRow (new SubmitURL ())
          .newRow ()
            .newColumn ()
              .addProperty (SESSION_KEY_LIMIT_JSON)
              .addIntegerValue (SESSION_KEY_LIMIT_JSON)
            .newColumn ()
              .setType (JSON_TYPE_SHORT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createProvisioningSession." + SESSION_KEY_LIMIT_JSON + "</code>")
          .newRow ()
            .newColumn ()
              .addProperty (SESSION_LIFE_TIME_JSON)
              .addIntegerValue (SESSION_LIFE_TIME_JSON)
            .newColumn ()
              .setType (JSON_TYPE_INT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createProvisioningSession." + SESSION_LIFE_TIME_JSON + "</code>")
          .newRow ()
            .newColumn ()
              .addProperty (SERVER_EPHEMERAL_KEY_JSON)
              .addLink (SERVER_EPHEMERAL_KEY_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createProvisioningSession." + SERVER_EPHEMERAL_KEY_JSON + "</code>")
          .newRow ()
            .newColumn ()
              .addProperty (KEY_MANAGEMENT_KEY_JSON)
              .addLink (KEY_MANAGEMENT_KEY_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createProvisioningSession." + KEY_MANAGEMENT_KEY_JSON + "</code>")
          .newRow ()
            .newColumn ()
              .addProperty (REQUESTED_CLIENT_ATTRIBUTES_JSON)
              .addArrayList (URI_LIST)
            .newColumn ()
              .setType (JSON_TYPE_URI)
            .newColumn ()
              .setUsage (false, 1)
            .newColumn ()
              .addString ("List of client attribute types (expressed as URI strings) that the client <i>may</i> honor. See ")
              .addLink (PROVISIONING_INITIALIZATION_RESPONSE_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (VIRTUAL_MACHINE_JSON)
              .addLink (VIRTUAL_MACHINE_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString (NOT_READY + " Note that the <code>" +
                          VIRTUAL_MACHINE_JSON +
                          "</code> option presumes that the <code>" +
                          PROVISIONING_INITIALIZATION_REQUEST_JSON + "</code> is <i>signed</i>")
          .newRow ()
            .newColumn ()
              .addProperty (NONCE_JSON)
              .addSymbolicValue (NONCE_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("<i>Optional</i> 1-32 byte nonce. The <code>" +
                           NONCE_JSON + "</code> value <i>must</i> be identical to the <code>" +
                           NONCE_JSON + "</code> specified in ")
               .addLink (PLATFORM_NEGOTIATION_RESPONSE_JSON)
               .addString (". Also see <code>" + JSONSignatureEncoder.SIGNATURE_JSON + "</code>")
          .newExtensionRow (new OptionalSignature ())
              .addString (". Note that <code>" + NONCE_JSON +
                          "</code> <i>must</i> be specified for a signed <code>" +
                          PROVISIONING_INITIALIZATION_REQUEST_JSON + "</code>");

        preAmble (PROVISIONING_INITIALIZATION_RESPONSE_JSON)
          .newExtensionRow (new StandardServerClientSessionIDs ())
          .newRow ()
            .newColumn ()
              .addProperty (SESSION_ATTESTATION_JSON)
              .addSymbolicValue (SESSION_ATTESTATION_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createProvisioningSession." +
                          SESSION_ATTESTATION_JSON + "</code>")
          .newRow ()
            .newColumn ()
              .addProperty (SERVER_TIME_JSON)
              .addSymbolicValue (SERVER_TIME_JSON)
            .newColumn ()
              .setType (JSON_TYPE_DATE)
            .newColumn ()
            .newColumn ()
              .addString ("Server time transferred verbatim from ")
              .addLink (PROVISIONING_INITIALIZATION_REQUEST_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (CLIENT_TIME_JSON)
              .addSymbolicValue (CLIENT_TIME_JSON)
            .newColumn ()
              .setType (JSON_TYPE_DATE)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createProvisioningSession." + CLIENT_TIME_JSON + "</code>")
          .newRow ()
            .newColumn ()
              .addProperty (CLIENT_EPHEMERAL_KEY_JSON)
              .addLink (CLIENT_EPHEMERAL_KEY_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createProvisioningSession." + CLIENT_EPHEMERAL_KEY_JSON + "</code>")
          .newRow ()
            .newColumn ()
              .addProperty (DEVICE_CERTIFICATE_JSON)
              .addLink (DEVICE_CERTIFICATE_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createProvisioningSession</code>")
          .newRow ()
            .newColumn ()
              .addProperty (CLIENT_ATTRIBUTES_JSON)
              .addLink (CLIENT_ATTRIBUTES_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (false, 0)
            .newColumn ()
              .addString ("List of client attribute types and values. See ")
              .addLink (PROVISIONING_INITIALIZATION_REQUEST_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.SIGNATURE_JSON)
              .addLink (JSONSignatureEncoder.SIGNATURE_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("Signature covering the entire response. See <code>" +
                          "SKS:createProvisioningSession</code>");

        preAmble (PROVISIONING_FINALIZATION_REQUEST_JSON)
          .newExtensionRow (new StandardServerClientSessionIDs ())
          .newExtensionRow (new SubmitURL ())
          .newRow ()
            .newColumn ()
              .addProperty (ISSUED_CREDENTIALS_JSON)
              .addArrayLink (ISSUED_CREDENTIALS_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (false, 1)
            .newColumn ()
              .addString ("<i>Optional:</i> List of issued credentials. See <code>" +
                          "SKS:setCertificatePath</code>")
          .newRow ()
            .newColumn ()
              .addProperty (UNLOCK_KEYS_JSON)
              .addArrayLink (UNLOCK_KEYS_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (false, 1)
            .newColumn ()
              .addString ("<i>Optional:</i> List of keys to be unlocked. See <code>" +
                          "SKS:postUnlockKey</code>")
          .newRow ()
            .newColumn ()
              .addProperty (DELETE_KEYS_JSON)
              .addArrayLink (DELETE_KEYS_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (false, 1)
            .newColumn ()
              .addString ("<i>Optional:</i> List of keys to be deleted. See <code>" +
                          "SKS:postDeleteKey</code>")
          .newRow ()
            .newColumn ()
              .addProperty (CHALLENGE_JSON)
              .addSymbolicValue (CHALLENGE_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:closeProvisioningSession</code>")
          .newExtensionRow (new MAC ("closeProvisioningSession"))
          .newExtensionRow (new OptionalSignature ());

        preAmble (PROVISIONING_FINALIZATION_RESPONSE_JSON)
          .newExtensionRow (new StandardServerClientSessionIDs ())
          .newRow ()
            .newColumn ()
              .addProperty (CLOSE_ATTESTATION_JSON)
              .addSymbolicValue (CLOSE_ATTESTATION_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:closeProvisioningSession</code>");

        json.addSubItemTable (KEY_MANAGEMENT_KEY_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.PUBLIC_KEY_JSON)
              .addLink (JSONSignatureEncoder.PUBLIC_KEY_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("Actual key management key")
          .newRow ()
            .newColumn ()
              .addProperty (UPDATABLE_KEY_MANAGEMENT_KEYS_JSON)
              .addArrayLink (UPDATABLE_KEY_MANAGEMENT_KEYS_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (false, 1)
            .newColumn ()
              .addString ("<i>Optional:</i> List of the previous generation of key management keys");

        json.addSubItemTable (UPDATABLE_KEY_MANAGEMENT_KEYS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.PUBLIC_KEY_JSON)
              .addLink (JSONSignatureEncoder.PUBLIC_KEY_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("Previous generation key management key. Note that <code>SKS:updateKeyManagementKey.KeyManagementKey</code>" +
                          " refers to the <i>new</i> key management key specified in the object <i>immediately above</i> (=embedding) this ")
              .addLink (UPDATABLE_KEY_MANAGEMENT_KEYS_JSON)
              .addString (" object")
          .newRow ()
            .newColumn ()
              .addProperty (AUTHORIZATION_JSON)
              .addSymbolicValue (AUTHORIZATION_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("Authorization of the new key management key. See <code>SKS:updateKeyManagementKey.Authorization</code>")
          .newRow ()
            .newColumn ()
              .addProperty (UPDATABLE_KEY_MANAGEMENT_KEYS_JSON)
              .addArrayLink (UPDATABLE_KEY_MANAGEMENT_KEYS_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (false, 1)
            .newColumn ()
              .addString ("<i>Optional:</i> List of the previous generation of key management keys");

        json.addSubItemTable (VIRTUAL_MACHINE_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (TYPE_JSON)
              .addSymbolicValue (TYPE_JSON)
            .newColumn ()
              .setType (JSON_TYPE_URI)
            .newColumn ()
            .newColumn ()
              .addString ("Virtual machine type")
          .newRow ()
            .newColumn ()
              .addProperty (CONFIGURATION_JSON)
              .addSymbolicValue (CONFIGURATION_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("Actual virtual machine setup data")
          .newRow ()
            .newColumn ()
              .addProperty (FRIENDLY_NAME_JSON)
              .addSymbolicValue (FRIENDLY_NAME_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("Virtual machine type");

        json.addSubItemTable (ISSUED_CREDENTIALS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (ID_JSON)
              .addSymbolicValue (ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:setCertificatePath.ID</code>")
              .addString (". Must match the identifier used in ")
              .addLink (KEY_CREATION_REQUEST_JSON)
              .addString (" for a specific key")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.X509_CERTIFICATE_PATH_JSON)
              .addArrayList (SORTED_CERT_PATH)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:setCertificatePath.X509Certificate</code>")
              .addString (". Identical representation as the <code>" +
                          JSONSignatureEncoder.X509_CERTIFICATE_PATH_JSON +
                          "</code> in ")
              .addLink (JSONSignatureEncoder.KEY_INFO_JSON)
            .newExtensionRow (new MAC ("setCertificatePath"))
            .newRow ()
              .newColumn ()
                .addProperty (TRUST_ANCHOR_JSON)
                .addSymbolicValue (TRUST_ANCHOR_JSON)
              .newColumn ()
                .setType (JSON_TYPE_BOOLEAN)
              .newColumn ()
                .setUsage (false)
              .newColumn ()
                .addString ("<i>Optional</i> flag (with the default value <code>false</code>), " +
                            "which tells if <code>" +
                            JSONSignatureEncoder.X509_CERTIFICATE_PATH_JSON +
                            "</code> contains a user-installable trust anchor as well. " +
                            "Trust anchor installation is indepdenent of SKS provisioning")
            .newRow ()
              .newColumn ()
                .addProperty (IMPORT_KEY_JSON)
                .addLink (IMPORT_KEY_JSON)
              .newColumn ()
                .setType (JSON_TYPE_OBJECT)
              .newColumn ()
                .setUsage (false)
              .newColumn ()
                .addString ("<i>Optional</i> key import operation")
            .newExtensionRow (new TargetKeyReference (UPDATE_KEY_JSON, false, "postUpdateKey", true))
            .newExtensionRow (new TargetKeyReference (CLONE_KEY_PROTECTION_JSON, false, "postCloneKeyProtection", false));

        json.addSubItemTable (new String[]{UPDATE_KEY_JSON,
                                           CLONE_KEY_PROTECTION_JSON,
                                           UNLOCK_KEYS_JSON,
                                           DELETE_KEYS_JSON})
          .newRow ()
            .newColumn ()
              .addProperty (CertificateFilter.CF_FINGER_PRINT)
              .addSymbolicValue (CertificateFilter.CF_FINGER_PRINT)
            .newColumn ()
               .setType (JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("SHA256 fingerprint of target certificate")
          .newRow ()
            .newColumn ()
              .addProperty (SERVER_SESSION_ID_JSON)
              .addSymbolicValue (SERVER_SESSION_ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("For locating the target key")
          .newRow ()
            .newColumn ()
              .addProperty (CLIENT_SESSION_ID_JSON)
              .addSymbolicValue (CLIENT_SESSION_ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("For locating the target key")
          .newRow ()
            .newColumn ()
              .addProperty (AUTHORIZATION_JSON)
              .addSymbolicValue (AUTHORIZATION_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("See &quot;Target Key Reference&quot; in the SKS reference")
          .newExtensionRow (new MAC ("post* </code> methods<code>"));
        
        json.addSubItemTable (CLIENT_ATTRIBUTES_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (TYPE_JSON)
              .addSymbolicValue (TYPE_JSON)
            .newColumn ()
               .setType (JSON_TYPE_URI)
            .newColumn ()
            .newColumn ()
              .addString ("Client attribute type URI")
          .newRow ()
            .newColumn ()
              .addProperty (VALUES_JSON)
              .addArrayList (VALUES_JSON)
            .newColumn ()
            .newColumn ()
              .setUsage (true, 1)
            .newColumn ()
              .addString ("List of attributes associated with <code>" + TYPE_JSON + "</code>");

        json.addSubItemTable (DEVICE_CERTIFICATE_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.X509_CERTIFICATE_PATH_JSON)
              .addArrayList (SORTED_CERT_PATH)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("Identical representation as the <code>" +
                          JSONSignatureEncoder.X509_CERTIFICATE_PATH_JSON +
                          "</code> in ")
              .addLink (JSONSignatureEncoder.KEY_INFO_JSON);
        
        json.addSubItemTable (SERVER_EPHEMERAL_KEY_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.PUBLIC_KEY_JSON)
              .addLink (JSONSignatureEncoder.PUBLIC_KEY_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("Must be an EC key matching the capabilities of the SKS");
      
        json.addSubItemTable (CLIENT_EPHEMERAL_KEY_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.PUBLIC_KEY_JSON)
              .addLink (JSONSignatureEncoder.PUBLIC_KEY_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("Must be an EC key matching the capabilities of the SKS");

        json.addJSONSignatureDefinitions ();

        json.writeHTML (args[0]);
      }
  }
