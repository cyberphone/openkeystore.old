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
import org.webpki.crypto.KeyContainerTypes;

import org.webpki.json.JSONBaseHTML;
import org.webpki.json.JSONBaseHTML.RowInterface;
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
    
    static JSONBaseHTML json;
    static RowInterface row;
    
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
                  .addString (".MAC</code>");
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
    
    static class LinkedObject implements JSONBaseHTML.Extender
      {
        String name;
        boolean mandatory;
        String description;
        
        LinkedObject (String name, boolean mandatory, String description)
          {
            this.name = name;
            this.mandatory = mandatory;
            this.description = description;
          }

        @Override
        public Column execute (Column column) throws IOException
          {
            return column
              .newRow ()
                .newColumn ()
                  .addProperty (name)
                  .addLink (name)
                .newColumn ()
                  .setType (JSON_TYPE_OBJECT)
                .newColumn ()
                  .setUsage (mandatory)
                .newColumn ()
                  .addString (description);
          }
      }

    static class OptionalArrayObject implements JSONBaseHTML.Extender
      {
        String name;
        int min;
        String description;
        
        OptionalArrayObject (String name, int min, String description)
          {
            this.name = name;
            this.min = min;
            this.description = description;
          }

        @Override
        public Column execute (Column column) throws IOException
          {
            return column
              .newRow ()
                .newColumn ()
                  .addProperty (name)
                  .addArrayLink (name)
                .newColumn ()
                  .setType (JSON_TYPE_OBJECT)
                .newColumn ()
                  .setUsage (false, min)
                .newColumn ()
                  .addString (description);
          }
      }

    static class BasicCapabilityQuery implements JSONBaseHTML.Extender
      {
        String tag;
        String description;
        
        BasicCapabilityQuery (String tag, String description)
          {
            this.tag = tag;
            this.description = description;
          }

        @Override
        public Column execute (Column column) throws IOException
          {
            return column
              .newRow ()
                .newColumn ()
                  .addProperty (BasicCapabilities.tagName (tag, true))
                  .addArrayList (URI_LIST)
                .newColumn ()
                  .setType (JSON_TYPE_URI)
                .newColumn ()
                  .setUsage (false, 1)
                .newColumn ()
                  .addString (description);
          }
      }

    static class BasicCapabilitySupport implements JSONBaseHTML.Extender
      {
        String tag;
        
        BasicCapabilitySupport (String tag)
          {
            this.tag = tag;
          }

        @Override
        public Column execute (Column column) throws IOException
          {
            return column
              .newRow ()
                .newColumn ()
                  .addProperty (BasicCapabilities.tagName (tag, false))
                  .addArrayList (URI_LIST)
                .newColumn ()
                  .setType (JSON_TYPE_URI)
                .newColumn ()
                  .setUsage (false, 1)
                .newColumn ()
                  .addString ("The result from <code>" + BasicCapabilities.tagName (tag, true) + "</code>.  If there are no matches, the property will not be created");
          }
      }

    static class OptionalArrayList implements JSONBaseHTML.Extender
      {
        String name;
        int min;
        String description;
        
        OptionalArrayList (String name, String description)
          {
            this.name = name;
            this.description = description;
          }
  
        @Override
        public Column execute (Column column) throws IOException
          {
            return column
              .newRow ()
                .newColumn ()
                  .addProperty (name)
                  .addArrayList (name)
                .newColumn ()
                .newColumn ()
                  .setUsage (false, 1)
                .newColumn ()
                  .addString (description);
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

    static void createOption (String property, String type, boolean array_flag, String descrption) throws IOException
      {
        Column column = row.newRow ()
          .newColumn ()
            .addProperty (property);
        if (array_flag)
          {
            column.addArrayList (property);
          }
        else
          {
            column.addSymbolicValue (property);
          }
        column = column.newColumn ().setType (type).newColumn ();
        if (array_flag)
          {
            column.setUsage (false, 1);
          }
        else
          {
            column.setUsage (false);
          }
        row = column.newColumn ().addString (descrption);
      }
    
    static void createSearchFilter () throws IOException
      {
        row = json.addSubItemTable (SEARCH_FILTER_JSON);       
        createOption (CertificateFilter.CF_FINGER_PRINT, JSON_TYPE_BASE64, false, "SHA256 fingerprint matching any certificate in the <i>certificate path</i>");
        createOption (CertificateFilter.CF_ISSUER_REG_EX, JSON_TYPE_STRING, false, "Regular expression matching any issuer in the <i>certificate path</i>");
        createOption (CertificateFilter.CF_SERIAL_NUMBER, JSON_TYPE_BIGINT, false, "Serial number matching that of the <i>end-entity certificate</i>");
        createOption (CertificateFilter.CF_SUBJECT_REG_EX, JSON_TYPE_STRING, false, "Regular expression matching the subject in the <i>end-entity certificate</i>");
        createOption (CertificateFilter.CF_EMAIL_REG_EX, JSON_TYPE_STRING, false, "Regular expression matching any of the e-mail addresses in the <i>end-entity certificate</i>. Note that both RFC822 attributes and <code>subjectAltName</code> fields are in scope");
        createOption (CertificateFilter.CF_POLICY_RULES, JSON_TYPE_STRING, true,
                            "List of X509 policy extension OIDs using the notation <nobr><code>&quot;1.4.3&quot;</code></nobr> and <nobr><code>&quot;-1.4.7&quot;</code></nobr> " +
                            "for a required and forbidden policy OID respectively.  Policy OIDs encountered in <i>end-entity certificates</i> that " +
                            "are not specified in <code>" + CertificateFilter.CF_POLICY_RULES + "</code> are simply <i>ignored</i>");
        createOption (CertificateFilter.CF_KEY_USAGE_RULES, JSON_TYPE_STRING, true,
                            "List of X509 key usage flags using the notation <code>&quot;digitalSignature&quot;</code> and <nobr><code>&quot;-dataEncipherment&quot;</code></nobr> " +
                            "for a required and forbidden key usage respectively.  Key usage flags encountered in <i>end-entity certificates</i> that " +
                            "are not specified in <code>" + CertificateFilter.CF_KEY_USAGE_RULES + "</code> are simply <i>ignored</i>");
        createOption (CertificateFilter.CF_EXT_KEY_USAGE_RULES, JSON_TYPE_STRING, true,
                            "List of X509 extended key usage extension OIDs using the notation <nobr><code>&quot;1.4.3&quot;</code></nobr> and <nobr><code>&quot;-1.4.7&quot;</code></nobr> " +
                            "for a required and forbidden extended key usage respectively.  Extended key usage OIDs encountered in <i>end-entity certificates</i> that " +
                            "are not specified in <code>" + CertificateFilter.CF_EXT_KEY_USAGE_RULES + "</code> are simply <i>ignored</i>");
        createOption (ISSUED_BEFORE_JSON, JSON_TYPE_DATE, false, "Matching <i>end-entity certificates</i> issued before this date. " +
                            "Note that you can combine this criterion with an earlier <code>" + 
                            ISSUED_AFTER_JSON + "</code> criterion, effectively creating a time window");
        createOption (ISSUED_AFTER_JSON, JSON_TYPE_DATE, false, "Matching <i>end-entity certificates</i> issued after this date");
        createOption (GROUPING_JSON, JSON_TYPE_STRING, false, "Matching keys based on the <code>SKS:createPINPolicy." + GROUPING_JSON + "</code> attribute. " +
                            "Note that keys that are not PIN-protected must always fail to match");
        createOption (APP_USAGE_JSON, JSON_TYPE_STRING, false, "Matching keys based on the <code>SKS:createKeyEntry." + APP_USAGE_JSON + "</code> attribute");
      }

    static String getKeyContainers () throws IOException
      {
        StringBuffer s = new StringBuffer ();
        boolean next = false;
        for (KeyContainerTypes kct : KeyContainerTypes.values ())
          {
            s.append (next ? "<li style=\"padding-top:4pt\">" : "<li>");
            next = true;
            String desc;
            switch (kct)
              {
                case SOFTWARE:
                  desc = "Software protected key container";
                  break;

                case EMBEDDED:
                  desc = "Hardware protected embedded key container";
                  break;

                case UICC:
                  desc = "UICC/SIM card";
                  break;

                case SD_CARD:
                  desc = "SD card";
                  break;

                case EXTERNAL:
                  desc = "External/connected key container";
                  break;

                default:
                  throw new IOException ("Unknown KCT");
              }
            s.append ("<code>")
             .append (kct.getName ())
             .append ("</code> - ")
             .append (desc)
             .append ("</li>");
          }
        return s.toString ();
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
              .addString ("Server time which the client should verify as a &quot;sanity&quot; check")
          .newExtensionRow (new SubmitURL ())
          .newRow ()
            .newColumn ()
              .addProperty (SESSION_KEY_LIMIT_JSON)
              .addUnquotedValue (SESSION_KEY_LIMIT_JSON)
            .newColumn ()
              .setType (JSON_TYPE_SHORT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createProvisioningSession." + SESSION_KEY_LIMIT_JSON + "</code>")
          .newRow ()
            .newColumn ()
              .addProperty (SESSION_LIFE_TIME_JSON)
              .addUnquotedValue (SESSION_LIFE_TIME_JSON)
            .newColumn ()
              .setType (JSON_TYPE_INT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createProvisioningSession." + SESSION_LIFE_TIME_JSON + "</code>")
          .newExtensionRow (new LinkedObject (SERVER_EPHEMERAL_KEY_JSON,
                                              true,
                                               "See <code>SKS:createProvisioningSession." +
                                              SERVER_EPHEMERAL_KEY_JSON + "</code>"))
          .newExtensionRow (new LinkedObject (KEY_MANAGEMENT_KEY_JSON,
                                              false,
                                              "See <code>SKS:createProvisioningSession." +
                                              KEY_MANAGEMENT_KEY_JSON + "</code>"))
          .newRow ()
            .newColumn ()
              .addProperty (REQUESTED_CLIENT_ATTRIBUTES_JSON)
              .addArrayList (URI_LIST)
            .newColumn ()
              .setType (JSON_TYPE_URI)
            .newColumn ()
              .setUsage (false, 1)
            .newColumn ()
              .addString ("<i>Optional</i>: List of client attribute types (expressed as URI strings) that the client <i>may</i> honor. See ")
              .addLink (PROVISIONING_INITIALIZATION_RESPONSE_JSON)
          .newExtensionRow (new LinkedObject (VIRTUAL_MACHINE_JSON,
                                              false,
                                              "The <code>" + VIRTUAL_MACHINE_JSON + "</code> option is intended to support BYOD " +
                                              "use-cases where the provisioning process is also used to bootstrap an alternative " +
                                              "environment and associated policies. " +
                                              "The exact nature of this environment is platform-dependent which makes it nessesary " +
                                              "using the <code>" + BasicCapabilities.tagName (BasicCapabilities.BASIC_CAP_EXTENSION, true) + "</code> option to find out what is available. " +
                                              "If&nbsp;the&nbsp;environment is already installed only the configuration should be updated. " +
                                              "Note&nbsp;that&nbsp;the&nbsp;<code>" +
                                              VIRTUAL_MACHINE_JSON +
                                              "</code> option presumes that the <code>" +
                                              PROVISIONING_INITIALIZATION_REQUEST_JSON +
                                              "</code> is <i>signed</i>"))
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
          .newExtensionRow (new LinkedObject (CLIENT_EPHEMERAL_KEY_JSON,
                                              true,
                                              "See <code>SKS:createProvisioningSession." + CLIENT_EPHEMERAL_KEY_JSON + "</code>"))
          .newExtensionRow (new LinkedObject (DEVICE_CERTIFICATE_JSON,
                                              false,
                                              "See <code>SKS:createProvisioningSession</code>"))
          .newRow ()
            .newColumn ()
              .addProperty (SERVER_CERT_FP_JSON)
              .addSymbolicValue (SERVER_CERT_FP_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("SHA256 fingerprint of the server's certificate during receival of the ")
              .addLink (PROVISIONING_INITIALIZATION_REQUEST_JSON)
              .addString (" object. Mandatory for HTTPS connections")
          .newRow ()
            .newColumn ()
              .addProperty (CLIENT_ATTRIBUTES_JSON)
              .addLink (CLIENT_ATTRIBUTES_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (false, 0)
            .newColumn ()
              .addString ("<i>Optional</i>: List of client attribute types and values. See ")
              .addLink (PROVISIONING_INITIALIZATION_REQUEST_JSON)
          .newExtensionRow (new LinkedObject (JSONSignatureEncoder.SIGNATURE_JSON,
                                              true,
                                              "Signature covering the entire response. See <code>" +
                                              "SKS:createProvisioningSession</code>"));

        preAmble (PROVISIONING_FINALIZATION_REQUEST_JSON)
          .newExtensionRow (new StandardServerClientSessionIDs ())
          .newExtensionRow (new SubmitURL ())
          .newExtensionRow (new OptionalArrayObject (ISSUED_CREDENTIALS_JSON,
                                                     1,
                                                     "<i>Optional:</i> List of issued credentials. See <code>" +
                                                     "SKS:setCertificatePath</code>"))
          .newExtensionRow (new OptionalArrayObject (UNLOCK_KEYS_JSON,
                                                     1,
                                                     "<i>Optional:</i> List of keys to be unlocked. See <code>" +
                                                     "SKS:postUnlockKey</code>"))
          .newExtensionRow (new OptionalArrayObject (DELETE_KEYS_JSON,
                                                     1,
                                                     "<i>Optional:</i> List of keys to be deleted. See <code>" +
                                                     "SKS:postDeleteKey</code>"))
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

        preAmble (KEY_CREATION_REQUEST_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (KEY_ENTRY_ALGORITHM_JSON)
              .addValue (SecureKeyStore.ALGORITHM_KEY_ATTEST_1)
            .newColumn ()
              .setType (JSON_TYPE_URI)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." +
                          KEY_ENTRY_ALGORITHM_JSON + "</code>")
          .newExtensionRow (new StandardServerClientSessionIDs ())
          .newExtensionRow (new SubmitURL ())
          .newRow ()
            .newColumn ()
              .addProperty (DEFERRED_CERTIFICATION_JSON)
              .addUnquotedValue (DEFERRED_CERTIFICATION_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BOOLEAN)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("Flag telling if the process should be suspended after ")
              .addLink (KEY_CREATION_RESPONSE_JSON)
              .addString (".  Default value: <code>false</code>. " +
                          "See the <code>" + ACTION_JSON + "</code> property in ")
              .addLink (PLATFORM_NEGOTIATION_REQUEST_JSON)
              
          .newExtensionRow (new OptionalArrayObject (PUK_POLICY_SPECIFIERS_JSON,
                                                     1,
                                                     "List of PUK policy objects to be created. " +
                                                     "See <code>SKS:createPUKPolicy</code>"))
          .newExtensionRow (new OptionalArrayObject (PIN_POLICY_SPECIFIERS_JSON,
                                                     1,
                                                     "List of PIN policy objects to be created. " +
                                                     "See <code>SKS:createPINPolicy</code>"))
          .newExtensionRow (new OptionalArrayObject (KEY_ENTRY_SPECIFIERS_JSON,
                                                     1,
                                                     "List of key entries to be created. " +
                                                     "See <code>SKS:createKeyEntry</code>"))
          .newExtensionRow (new OptionalSignature ());

        preAmble (KEY_CREATION_RESPONSE_JSON)
          .newExtensionRow (new StandardServerClientSessionIDs ())
          .newRow ()
            .newColumn ()
              .addProperty (GENERATED_KEYS_JSON)
              .addArrayLink (GENERATED_KEYS_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (true, 1)
            .newColumn ()
              .addString ("List of generated keys. See <code>SKS:createKeyEntry</code>");

        preAmble (PLATFORM_NEGOTIATION_REQUEST_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (ACTION_JSON)
              .addSymbolicValue (ACTION_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("The <code>" + ACTION_JSON +
                          "</code> property gives (through a suitable GUI dialog) the user a hint of what the session in progess is about to perform. " +
                          "The valid constants are:<ul>" +
                          "<li><code>" + Action.MANAGE.getJSONName () + "</code> - Create, delete and/or update credentials</li>" +
                          "<li style=\"padding-bottom:4pt;padding-top:4pt\"><code>" + Action.RESUME.getJSONName () + "</code> - Resume operation after an interrupted <code>" + KEY_CREATION_RESPONSE_JSON + 
                            "</code>.  See <code>" + DEFERRED_CERTIFICATION_JSON + "</code> in ")
               .addLink (KEY_CREATION_REQUEST_JSON)
               .addString (". A confirming client should after this call only accept a ")
               .addLink (PROVISIONING_FINALIZATION_REQUEST_JSON)
               .addString ("</li>" +
                   "<li><code>" + Action.UNLOCK.getJSONName () + "</code> - Unlock existing keys. A conforming client should disallow ")
               .addLink (KEY_CREATION_REQUEST_JSON)
               .addString ("</li>" +
                   "</ul>")
          .newRow ()
            .newColumn ()
              .addProperty (PRIVACY_ENABLED_JSON)
              .addSymbolicValue (PRIVACY_ENABLED_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BOOLEAN)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("The <code>" + PRIVACY_ENABLED_JSON +
                          "</code> flag serves two purposes:<ul>" +
                          "<li>Give the user a chance to cancel the provisioning operation " +
                          "if the privacy implications of the standard mode are unacceptable</li>" +
                          "<li style=\"padding-top:4pt\">Activate the correct mode during ")
               .addLink (PROVISIONING_INITIALIZATION_REQUEST_JSON)
               .addString ("</li></ul>Note: The default value is <code>false</code>")
          .newExtensionRow (new OptionalArrayList (PREFERREDD_LANGUAGES_JSON,
                                                   "<i>Optional</i>: List of preferred languages using ISO 639-1 two-character notation"))
          .newExtensionRow (new OptionalArrayList (KeyContainerTypes.KCT_TARGET_KEY_CONTAINERS,
                                                   "<i>Optional</i>: List of target key container types.  The elements may be:<ul>" +
                                                   getKeyContainers () +
                                                   "</ul>" +
                                                   "The key containers are listed in preference order. " +
                                                   "If no matching container is available the client may prompt " +
                                                   "the user for inserting a card or similar. If&nbsp;<code>" +
                                                   KeyContainerTypes.KCT_TARGET_KEY_CONTAINERS + "</code> is undefined " +
                                                   "the provisioning client is supposed to use the system's 'native' keystore"))
          .newExtensionRow (new BasicCapabilityQuery (BasicCapabilities.BASIC_CAP_ALGORITHM, "Query the client for support for non-mandatory algorithms"))
          .newExtensionRow (new BasicCapabilityQuery (BasicCapabilities.BASIC_CAP_EXTENSION, "Query the client for support for specific extension objects.  See <code>SKS:addExtension</code>"))
          .newExtensionRow (new BasicCapabilityQuery (BasicCapabilities.BASIC_CAP_CLIENT_ATTRI, "Query the client for support for client attributes like IMEI number. " +
                                                      "If the client has support for " +
                                                      "such attributes it should request the user's permission to disclose them. " +
                                                      "This property is not allowed in the <code>" + PRIVACY_ENABLED_JSON + "</code> mode"))
          .newRow ()
            .newColumn ()
              .addProperty (SERVER_SESSION_ID_JSON)
              .addSymbolicValue (SERVER_SESSION_ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("The <code>" + SERVER_SESSION_ID_JSON +
                          "</code> must remain constant for the entire session")
          .newExtensionRow (new SubmitURL ())
          .newRow ()
            .newColumn ()
              .addProperty (ABORT_URL_JSON)
              .addSymbolicValue (ABORT_URL_JSON)
            .newColumn ()
              .setType (JSON_TYPE_URI)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("Optional URL the provisioning client should launch the browser with if the user cancels the process")
          .newExtensionRow (new OptionalSignature ());

        preAmble (PLATFORM_NEGOTIATION_RESPONSE_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (SERVER_SESSION_ID_JSON)
              .addSymbolicValue (SERVER_SESSION_ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("Copy of <code>" + SERVER_SESSION_ID_JSON +
                          "</code> from ")
              .addLink (PLATFORM_NEGOTIATION_REQUEST_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (NONCE_JSON)
              .addSymbolicValue (NONCE_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("<i>Optional</i> 1-32 byte nonce. See ")
              .addLink (PROVISIONING_INITIALIZATION_REQUEST_JSON)
          .newExtensionRow (new BasicCapabilitySupport (BasicCapabilities.BASIC_CAP_ALGORITHM))
          .newExtensionRow (new BasicCapabilitySupport (BasicCapabilities.BASIC_CAP_EXTENSION))
          .newExtensionRow (new BasicCapabilitySupport (BasicCapabilities.BASIC_CAP_CLIENT_ATTRI))
          .newExtensionRow (new OptionalArrayObject (IMAGE_PREFERENCES_JSON,
                                                     1,
                                                     "List of client image preferences that the server may use for creating suitable "))
            .addLink (LOGOTYPES_JSON);

        preAmble (CREDENTIAL_DISCOVERY_REQUEST_JSON)
          .newExtensionRow (new StandardServerClientSessionIDs ())
          .newExtensionRow (new SubmitURL ())
          .newRow ()
             .newColumn ()
              .addProperty (LOOKUP_SPECIFIERS_JSON)
              .addArrayLink (LOOKUP_SPECIFIERS_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (true, 1)
            .newColumn ()
              .addString ("List of signed credential lookup specifiers. " +
                          "See SKS appendix &quot;Remote Key Lookup&quot; for details")
          .newExtensionRow (new OptionalSignature ());

        preAmble (CREDENTIAL_DISCOVERY_RESPONSE_JSON)
          .newExtensionRow (new StandardServerClientSessionIDs ())
          .newRow ()
            .newColumn ()
              .addProperty (LOOKUP_RESULTS_JSON)
              .addArrayLink (LOOKUP_RESULTS_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (true, 1)
            .newColumn ()
              .addString ("List of credential lookup results. " +
                          "See SKS appendix &quot;Remote Key Lookup&quot; for details");

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
          .newExtensionRow (new OptionalArrayObject (UPDATABLE_KEY_MANAGEMENT_KEYS_JSON,
                            1,
                            "<i>Optional:</i> List of the previous generation " +
                            "of key management keys"));

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
          .newExtensionRow (new OptionalArrayObject (UPDATABLE_KEY_MANAGEMENT_KEYS_JSON,
                            1,
                            "<i>Optional:</i> List of the previous generation of key management keys"));

        json.addSubItemTable (VIRTUAL_MACHINE_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (TYPE_JSON)
              .addSymbolicValue (TYPE_JSON)
            .newColumn ()
              .setType (JSON_TYPE_URI)
            .newColumn ()
            .newColumn ()
              .addString ("Virtual machine type URI")
          .newRow ()
            .newColumn ()
              .addProperty (CONFIGURATION_JSON)
              .addSymbolicValue (CONFIGURATION_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("Virtual machine configuration (setup) data")
          .newRow ()
            .newColumn ()
              .addProperty (FRIENDLY_NAME_JSON)
              .addSymbolicValue (FRIENDLY_NAME_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("Virtual machine friendly name");

        json.addSubItemTable (LOOKUP_SPECIFIERS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (ID_JSON)
              .addSymbolicValue (ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("Each specifier must have a unique ID")
          .newRow ()
            .newColumn ()
              .addProperty (NONCE_JSON)
              .addSymbolicValue (NONCE_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("<code>" + NONCE_JSON + "</code>. " +
                          "See SKS appendix &quot;Remote Key Lookup&quot; for details")
          .newRow ()
            .newColumn ()
              .addProperty (SEARCH_FILTER_JSON)
              .addLink (SEARCH_FILTER_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("<i>Optional</i> additional search criterions. Note that at least one search criterion must be specified if this option is used")
          .newExtensionRow (new LinkedObject (JSONSignatureEncoder.SIGNATURE_JSON,
                            true,
                            "Signature using a key management key signature covering the lookup specifier. " +
                            "See SKS appendix &quot;Remote Key Lookup&quot; for details"));

        json.addSubItemTable (LOOKUP_RESULTS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (ID_JSON)
              .addSymbolicValue (ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("Each result must have a unique ID matching the request")
          .newRow ()
            .newColumn ()
              .addProperty (MATCHING_CREDENTIALS_JSON)
              .addArrayLink (MATCHING_CREDENTIALS_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (true, 0)
            .newColumn ()
              .addString ("List of matching credentials");
        
        json.addSubItemTable (MATCHING_CREDENTIALS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (SERVER_SESSION_ID_JSON)
              .addSymbolicValue (SERVER_SESSION_ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("<code>" + SERVER_SESSION_ID_JSON + "</code> of matching credential")
          .newRow ()
            .newColumn ()
              .addProperty (CLIENT_SESSION_ID_JSON)
              .addSymbolicValue (CLIENT_SESSION_ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("<code>" + CLIENT_SESSION_ID_JSON + "</code> of matching credential")
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

        json.addSubItemTable (PUK_POLICY_SPECIFIERS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (ID_JSON)
              .addSymbolicValue (ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPUKPolicy.ID</code>")
          .newRow ()
            .newColumn ()
              .addProperty (ENCRYPTED_PUK_JSON)
              .addSymbolicValue (ENCRYPTED_PUK_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPUKPolicy.EncryptedPUK</code>")
          .newRow ()
            .newColumn ()
              .addProperty (RETRY_LIMIT_JSON)
              .addUnquotedValue (RETRY_LIMIT_JSON)
            .newColumn ()
              .setType (JSON_TYPE_SHORT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPUKPolicy.RetryLimit</code>")
          .newRow ()
            .newColumn ()
              .addProperty (FORMAT_JSON)
              .addSymbolicValue (FORMAT_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPUKPolicy.Format</code>")
          .newExtensionRow (new MAC ("createPUKPolicy"))
          .newRow ()
            .newColumn ()
              .addProperty (PIN_POLICY_SPECIFIERS_JSON)
              .addArrayLink (PIN_POLICY_SPECIFIERS_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (true, 1)
            .newColumn ()
              .addString ("List of PIN policy objects to be created and controlled by this PUK policy. " +
                          "See <code>SKS:createPINPolicy</code>");

        json.addSubItemTable (PIN_POLICY_SPECIFIERS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (ID_JSON)
              .addSymbolicValue (ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPINPolicy.ID</code>")
          .newRow ()
            .newColumn ()
              .addProperty (MIN_LENGTH_JSON)
              .addUnquotedValue (MIN_LENGTH_JSON)
            .newColumn ()
              .setType (JSON_TYPE_SHORT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPINPolicy.MinLength</code>")
          .newRow ()
            .newColumn ()
              .addProperty (MAX_LENGTH_JSON)
              .addUnquotedValue (MAX_LENGTH_JSON)
            .newColumn ()
              .setType (JSON_TYPE_SHORT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPINPolicy.MaxLength</code>")
          .newRow ()
            .newColumn ()
              .addProperty (RETRY_LIMIT_JSON)
              .addUnquotedValue (RETRY_LIMIT_JSON)
            .newColumn ()
              .setType (JSON_TYPE_SHORT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPINPolicy.RetryLimit</code>")
          .newRow ()
            .newColumn ()
              .addProperty (FORMAT_JSON)
              .addSymbolicValue (FORMAT_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPINPolicy.Format</code>")
          .newRow ()
            .newColumn ()
              .addProperty (USER_MODIFIABLE_JSON)
              .addUnquotedValue (USER_MODIFIABLE_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BOOLEAN)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("Flag with the default value <code>true</code>.  See <code>SKS:createPINPolicy.UserModifiable</code>")
          .newRow ()
            .newColumn ()
              .addProperty (GROUPING_JSON)
              .addSymbolicValue (GROUPING_JSON)
            .newColumn ()
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("Grouping specifier with the default value <code>none</code>.  See <code>SKS:createPINPolicy.Grouping</code>")
          .newRow ()
            .newColumn ()
              .addProperty (INPUT_METHOD_JSON)
              .addSymbolicValue (INPUT_METHOD_JSON)
            .newColumn ()
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("Input method specifier with the default value <code>any</code>.  See <code>SKS:createPINPolicy.InputMethod</code>")
          .newRow ()
            .newColumn ()
              .addProperty (PATTERN_RESTRICTIONS_JSON)
              .addArrayList (PATTERN_RESTRICTIONS_JSON)
            .newColumn ()
            .newColumn ()
              .setUsage (false, 0)
            .newColumn ()
              .addString ("List of pattern restrictions.  See <code>SKS:createPINPolicy.PatternRestrictions</code>")
          .newExtensionRow (new MAC ("createPINPolicy"))
          .newRow ()
            .newColumn ()
              .addProperty (KEY_ENTRY_SPECIFIERS_JSON)
              .addArrayLink (KEY_ENTRY_SPECIFIERS_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (true, 1)
            .newColumn ()
              .addString ("List of key entries to be created and controlled by this PIN policy. " +
                          "See <code>SKS:createKeyEntry</code>");

        json.addSubItemTable (KEY_ENTRY_SPECIFIERS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (ID_JSON)
              .addSymbolicValue (ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry.ID</code>")
          .newRow ()
            .newColumn ()
              .addProperty (ENCRYPTED_PRESET_PIN_JSON)
              .addSymbolicValue (ENCRYPTED_PRESET_PIN_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry.PINValue</code>. " + "" +
              		      "Note that if this property is defined, the " +
              		      "<code>SKS:createPINPolicy.UserDefined</code> " +
              		      "flag of the required embedding PIN policy is set to <code>false</code> else it is set to <code>true</code>")
          .newRow ()
            .newColumn ()
              .addProperty (ENABLE_PIN_CACHING_JSON)
              .addUnquotedValue (ENABLE_PIN_CACHING_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BOOLEAN)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("Flag with the default value <code>false</code>. " +
                          "See <code>SKS:createKeyEntry." + ENABLE_PIN_CACHING_JSON + "</code>")
          .newRow ()
            .newColumn ()
              .addProperty (DEVICE_PIN_PROTECTION_JSON)
              .addUnquotedValue (DEVICE_PIN_PROTECTION_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BOOLEAN)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("Flag with the default value <code>false</code>. " +
                          "See <code>SKS:createKeyEntry." + DEVICE_PIN_PROTECTION_JSON + "</code>. " +
                          "This flag (if true) cannot be combined with PIN policy settings")
          .newRow ()
            .newColumn ()
              .addProperty (APP_USAGE_JSON)
              .addSymbolicValue (APP_USAGE_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." + APP_USAGE_JSON + "</code>")
          .newRow ()
            .newColumn ()
              .addProperty (KEY_ALGORITHM_JSON)
              .addSymbolicValue (KEY_ALGORITHM_JSON)
            .newColumn ()
              .setType (JSON_TYPE_URI)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." + KEY_ALGORITHM_JSON + "</code>")
          .newRow ()
            .newColumn ()
              .addProperty (KEY_PARAMETERS_JSON)
              .addSymbolicValue (KEY_PARAMETERS_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." + KEY_PARAMETERS_JSON + "</code>")
          .newRow ()
            .newColumn ()
              .addProperty (ENDORSED_ALGORITHMS_JSON)
              .addArrayList (ENDORSED_ALGORITHMS_JSON)
            .newColumn ()
              .setType (JSON_TYPE_URI)
            .newColumn ()
              .setUsage (false, 0)
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry.EndorsedAlgorithm</code>")
          .newRow ()
            .newColumn ()
              .addProperty (SERVER_SEED_JSON)
              .addSymbolicValue (SERVER_SEED_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." + SERVER_SEED_JSON + "</code>.  " +
                          "If this property is undefined, it is assumed (by KeyGen2) to be a zero-length array")
          .newRow ()
            .newColumn ()
              .addProperty (BIOMETRIC_PROTECTION_JSON)
              .addSymbolicValue (BIOMETRIC_PROTECTION_JSON)
            .newColumn ()
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." + BIOMETRIC_PROTECTION_JSON + "</code>. " +
                          "If this property is undefined, it is assumed (by KeyGen2) to be <code>none</none>")
          .newRow ()
            .newColumn ()
              .addProperty (DELETE_PROTECTION_JSON)
              .addSymbolicValue (DELETE_PROTECTION_JSON)
            .newColumn ()
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." + DELETE_PROTECTION_JSON + "</code>. " +
                          "If this property is undefined, it is assumed (by KeyGen2) to be <code>none</none>")
          .newRow ()
            .newColumn ()
              .addProperty (EXPORT_PROTECTION_JSON)
              .addSymbolicValue (EXPORT_PROTECTION_JSON)
            .newColumn ()
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." + EXPORT_PROTECTION_JSON + "</code>. " +
                          "If this property is undefined, it is assumed (by KeyGen2) to be <code>non-exportable</none>")
          .newRow ()
            .newColumn ()
              .addProperty (FRIENDLY_NAME_JSON)
              .addSymbolicValue (FRIENDLY_NAME_JSON)
            .newColumn ()
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." + FRIENDLY_NAME_JSON + "</code>")
          .newExtensionRow (new MAC ("createKeyEntry"));

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
              .addUnquotedValue (TRUST_ANCHOR_JSON)
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
          .newExtensionRow (new LinkedObject (IMPORT_KEY_JSON,
                                              false,
                                              "<i>Optional</i> key import operation"))
          .newExtensionRow (new TargetKeyReference (UPDATE_KEY_JSON, false, "postUpdateKey", true))
          .newExtensionRow (new TargetKeyReference (CLONE_KEY_PROTECTION_JSON, false, "postCloneKeyProtection", false))
          .newExtensionRow (new OptionalArrayObject (EXTENSIONS_JSON,
              1,
              "<i>Optional:</i> List of extension objects. See <code>" +
              "SKS:addExtension</code>"))
          .newExtensionRow (new OptionalArrayObject (ENCRYPTED_EXTENSIONS_JSON,
              1,
              "<i>Optional:</i> List of encrypted extension objects. See <code>" +
              "SKS:addExtension</code>"))
          .newExtensionRow (new OptionalArrayObject (PROPERTY_BAGS_JSON,
              1,
              "<i>Optional:</i> List of property objects. See <code>" +
              "SKS:addExtension</code>"))
          .newExtensionRow (new OptionalArrayObject (LOGOTYPES_JSON,
              1,
              "<i>Optional:</i> List of logotype objects. See <code>" +
              "SKS:addExtension</code>"));

        json.addSubItemTable (GENERATED_KEYS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (ID_JSON)
              .addSymbolicValue (ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("Must match the identifier used in ")
              .addLink (KEY_CREATION_REQUEST_JSON)
              .addString (" for a specific key")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.PUBLIC_KEY_JSON)
              .addLink (JSONSignatureEncoder.PUBLIC_KEY_JSON)
            .newColumn ()
              .setType (JSON_TYPE_OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry.PublicKey</code>")
          .newRow ()
            .newColumn ()
              .addProperty (KEY_ATTESTATION_JSON)
              .addSymbolicValue (KEY_ATTESTATION_JSON)
            .newColumn ()
              .setType (JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry.KeyAttestation</code>");

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
        
        json.addSubItemTable (new String[]{EXTENSIONS_JSON,
                                           ENCRYPTED_EXTENSIONS_JSON})
          .newRow ()
            .newColumn ()
              .addProperty (TYPE_JSON)
              .addSymbolicValue (TYPE_JSON)
            .newColumn ()
               .setType (JSON_TYPE_URI)
            .newColumn ()
            .newColumn ()
              .addString ("Extension type URI")
          .newRow ()
            .newColumn ()
              .addProperty (EXTENSION_DATA_JSON)
              .addSymbolicValue (EXTENSION_DATA_JSON)
            .newColumn ()
               .setType (JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("Extension data")
          .newExtensionRow (new MAC ("addExtension"));

        json.addSubItemTable (LOGOTYPES_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (TYPE_JSON)
              .addSymbolicValue (TYPE_JSON)
            .newColumn ()
               .setType (JSON_TYPE_URI)
            .newColumn ()
            .newColumn ()
              .addString ("Logotype type URI")
          .newRow ()
            .newColumn ()
              .addProperty (MIME_TYPE_JSON)
              .addSymbolicValue (MIME_TYPE_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("Logotype MIME type")
          .newRow ()
            .newColumn ()
              .addProperty (EXTENSION_DATA_JSON)
              .addSymbolicValue (EXTENSION_DATA_JSON)
            .newColumn ()
               .setType (JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("Logotype image data")
          .newExtensionRow (new MAC ("addExtension"));

        json.addSubItemTable (IMAGE_PREFERENCES_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (TYPE_JSON)
              .addSymbolicValue (TYPE_JSON)
            .newColumn ()
               .setType (JSON_TYPE_URI)
            .newColumn ()
            .newColumn ()
              .addString ("Logotype type URI")
          .newRow ()
            .newColumn ()
              .addProperty (MIME_TYPE_JSON)
              .addSymbolicValue (MIME_TYPE_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("Logotype MIME type")
          .newRow ()
            .newColumn ()
              .addProperty (WIDTH_JSON)
              .addSymbolicValue (WIDTH_JSON)
            .newColumn ()
               .setType (JSON_TYPE_INT)
            .newColumn ()
            .newColumn ()
              .addString ("Logotype width")
          .newRow ()
            .newColumn ()
              .addProperty (HEIGHT_JSON)
              .addSymbolicValue (HEIGHT_JSON)
            .newColumn ()
               .setType (JSON_TYPE_INT)
            .newColumn ()
            .newColumn ()
              .addString ("Logotype height");

        json.addSubItemTable (PROPERTY_BAGS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (TYPE_JSON)
              .addSymbolicValue (TYPE_JSON)
            .newColumn ()
               .setType (JSON_TYPE_URI)
            .newColumn ()
            .newColumn ()
              .addString ("Property bag type URI")
          .newRow ()
            .newColumn ()
              .addProperty (PROPERTIES_JSON)
              .addArrayLink (PROPERTIES_JSON)
            .newColumn ()
               .setType (JSON_TYPE_OBJECT)
            .newColumn ()
               .setUsage (true, 1)
            .newColumn ()
              .addString ("List of property values")
          .newExtensionRow (new MAC ("addExtension"));

        json.addSubItemTable (PROPERTIES_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (NAME_JSON)
              .addSymbolicValue (NAME_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("Property name")
          .newRow ()
            .newColumn ()
              .addProperty (VALUE_JSON)
              .addSymbolicValue (VALUE_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("Property value")
          .newRow ()
            .newColumn ()
              .addProperty (WRITABLE_JSON)
              .addUnquotedValue (WRITABLE_JSON)
            .newColumn ()
               .setType (JSON_TYPE_BOOLEAN)
            .newColumn ()
               .setUsage (false)
            .newColumn ()
              .addString ("Writable flag. Default is <code>false</code>");

        json.addSubItemTable (IMPORT_KEY_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (SYMMETRIC_KEY_JSON)
              .addSymbolicValue (SYMMETRIC_KEY_JSON)
            .newColumn ()
               .setType (JSON_TYPE_BASE64)
            .newColumn ()
               .setChoice (true, 2)
            .newColumn ()
              .addString ("Encrypted symmetric key")
          .newRow ()
            .newColumn ()
              .addProperty (PRIVATE_KEY_JSON)
              .addSymbolicValue (PRIVATE_KEY_JSON)
            .newColumn ()
               .setType (JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("Encrypted PKCS #8 object")
          .newExtensionRow (new MAC ("import* </code> methods<code>"));

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
