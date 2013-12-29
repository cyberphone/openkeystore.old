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

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.KeyContainerTypes;
import org.webpki.crypto.KeyUsageBits;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.MACAlgorithms;

import org.webpki.json.JSONBaseHTML;
import org.webpki.json.JSONBaseHTML.RowInterface;
import org.webpki.json.JSONBaseHTML.ProtocolObject.Row.Column;
import org.webpki.json.JSONSignatureDecoder;

import org.webpki.sks.SecureKeyStore;

/**
 * Create an HTML description of the current KeyGen2 protocol.
 * 
 * @author Anders Rundgren
 */
public class KeyGen2HTMLReference extends JSONBaseHTML.Types
  {
    static final String KEYGEN2_NAME_SPACE            = "KeyGen2 name space/version indicator.";
    static final String OBJECT_ID                     = "Actual KeyGen2 message type.";

    static JSONBaseHTML json;
    static RowInterface row;
    
    static class ProtocolDescription
      {
        static final String BAR_COLOR = "#909090";
        
        StringBuffer s;
        ProtocolDescription (StringBuffer s)
          {
            this.s = s;
          }
        void execute ()
          {
            s.append ("This chapter contains a high-level description of the KeyGen2 protocol "+
                "while the subsequent chapters cover the actual format. " + LINE_SEPARATOR +
                "To facilitate a straightforward implementation as well as robust operation, KeyGen2 builds on a concept where each major process " +
                "step is handled by a specific request/response pair as outlined below:" + 
                      "<table style=\"width:600pt;margin-top:10pt;margin-left:auto;margin-right:auto;border-collapse:collapse\">");
            bar (10);
            sign ("PlatformNegotiation", "Protocol invocation. During this step the user should be alerted by a browser-defined dialog " +
                  "telling what is supposed to happen giving as well as providing an option aborting the process. "+
                  "In addition, the issuer <i>may</i> perform an SKS capability query.");
            bar (14);
            sign ("ProvisioningInitialization", "Creation of a <i>shared session key</i> securing the rest of the interactions between the issuer and the SKS. " +
                  "To support future updates of provisioned credentials, the issuer <i>may</i> also provide a " + json.globalLinkRef (PROVISIONING_INITIALIZATION_REQUEST_JSON, KEY_MANAGEMENT_KEY_JSON) + ".");
            bar (14);
            sign ("CredentialDiscovery", "<i>Optional</i>: Issuer lookup of already provisioned SKS credentials. " +
                  "This is primarily used when keys need to be updated or unlocked.");
            bar (14);
            sign ("KeyCreation", "Creation of asymmetric key-pairs in the SKS. " +
                  "If user-defined PINs are to be set, this is carried out during " + json.globalLinkRef (KEY_CREATION_REQUEST_JSON) + ". " +
                  "After key-pairs have been created the public keys are sent to the issuer for certification.");
            bar (14);
            sign ("ProvisioningFinalization", "Deployment of credentials and associated attributes. " +
                  "Key&nbsp;management operations are also performed in this step. " +
                  "After that the session is terminated. " +
                  "Due to the &quot;transactional&quot; nature of SKS, <i>successful</i> session termination returns a cryptographic proof to the " +
                  "issuer.");
            bar (6);
            s.append ("<tr><td style=\"padding:0px\"><div style=\"margin-left:auto;margin-right:auto;width:0pt;height:0px;border-style: solid;border-width: 8pt 4pt 0pt 4pt" +
                      ";border-color:" + BAR_COLOR + " transparent transparent transparent\"></div></td><td></td></tr></table>" +
                      "Not elaborated on here is the result of the " + json.globalLinkRef (PROVISIONING_FINALIZATION_RESPONSE_JSON) +
                      " because it is anticipated to be a custom HTML page, typically telling the user that the operation succeeded.");
          }

        private void sign (String protcol_step, String description)
          {
            s.append ("<tr><td style=\"padding:0px\"><div style=\"padding:20pt;font-size:14pt;text-align:center;" +
//                      "background: radial-gradient(ellipse at center, rgba(252,246,239,1) 12%,rgba(252,217,174,1) 100%)" +
//                      "background: radial-gradient(ellipse at center, rgba(249,246,229,1) 9%,rgba(247,221,170,1) 100%)" +
//                      "background: radial-gradient(ellipse at center, rgba(242,243,252,1) 0%,rgba(196,210,242,1) 100%)" +
                      "background: radial-gradient(ellipse at center, rgba(255,255,255,1) 0%,rgba(242,243,252,1) 38%,rgba(196,210,242,1) 100%)" +
                      ";border-radius:8pt;border-width:1px;border-style:solid;border-color:#B0B0B0;box-shadow:3pt 3pt 3pt #D0D0D0\">")
            .append (protcol_step)
            .append ("</div></td><td style=\"padding-left:20pt\">")
            .append (description)
            .append ("</td></tr>");
          }

        private void bar (int height)
          {
            s.append ("<tr><td style=\"padding:0px\"><div style=\"margin-left:auto;margin-right:auto;height:")
             .append (height)
             .append ("pt;width:2pt;background-color:" + BAR_COLOR + "\"></div></td><td></td></tr>");
          }
      }
    
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
                  .setType (WEBPKI_DATA_TYPES.BASE64)
                .newColumn ()
                .newColumn ()
                  .addString ("Caller authentication. See <code>SKS:")
                  .addString (sks_method)
                  .addString (".MAC</code>.");
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
            column = (array_flag ? column.addArrayLink (json_tag, 1) : column.addLink (json_tag))
                .newColumn ()
                  .setType (WEBPKI_DATA_TYPES.OBJECT)
                .newColumn ();
            if (optional_group)
              {
                column.setChoice (false, 2);
              }
            return column
                .newColumn ()
                  .addString ("<i>Optional</i>: See <code>SKS:")
                  .addString (sks_method)
                  .addString ("</code>.");
          }
      }
    
    static class LinkedObject implements JSONBaseHTML.Extender
      {
        String name;
        boolean mandatory;
        String description;
        int choice_length;
        
        LinkedObject (String name, boolean mandatory, String description, int choice_length)
          {
            this.name = name;
            this.mandatory = mandatory;
            this.description = description;
            this.choice_length = choice_length;
          }

        LinkedObject (String name, boolean mandatory, String description)
          {
            this (name, mandatory,description, 0);
          }

        @Override
        public Column execute (Column column) throws IOException
          {
            column = column
              .newRow ()
                .newColumn ()
                  .addProperty (name)
                  .addLink (name)
                .newColumn ()
                  .setType (WEBPKI_DATA_TYPES.OBJECT)
                .newColumn ();
            if (choice_length  == 0)
              {
                column.setUsage (mandatory);
              }
            else
              {
                column.setChoice (mandatory, choice_length);
              }
            return column
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
                  .addArrayLink (name, min)
                .newColumn ()
                  .setType (WEBPKI_DATA_TYPES.OBJECT)
                .newColumn ()
                  .setUsage (false)
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
                  .addArrayList (URI_LIST, 1)
                .newColumn ()
                  .setType (WEBPKI_DATA_TYPES.URI)
                .newColumn ()
                  .setUsage (false)
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
                  .addArrayList (URI_LIST, 1)
                .newColumn ()
                  .setType (WEBPKI_DATA_TYPES.URI)
                .newColumn ()
                  .setUsage (false)
                .newColumn ()
                  .addString ("The result from <code>" + BasicCapabilities.tagName (tag, true) + 
                              "</code>.  If there are no matches, this property <b>must not</b> be present.");
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
                  .addArrayList (name, 1)
                .newColumn ()
                .newColumn ()
                  .setUsage (false)
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
                  .setType (WEBPKI_DATA_TYPES.ID)
                .newColumn ()
                .newColumn ()
                  .addString ("See <code>SKS:createProvisioningSession." +
                              SERVER_SESSION_ID_JSON + "</code> and ")
                  .addLink (PLATFORM_NEGOTIATION_REQUEST_JSON)
                  .addString (".");
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
                  .addProperty (JSONSignatureDecoder.SIGNATURE_JSON)
                  .addLink (JSONSignatureDecoder.SIGNATURE_JSON)
                .newColumn ()
                  .setType (WEBPKI_DATA_TYPES.OBJECT)
                .newColumn ()
                  .setUsage (false)
                .newColumn ()
                  .addString ("<i>Optional</i> X509-based signature covering the request. See ")
                  .addLink (JSONSignatureDecoder.KEY_INFO_JSON)
                  .addString (".");
          }
      }

    static Column preAmble (String qualifier) throws IOException
      {
        return json.addProtocolTable (qualifier)
          .newRow ()
            .newColumn ()
              .addContext (KEYGEN2_NS)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.URI)
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
                  .setType (WEBPKI_DATA_TYPES.ID)
                .newColumn ()
                .newColumn ()
                  .addString ("See <code>SKS:createProvisioningSession." +
                              CLIENT_SESSION_ID_JSON + "</code>.");
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
                  .setType (WEBPKI_DATA_TYPES.URI)
                .newColumn ()
                .newColumn ()
                  .addString ("Where to POST the response.");
          }
      }

    static void createOption (String property, WEBPKI_DATA_TYPES type, boolean array_flag, String descrption) throws IOException
      {
        Column column = row.newRow ()
          .newColumn ()
            .addProperty (property);
        if (array_flag)
          {
            column.addArrayList (property, 1);
          }
        else
          {
            column.addSymbolicValue (property);
          }
        column = column.newColumn ().setType (type).newColumn ();
        column.setUsage (false);
        row = column.newColumn ().addString (descrption);
      }
    
    static void createSearchFilter () throws IOException
      {
        row = json.addSubItemTable (SEARCH_FILTER_JSON);       
        createOption (CertificateFilter.CF_FINGER_PRINT, WEBPKI_DATA_TYPES.BASE64, false, "SHA256 fingerprint matching any certificate in the <i>certificate path</i>.");
        createOption (CertificateFilter.CF_ISSUER_REG_EX, WEBPKI_DATA_TYPES.STRING, false, 
            "Regular expression matching any issuer in the <i>certificate path</i>. " +
            "Issuer names are assumed to be expressed in LDAP " + json.createReference (JSONBaseHTML.REF_LDAP_NAME) + " notation.");
        createOption (CertificateFilter.CF_SERIAL_NUMBER, WEBPKI_DATA_TYPES.BIGINT, false, "Serial number matching that of the <i>end-entity certificate</i>.");
        createOption (CertificateFilter.CF_SUBJECT_REG_EX, WEBPKI_DATA_TYPES.STRING, false, 
            "Regular expression matching the subject in the <i>end-entity certificate</i>. " + 
            "Subject names are assumed to be expressed in LDAP " + json.createReference (JSONBaseHTML.REF_LDAP_NAME) + " notation.");
        createOption (CertificateFilter.CF_EMAIL_REG_EX, WEBPKI_DATA_TYPES.STRING, false, "Regular expression matching any of the e-mail addresses in the <i>end-entity certificate</i>." + LINE_SEPARATOR +
                            "Note that both RFC&nbsp;822 subject attributes and <code>subjectAltName</code> fields are in scope.");
        createOption (CertificateFilter.CF_POLICY_RULES, WEBPKI_DATA_TYPES.STRING, true,
                            "List of X.509 policy extension OIDs using the notation <code style=\"white-space:nowrap\">&quot;1.4.3&quot;</code> and <code style=\"white-space:nowrap\">&quot;-1.4.7&quot;</code> " +
                            "for a required and forbidden policy OID respectively." + LINE_SEPARATOR +
                            "Policy OIDs encountered in <i>end-entity certificates</i> that " +
                            "are not specified in <code>" + CertificateFilter.CF_POLICY_RULES + "</code> <b>must</b> be <i>ignored</i>.");
        createOption (CertificateFilter.CF_KEY_USAGE_RULES, WEBPKI_DATA_TYPES.STRING, true,
                            "List of X.509 key usage flags using the notation <code>&quot;" +
                            KeyUsageBits.DIGITAL_SIGNATURE.getX509Name () + "&quot;</code> and <code style=\"white-space:nowrap\">&quot;-" +
                            KeyUsageBits.DATA_ENCIPHERMENT.getX509Name () + "&quot;</code> " +
                            "for a required and forbidden key usage respectively." + LINE_SEPARATOR +
                            "Key usage flags encountered in <i>end-entity certificates</i> that " +
                            "are not specified in <code>" + CertificateFilter.CF_KEY_USAGE_RULES + "</code> <b>must</b> be <i>ignored</i>. " + LINE_SEPARATOR +
                            "The set of permitted flags include:" + getKeyUsageBits ());
        createOption (CertificateFilter.CF_EXT_KEY_USAGE_RULES, WEBPKI_DATA_TYPES.STRING, true,
                            "List of X.509 extended key usage extension OIDs using the notation <code style=\"white-space:nowrap\">&quot;1.4.3&quot;</code> and <code style=\"white-space:nowrap\">&quot;-1.4.7&quot;</code> " +
                            "for a required and forbidden extended key usage respectively." + LINE_SEPARATOR +
                            "Extended key usage OIDs encountered in <i>end-entity certificates</i> that " +
                            "are not specified in <code>" + CertificateFilter.CF_EXT_KEY_USAGE_RULES + "</code> <b>must</b> be <i>ignored</i>.");
        createOption (ISSUED_BEFORE_JSON, WEBPKI_DATA_TYPES.DATE, false, "Matching <i>end-entity certificates</i> issued before this date." + LINE_SEPARATOR +
                            "Note that you can combine this criterion with an <code>" + 
                            ISSUED_AFTER_JSON + "</code> criterion using an earlier date, effectively creating a time window.");
        createOption (ISSUED_AFTER_JSON, WEBPKI_DATA_TYPES.DATE, false, "Matching <i>end-entity certificates</i> issued after this date.");
        createOption (GROUPING_JSON, WEBPKI_DATA_TYPES.STRING, false, "Matching keys based on the <code>SKS:createPINPolicy." + GROUPING_JSON + "</code> attribute." + LINE_SEPARATOR +
                            "Note that keys that are not PIN-protected <b>must</b> always fail to match.");
        createOption (APP_USAGE_JSON, WEBPKI_DATA_TYPES.STRING, false, "Matching keys based on the <code>SKS:createKeyEntry." + APP_USAGE_JSON + "</code> attribute.");
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


    static void getLogotype (StringBuffer s, String type, boolean li_add, String comment)
      {
        s.append ("<li")
         .append (li_add ? " style=\"padding-top:4pt\"" : "")
         .append ("><code>")
         .append (type)
         .append ("</code><br>")
         .append (comment)
         .append ("</li>");
      }


    static String getLogotypes ()
      {
        StringBuffer s = new StringBuffer ();
        getLogotype (s, KeyGen2URIs.LOGOTYPES.LIST, false, "This type is meant to be " +
                    "used in credential lists and management dialogs where you could use a " +
                    "logotype together with a &quot;friendly name&quot; string or similar.");
        getLogotype (s, KeyGen2URIs.LOGOTYPES.CARD, true, "A shape designed for wallet-like applications where logotypes usually are personalized.");
        getLogotype (s, KeyGen2URIs.LOGOTYPES.ICON, true, "Intended for selection windows " +
                    "holding large collections of credentials featured as maps or lists of <i>small</i> icons.");
        getLogotype (s, KeyGen2URIs.LOGOTYPES.APPLICATION, true, "Could be used in applications where a " +
                    "logotype is useful for branding/recognition purposes like in OTP systems.");
        return s.toString ();
      }


    static void getListAttribute (StringBuffer s, String attribute)
      {
        s.append ("<li><code>")
         .append (attribute)
         .append ("</code></li>");
      }

    static String clientAttributes ()
      {
        StringBuffer s = new StringBuffer ();
        getListAttribute (s, KeyGen2URIs.CLIENT_ATTRIBUTES.IMEI_NUMBER);
        getListAttribute (s, KeyGen2URIs.CLIENT_ATTRIBUTES.IP_ADDRESS);
        getListAttribute (s, KeyGen2URIs.CLIENT_ATTRIBUTES.MAC_ADDRESS);
        getListAttribute (s, KeyGen2URIs.CLIENT_ATTRIBUTES.OS_VENDOR);
        getListAttribute (s, KeyGen2URIs.CLIENT_ATTRIBUTES.OS_VERSION);
        return s.toString ();
      }

    static String getKeyUsageBits ()
      {
        StringBuffer s = new StringBuffer ("<ul>");
        for (KeyUsageBits kub : KeyUsageBits.values ())
          {
            getListAttribute (s, kub.getX509Name ());
          }
        return s.append ("</ul>").toString ();
      }

    public static void main (String args[]) throws IOException
      {
        if (args.length != 1)
          {
            new RuntimeException ("Missing file argument");
          }
        json = new JSONBaseHTML (args, "KeyGen2 - Credential Enrollment and Management Protocol");
        
        json.addParagraphObject ().append ("<div style=\"margin-top:200pt;margin-bottom:200pt;text-align:center\"><span style=\"" + JSONBaseHTML.HEADER_STYLE + "\">KeyGen2</span>" +
             "<br><span style=\"font-size:" + JSONBaseHTML.CHAPTER_FONT_SIZE + "\">&nbsp;<br>Credential Enrollment and Management Protocol</span></div>");
        
        json.niceSquare ("<i>Disclaimer</i>: This is a system in development. That is, the specification may change without notice.", 20);
        
        json.addTOC ();
        
        json.addParagraphObject ("Introduction").append ("KeyGen2 is a web-based protocol for enrolling and managing credentials like X.509 certificates ")
            .append (json.createReference (JSONBaseHTML.REF_X509))
            .append (". " +
                     "The protocol is a part of a security architecture which at the core " +
                     "consists of SKS (Secure Key Store) ")
            .append (json.createReference (JSONBaseHTML.REF_SKS))
            .append ("." + LINE_SEPARATOR + " The KeyGen2 protocol is expressed as a set of JSON ")
            .append (json.createReference (JSONBaseHTML.REF_JSON))
            .append (" objects. " +
                     "This document contains a description of these objects and how they interact, " +
                     "while the integration with the SKS API is dealt with in the SKS architecture document ")
            .append (json.createReference (JSONBaseHTML.REF_SKS))
            .append ("." + LINE_SEPARATOR +
                     "Parts of the protocol rely on cryptographic constructs using JSON which " +
                     "initially were created for the KeyGen2 project, but later became an activity "+
                     "of its own: JSON Cleartext Signature ")
             .append (json.createReference (JSONBaseHTML.REF_JCS))
             .append ("." + LINE_SEPARATOR +
                      "Finding the proper balance in a complex scheme like KeyGen2 is a combination of &quot;gut feeling&quot;, " +
                      "political considerations, available technology, foresight and market research. " +
                      "If this particular specification hit the right level only time can tell." +
                      "<table style=\"margin-top:20pt;margin-bottom:20pt;margin-left:auto;margin-right:auto;text-align:center\">" +
                      "<tr><td>&quot;<i>Perfection&nbsp;is&nbsp;achieved,&nbsp;not&nbsp;when&nbsp;there&nbsp;is&nbsp;" +
                      "nothing&nbsp;more<br>to&nbsp;add,&nbsp;but&nbsp;when&nbsp;there&nbsp;is&nbsp;nothing&nbsp;left&nbsp;to&nbsp;take&nbsp;away</i>&quot;</td></tr>" +
                      "<tr><td style=\"padding-top:4pt;font-size:8pt;text-align:right\">Antoine de Saint-Exup\u00e9ry</td></tr></table>");

        json.addParagraphObject ("Proxy Scheme").append ("Unlike certificate management protocols like CMP ")
            .append (json.createReference (JSONBaseHTML.REF_CMP))
            .append (", <i>KeyGen2 " +
                     "mandates a two-layer client architecture</i> where the " +
                     "outermost part is talking to the outside world (user and issuer), " +
                     "while an inner part does the communication with the SKS. " +
                     "That is, the client implementation acts as &quot;proxy&quot; enabling the use of a cleartext, JSON-based, " +
                     "fairly high-level protocol with issuer, in spite of the fact that SKS only deals with " +
                     "low-level binary data." + LINE_SEPARATOR +
                     "Another core proxy task is minimizing network roundtrips through SKS command aggregation." + LINE_SEPARATOR +
                     "Although KeyGen2 depends on a proxy for doing the &quot;Heavy Lifting&quot;, " +
                     "E2ES (End To End Security) is achieved through the use of a <i>dynamically created shared secret</i>, " +
                     "which is only known by the SKS and the issuer. " +LINE_SEPARATOR +
                     "For a detailed description of the proxy scheme and the E2ES solution, consult the SKS architecture document ")
            .append (json.createReference (JSONBaseHTML.REF_SKS))
            .append (".");

        new ProtocolDescription (json.addParagraphObject ("Protocol Description")).execute ();
        
        json.addParagraphSubObject ("Invocation").append ("TBD");

        json.addParagraphSubObject ("Error Handling").append ("TBD");
        
        json.addParagraphSubObject ("Key Management Operations").append ("TBD");

        json.addParagraphSubObject ("Deferred Issuance").append ("TBD");

        json.addDataTypesDescription ("");
        
        json.addProtocolTableEntry ("Objects").append ("The following tables describe the KeyGen2 JSON structures in detail." + LINE_SEPARATOR +
                           "Entries written in <i>italics</i> represent sub objects, while the other entries consitute of the actual messages.");
        
        json.setAppendixMode ();
        
        json.sampleRun (KeyGen2HTMLReference.class,
                        "In the following KeyGen2 sample run the client (platform) " +
                        "suggests a suitable image size for logotypes associated with keys." + LINE_SEPARATOR +
                        "Then the issuer requests that the client (SKS) creates an RSA 2048-bit key " +
                        "protected by a user-set PIN governed by a number of issuer-defined policies." + LINE_SEPARATOR +
                        "Finally, the issuer provides a certificate and and a logotype to go with it." + LINE_SEPARATOR +
                        "For information regarding the cryptographic constructs, consult the SKS architecture manual.",
                        new String[]{"PlatformNegotiationRequest.json",
                                     "PlatformNegotiationResponse.json",
                                     "ProvisioningInitializationRequest.json",
                                     "ProvisioningInitializationResponse.json",
                                     "KeyCreationRequest.json",
                                     "KeyCreationResponse.json",
                                     "ProvisioningFinalizationRequest.json",
                                     "ProvisioningFinalizationResponse.json"});

        json.addParagraphObject ("Aknowledgements").append ("The design of the KeyGen2 protocol was &quot;inspired&quot; by several predecessors, most notably IETF's DSKPP ")
                          .append (json.createReference (JSONBaseHTML.REF_DSKPP))
                          .append ("." + LINE_SEPARATOR +
                          "Funding has been provided by <i>PrimeKey Solutions AB</i> and the <i>Swedish Innovation Board (VINNOVA)</i>.");
        
        json.addReferenceTable ();
        
        json.addDocumentHistoryLine ("2013-12-29", "0.2", "Not yet released document :-)");

        json.addParagraphObject ("Author").append ("KeyGen2 was primarily developed by Anders Rundgren (<code>anders.rundgren.net@gmail.com</code>).");

        preAmble (PLATFORM_NEGOTIATION_REQUEST_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (SERVER_SESSION_ID_JSON)
              .addSymbolicValue (SERVER_SESSION_ID_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.ID)
            .newColumn ()
            .newColumn ()
              .addString ("The <code>" + SERVER_SESSION_ID_JSON +
                          "</code> <b>must</b> remain constant for the entire session.")
          .newExtensionRow (new SubmitURL ())
          .newRow ()
            .newColumn ()
              .addProperty (ACTION_JSON)
              .addSymbolicValue (ACTION_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("The <code>" + ACTION_JSON +
                          "</code> property gives (through a suitable GUI dialog) the user a hint of what the session in progress is about to perform. " +
                          "The valid constants are:<ul>" +
                          "<li><code>" + Action.MANAGE.getJSONName () + "</code> - Create, delete and/or update credentials</li>" +
                          "<li style=\"padding-bottom:4pt;padding-top:4pt\"><code>" + Action.RESUME.getJSONName () + "</code> - Resume operation after an interrupted ")
               .addLink (KEY_CREATION_RESPONSE_JSON)
               .addString (".  See ")
               .addPropertyLink (DEFERRED_ISSUANCE_JSON, KEY_CREATION_REQUEST_JSON)
               .addString (". A confirming client should after this call only accept a ")
               .addLink (PROVISIONING_FINALIZATION_REQUEST_JSON)
               .addString ("</li>" +
                           "<li><code>" + Action.UNLOCK.getJSONName () +
                           "</code> - Unlock existing keys. A conforming client should disallow ")
               .addLink (KEY_CREATION_REQUEST_JSON)
               .addString ("</li></ul>")
          .newRow ()
            .newColumn ()
              .addProperty (ABORT_URL_JSON)
              .addSymbolicValue (ABORT_URL_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.URI)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("Optional URL the provisioning client should launch the browser with if the user cancels the process.")
          .newRow ()
            .newColumn ()
              .addProperty (PRIVACY_ENABLED_JSON)
              .addSymbolicValue (PRIVACY_ENABLED_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BOOLEAN)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("The <code>" + PRIVACY_ENABLED_JSON +
                          "</code> flag serves two purposes:<ul>" +
                          "<li>Give the user a chance to cancel the provisioning operation " +
                          "if the privacy implications of the standard mode are unacceptable.<br>" +
                          "See SKS &quot;Privacy Enabled Mode&quot;.</li>" +
                          "<li style=\"padding-top:4pt\">Activate the correct mode during ")
               .addLink (PROVISIONING_INITIALIZATION_REQUEST_JSON)
               .addString (".<br>See <code>SKS:createProvisioningSession." + PRIVACY_ENABLED_JSON +
                           "</code>.</li></ul>Note: The default value is <code>false</code>.")
          .newExtensionRow (new OptionalArrayList (PREFERREDD_LANGUAGES_JSON,
                                                   "<i>Optional</i>: List of preferred languages using ISO 639-1 two-character notation."))
          .newExtensionRow (new OptionalArrayList (KeyContainerTypes.KCT_TARGET_KEY_CONTAINERS,
                         "<i>Optional</i>: List of target key container types.  The elements may be:<ul>" +
                         getKeyContainers () +
                         "</ul>" +
                         "The key containers are listed in preference order. " +
                         "If no matching container is available the client may prompt " +
                         "the user for inserting a card or similar." + LINE_SEPARATOR + 
                         "If <code>" +
                         KeyContainerTypes.KCT_TARGET_KEY_CONTAINERS + "</code> is undefined " +
                         "the provisioning client is supposed to use the system's 'native' keystore."))
          .newExtensionRow (new BasicCapabilityQuery (BasicCapabilities.BASIC_CAP_ALGORITHM, "Query the client for support for non-mandatory algorithms.  See SKS &quot;Algorithm Support&quot;."))
          .newExtensionRow (new BasicCapabilityQuery (BasicCapabilities.BASIC_CAP_EXTENSION, "Query the client for support for specific extension objects." + LINE_SEPARATOR))
            .addString ("Note that extensions may refer to <code>SKS:addExtension</code> as well as to non-SKS items such as ")
            .addPropertyLink (VIRTUAL_MACHINE_JSON, PROVISIONING_INITIALIZATION_REQUEST_JSON)
            .addString ("." + LINE_SEPARATOR +
                        "Another possible use of this feature is for signaling support for extensions in the protocol itself while keeping the name-space etc. intact.")
          .newExtensionRow (new BasicCapabilityQuery (BasicCapabilities.BASIC_CAP_CLIENT_ATTRI, "Query the client for support for client attributes like IMEI number. " +
                         "If the client has support for " +
                         "such attributes it should request the user's permission to disclose them." + LINE_SEPARATOR +
                         "This property is not allowed in the <code>" + PRIVACY_ENABLED_JSON + "</code> mode." + LINE_SEPARATOR +
                         "The following client attribute URIs are pre-defined:<ul>" + clientAttributes () +
                         "</ul>"))
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
              .addString (".")
          .newRow ()
            .newColumn ()
              .addProperty (NONCE_JSON)
              .addSymbolicValue (NONCE_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("<i>Optional</i> 1-32 byte nonce. See ")
              .addLink (PROVISIONING_INITIALIZATION_REQUEST_JSON)
              .addString (".")
          .newExtensionRow (new BasicCapabilitySupport (BasicCapabilities.BASIC_CAP_ALGORITHM))
          .newExtensionRow (new BasicCapabilitySupport (BasicCapabilities.BASIC_CAP_EXTENSION))
          .newExtensionRow (new BasicCapabilitySupport (BasicCapabilities.BASIC_CAP_CLIENT_ATTRI))
          .newExtensionRow (new OptionalArrayObject (IMAGE_PREFERENCES_JSON,
                                                     1,
                                                     "List of client image preferences that the server may use for creating suitable "))
            .addLink (LOGOTYPES_JSON)
            .addString (".  Known logotypes include:<ul>" + getLogotypes () + "</ul>" +
                        "Logotypes should not have framing borders or extra margins " +
                        "unless these are integral parts of the actual logotype image. " + 
                        "Logotypes should render nicely on light backgrounds. " +
                        "Shadows should be avoided since the icon viewer itself may add such. " +
                        "Support for PNG files is <i>mandatory</i>.");

        preAmble (PROVISIONING_INITIALIZATION_REQUEST_JSON)
          .newExtensionRow (new ServerSessionID ())
          .newExtensionRow (new SubmitURL ())
          .newRow ()
            .newColumn ()
              .addProperty (SERVER_TIME_JSON)
              .addSymbolicValue (SERVER_TIME_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.DATE)
            .newColumn ()
            .newColumn ()
              .addString ("Server time which the client should verify as a &quot;sanity&quot; check.")
          .newRow ()
            .newColumn ()
              .addProperty (SESSION_KEY_ALGORITHM_JSON)
              .addValue (SecureKeyStore.ALGORITHM_SESSION_ATTEST_1)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.URI)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createProvisioningSession." +
                          SESSION_KEY_ALGORITHM_JSON + "</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (SESSION_KEY_LIMIT_JSON)
              .addUnquotedValue (SESSION_KEY_LIMIT_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.SHORT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createProvisioningSession." + SESSION_KEY_LIMIT_JSON + "</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (SESSION_LIFE_TIME_JSON)
              .addUnquotedValue (SESSION_LIFE_TIME_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.INT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createProvisioningSession." + SESSION_LIFE_TIME_JSON + "</code>.")
          .newExtensionRow (new LinkedObject (SERVER_EPHEMERAL_KEY_JSON,
                                              true,
                                               "See <code>SKS:createProvisioningSession." +
                                              SERVER_EPHEMERAL_KEY_JSON + "</code>."))
          .newExtensionRow (new LinkedObject (KEY_MANAGEMENT_KEY_JSON,
                                              false,
                                              "See <code>SKS:createProvisioningSession." +
                                              KEY_MANAGEMENT_KEY_JSON + "</code>."))
          .newRow ()
            .newColumn ()
              .addProperty (REQUESTED_CLIENT_ATTRIBUTES_JSON)
              .addArrayList (URI_LIST, 1)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.URI)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("<i>Optional</i>: List of client attribute types (expressed as URI strings) that the client <i>may</i> honor. See ")
              .addLink (PROVISIONING_INITIALIZATION_RESPONSE_JSON)
              .addString ("." + LINE_SEPARATOR + "Note that it is an <i>error</i> requesting an attribute not specified during ")
              .addLink (PLATFORM_NEGOTIATION_REQUEST_JSON)
              .addString (".")
          .newExtensionRow (new LinkedObject (VIRTUAL_MACHINE_JSON,
                                              false,
                          "The <code>" + VIRTUAL_MACHINE_JSON + "</code> option is intended to support BYOD " +
                          "use-cases where the provisioning process bootstraps an alternative " +
                          "environment and associated policies." + LINE_SEPARATOR +
                          "Since the exact nature of such an environment is platform-dependent, it is necessary " +
                          "to find out what is actually available using the pre-defined extension URI <code>&quot;"))
              .addString (KeyGen2URIs.FEATURE.VIRTUAL_MACHINE)
              .addString ("&quot;</code>. The recommended method is adding the following to ")
              .addLink (PLATFORM_NEGOTIATION_REQUEST_JSON)
              .addString (LINE_SEPARATOR + "<code>&nbsp;&nbsp;&quot;")
              .addString (BasicCapabilities.tagName (BasicCapabilities.BASIC_CAP_EXTENSION, true))
              .addString ("&quot;:<br>&nbsp;&nbsp;&nbsp;&nbsp;[<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;" +
                          KeyGen2URIs.FEATURE.VIRTUAL_MACHINE +
                          "&quot;,<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;" +
                          "http://extreme-vm.com/type.3&quot;,<br>" +
                          "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;" +
                          "http://cool-but-obscure-vm.com/x" +
                          "&quot;<br>&nbsp;&nbsp;&nbsp;&nbsp;]</code>" + LINE_SEPARATOR +
                          "where the two latter URIs represent different, potentially supported environment types." + LINE_SEPARATOR +
                          "A possible ")
              .addLink (PLATFORM_NEGOTIATION_RESPONSE_JSON)
              .addString (" could be:" + LINE_SEPARATOR +
                          "<code>&nbsp;&nbsp;&quot;")
              .addString (BasicCapabilities.tagName (BasicCapabilities.BASIC_CAP_EXTENSION, false))
              .addString ("&quot;:<br>&nbsp;&nbsp;&nbsp;&nbsp;[<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;" +
                          KeyGen2URIs.FEATURE.VIRTUAL_MACHINE +
                          "&quot;,<br>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;" +
                          "http://extreme-vm.com/type.3" +
                          "&quot;<br>&nbsp;&nbsp;&nbsp;&nbsp;]</code>" + LINE_SEPARATOR + 
                          "If an environment is already installed only the configuration should be updated. " + LINE_SEPARATOR +
                          "Note that the <code>" +
                          VIRTUAL_MACHINE_JSON +
                          "</code> option presumes that the <code>" +
                          PROVISIONING_INITIALIZATION_REQUEST_JSON +
                          "</code> is <i>signed</i>.")
          .newRow ()
            .newColumn ()
              .addProperty (NONCE_JSON)
              .addSymbolicValue (NONCE_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("<i>Optional</i> 1-32 byte nonce. The <code>" +
                           NONCE_JSON + "</code> value <b>must</b> be identical to the <code>" +
                           NONCE_JSON + "</code> specified in ")
               .addLink (PLATFORM_NEGOTIATION_RESPONSE_JSON)
               .addString (". Also see <code>" + JSONSignatureDecoder.SIGNATURE_JSON + "</code>.")
          .newExtensionRow (new OptionalSignature ())
              .addString (" Note that <code>" + NONCE_JSON +
                          "</code> <b>must</b> be specified for a signed <code>" +
                          PROVISIONING_INITIALIZATION_REQUEST_JSON + "</code>.");

        preAmble (PROVISIONING_INITIALIZATION_RESPONSE_JSON)
          .newExtensionRow (new StandardServerClientSessionIDs ())
          .newRow ()
            .newColumn ()
              .addProperty (SERVER_TIME_JSON)
              .addSymbolicValue (SERVER_TIME_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.DATE)
            .newColumn ()
            .newColumn ()
              .addString ("Server time transferred verbatim from ")
              .addLink (PROVISIONING_INITIALIZATION_REQUEST_JSON)
              .addString (".")
          .newRow ()
            .newColumn ()
              .addProperty (CLIENT_TIME_JSON)
              .addSymbolicValue (CLIENT_TIME_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.DATE)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createProvisioningSession." + CLIENT_TIME_JSON + "</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (SESSION_ATTESTATION_JSON)
              .addSymbolicValue (SESSION_ATTESTATION_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createProvisioningSession." +
                          SESSION_ATTESTATION_JSON + "</code>.")
          .newExtensionRow (new LinkedObject (CLIENT_EPHEMERAL_KEY_JSON,
                                              true,
                                              "See <code>SKS:createProvisioningSession." + CLIENT_EPHEMERAL_KEY_JSON + "</code>."))
          .newExtensionRow (new LinkedObject (DEVICE_CERTIFICATE_JSON,
                                              false,
                          "See <code>SKS:createProvisioningSession</code>. " +
                          "Note that this property is either required or forbidden " +
                          "depending on the value of "))
            .addPropertyLink (PRIVACY_ENABLED_JSON, PLATFORM_NEGOTIATION_REQUEST_JSON)
            .addString (".")
          .newRow ()
            .newColumn ()
              .addProperty (SERVER_CERT_FP_JSON)
              .addSymbolicValue (SERVER_CERT_FP_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("SHA256 fingerprint of the server's certificate during receival of the ")
              .addLink (PROVISIONING_INITIALIZATION_REQUEST_JSON)
              .addString (" object. " + LINE_SEPARATOR + 
                          "This property is mandatory for HTTPS connections.")
          .newRow ()
            .newColumn ()
              .addProperty (CLIENT_ATTRIBUTES_JSON)
              .addArrayLink (CLIENT_ATTRIBUTES_JSON, 1)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("<i>Optional</i>: List of client attribute types and values. See ")
              .addLink (PROVISIONING_INITIALIZATION_REQUEST_JSON)
              .addString (".")
          .newExtensionRow (new LinkedObject (JSONSignatureDecoder.SIGNATURE_JSON,
                                              true,
                                              "Symmetric key signature covering the entire response. See <code>" +
                                              "SKS:createProvisioningSession</code>." + LINE_SEPARATOR +
                                              "Note that the value of "))
          .addPropertyLink (JSONSignatureDecoder.KEY_ID_JSON, JSONSignatureDecoder.KEY_INFO_JSON)
          .addString (" property is <i>ignored</i>. ");

        preAmble (CREDENTIAL_DISCOVERY_REQUEST_JSON)
          .newExtensionRow (new StandardServerClientSessionIDs ())
          .newExtensionRow (new SubmitURL ())
          .newRow ()
             .newColumn ()
              .addProperty (LOOKUP_SPECIFIERS_JSON)
              .addArrayLink (LOOKUP_SPECIFIERS_JSON, 1)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("List of signed credential lookup specifiers. " +
                          "See SKS appendix &quot;Remote Key Lookup&quot; for details.")
          .newExtensionRow (new OptionalSignature ());
  
        preAmble (CREDENTIAL_DISCOVERY_RESPONSE_JSON)
          .newExtensionRow (new StandardServerClientSessionIDs ())
          .newRow ()
            .newColumn ()
              .addProperty (LOOKUP_RESULTS_JSON)
              .addArrayLink (LOOKUP_RESULTS_JSON, 1)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("List of credential lookup results. " +
                          "See SKS appendix &quot;Remote Key Lookup&quot; for details.");

        preAmble (KEY_CREATION_REQUEST_JSON)
          .newExtensionRow (new StandardServerClientSessionIDs ())
          .newExtensionRow (new SubmitURL ())
          .newRow ()
            .newColumn ()
              .addProperty (KEY_ENTRY_ALGORITHM_JSON)
              .addValue (SecureKeyStore.ALGORITHM_KEY_ATTEST_1)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.URI)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." +
                          KEY_ENTRY_ALGORITHM_JSON + "</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (DEFERRED_ISSUANCE_JSON)
              .addUnquotedValue (DEFERRED_ISSUANCE_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BOOLEAN)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("Flag telling if the process should be suspended after ")
              .addLink (KEY_CREATION_RESPONSE_JSON)
              .addString (".  Default value: <code>false</code>. " +
                          "See the <code>" + ACTION_JSON + "</code> property in ")
              .addLink (PLATFORM_NEGOTIATION_REQUEST_JSON)
              .addString (".")
          .newExtensionRow (new OptionalArrayObject (PUK_POLICY_SPECIFIERS_JSON,
                                                     1,
                                                     "List of PUK policy objects to be created. " +
                                                     "See <code>SKS:createPUKPolicy</code>."))
          .newExtensionRow (new OptionalArrayObject (PIN_POLICY_SPECIFIERS_JSON,
                                                     1,
                                                     "List of PIN policy objects to be created. " +
                                                     "See <code>SKS:createPINPolicy</code>."))
          .newExtensionRow (new OptionalArrayObject (KEY_ENTRY_SPECIFIERS_JSON,
                                                     1,
                                                     "List of key entries to be created. " +
                                                     "See <code>SKS:createKeyEntry</code>."))
          .newExtensionRow (new OptionalSignature ()).setNotes (
              "Due to the stateful MAC-scheme featured in SKS, " +
              "the properties beginning with <code>" + PUK_POLICY_SPECIFIERS_JSON + "</code> " +
              "and ending with <code>" + KEY_ENTRY_SPECIFIERS_JSON + "</code>, <b>must</b> " +
              "<i>be generated (by the issuer) and executed (by the SKS) in " +
              "exactly the order they are declared in this table as well " +
              "as in associated object arrays</i>.");
  
        preAmble (KEY_CREATION_RESPONSE_JSON)
          .newExtensionRow (new StandardServerClientSessionIDs ())
          .newRow ()
            .newColumn ()
              .addProperty (GENERATED_KEYS_JSON)
              .addArrayLink (GENERATED_KEYS_JSON, 1)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("List of generated keys. See <code>SKS:createKeyEntry</code>.").setNotes ("Due to the stateful MAC-scheme featured in SKS, " +
                          "<code>" + GENERATED_KEYS_JSON + "</code> <b>must</b> " +
                          "<i>be encoded (by the SKS) and decoded (by the issuer) in exactly the same " +
                          "order (message-wise) as they are encountered in the associated</i>  <a href=\"#" +
                           KEY_CREATION_REQUEST_JSON + "." + KEY_ENTRY_SPECIFIERS_JSON + "\">" + KEY_ENTRY_SPECIFIERS_JSON + "</a> "+
                           "(including those embedded by <a href=\"#" +
                           KEY_CREATION_REQUEST_JSON + "." + PIN_POLICY_SPECIFIERS_JSON + "\">" + PIN_POLICY_SPECIFIERS_JSON + "</a>).");

        preAmble (PROVISIONING_FINALIZATION_REQUEST_JSON)
          .newExtensionRow (new StandardServerClientSessionIDs ())
          .newExtensionRow (new SubmitURL ())
          .newExtensionRow (new OptionalArrayObject (ISSUED_CREDENTIALS_JSON,
                                                     1,
                 "<i>Optional:</i> List of issued credentials. See <code>" +
                 "SKS:setCertificatePath</code>.")).setNotes (
                     "Due to the stateful MAC-scheme featured in SKS, " +
                     "the properties beginning with <code>" + ISSUED_CREDENTIALS_JSON + "</code> " +
                     "and ending with <code>" + DELETE_KEYS_JSON + "</code>, <b>must</b> " +
                     "<i>be generated (by the issuer) and executed (by the SKS) in exactly " +
                     "the order they are declared in this table as well " +
                     "as in associated object arrays</i>.")
          .newExtensionRow (new OptionalArrayObject (UNLOCK_KEYS_JSON,
                                                     1,
                                                     "<i>Optional:</i> List of keys to be unlocked. See <code>" +
                                                     "SKS:postUnlockKey</code>."))
          .newExtensionRow (new OptionalArrayObject (DELETE_KEYS_JSON,
                                                     1,
                                                     "<i>Optional:</i> List of keys to be deleted. See <code>" +
                                                     "SKS:postDeleteKey</code>."))
          .newRow ()
            .newColumn ()
              .addProperty (CHALLENGE_JSON)
              .addSymbolicValue (CHALLENGE_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:closeProvisioningSession</code>.")
          .newExtensionRow (new MAC ("closeProvisioningSession"))
            .addString (LINE_SEPARATOR +
                 "Due to the stateful MAC-scheme featured in SKS, this " +
                 "<code>" + MAC_JSON + "</code> " +
                 "<b>must</b> be the final of a provisioning session both during encoding and decoding.")
          .newExtensionRow (new OptionalSignature ());

        preAmble (PROVISIONING_FINALIZATION_RESPONSE_JSON)
          .newExtensionRow (new StandardServerClientSessionIDs ())
          .newRow ()
            .newColumn ()
              .addProperty (CLOSE_ATTESTATION_JSON)
              .addSymbolicValue (CLOSE_ATTESTATION_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:closeProvisioningSession</code>.");

        json.addSubItemTable (KEY_MANAGEMENT_KEY_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.PUBLIC_KEY_JSON)
              .addLink (JSONSignatureDecoder.PUBLIC_KEY_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("Actual key management key.")
          .newExtensionRow (new OptionalArrayObject (UPDATABLE_KEY_MANAGEMENT_KEYS_JSON,
                            1,
                            "<i>Optional:</i> List of the previous generation " +
                            "of key management keys."));

        json.addSubItemTable (UPDATABLE_KEY_MANAGEMENT_KEYS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.PUBLIC_KEY_JSON)
              .addLink (JSONSignatureDecoder.PUBLIC_KEY_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("Previous generation key management key." + LINE_SEPARATOR +
                          "Note that <code>SKS:updateKeyManagementKey.KeyManagementKey</code>" +
                          " refers to the <i>new</i> key management key specified in the object <i>immediately above</i> (=embedding) this ")
              .addLink (UPDATABLE_KEY_MANAGEMENT_KEYS_JSON)
              .addString (" object.")
          .newRow ()
            .newColumn ()
              .addProperty (AUTHORIZATION_JSON)
              .addSymbolicValue (AUTHORIZATION_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("Authorization of the new key management key. See <code>SKS:updateKeyManagementKey.Authorization</code>.")
          .newExtensionRow (new OptionalArrayObject (UPDATABLE_KEY_MANAGEMENT_KEYS_JSON,
                            1,
                            "<i>Optional:</i> List of the previous generation of key management keys."));

        json.addSubItemTable (VIRTUAL_MACHINE_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (TYPE_JSON)
              .addSymbolicValue (TYPE_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.URI)
            .newColumn ()
            .newColumn ()
              .addString ("Virtual machine specific type URI like <code>&quot;http://extreme-vm.com/type.3&quot;</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (CONFIGURATION_JSON)
              .addSymbolicValue (CONFIGURATION_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("Virtual machine specific configuration (setup) data.")
          .newRow ()
            .newColumn ()
              .addProperty (FRIENDLY_NAME_JSON)
              .addSymbolicValue (FRIENDLY_NAME_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("Virtual machine friendly name.");

        json.addSubItemTable (LOOKUP_SPECIFIERS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (ID_JSON)
              .addSymbolicValue (ID_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.ID)
            .newColumn ()
            .newColumn ()
              .addString ("Each specifier <b>must</b> have a unique ID.")
          .newRow ()
            .newColumn ()
              .addProperty (NONCE_JSON)
              .addSymbolicValue (NONCE_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("<code>" + NONCE_JSON + "</code> data. " +
                          "See SKS appendix &quot;Remote Key Lookup&quot; for details.")
          .newRow ()
            .newColumn ()
              .addProperty (SEARCH_FILTER_JSON)
              .addLink (SEARCH_FILTER_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("<i>Optional</i> additional search criterions." + LINE_SEPARATOR +
                          "Note that at least one search criterion <b>must</b> be specified if this option is used.")
          .newExtensionRow (new LinkedObject (JSONSignatureDecoder.SIGNATURE_JSON,
                            true,
                            "Signature using a key management key signature covering the lookup specifier. " +
                            "See SKS appendix &quot;Remote Key Lookup&quot; for details."));

        createSearchFilter ();

        json.addSubItemTable (LOOKUP_RESULTS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (ID_JSON)
              .addSymbolicValue (ID_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.ID)
            .newColumn ()
            .newColumn ()
              .addString ("Each result <b>must</b> have a unique ID matching the request.")
          .newRow ()
            .newColumn ()
              .addProperty (MATCHING_CREDENTIALS_JSON)
              .addArrayLink (MATCHING_CREDENTIALS_JSON, 0)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("List of matching credentials.");
        
        json.addSubItemTable (MATCHING_CREDENTIALS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (SERVER_SESSION_ID_JSON)
              .addSymbolicValue (SERVER_SESSION_ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("<code>" + SERVER_SESSION_ID_JSON + "</code> of matching credential.")
          .newRow ()
            .newColumn ()
              .addProperty (CLIENT_SESSION_ID_JSON)
              .addSymbolicValue (CLIENT_SESSION_ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("<code>" + CLIENT_SESSION_ID_JSON + "</code> of matching credential.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON)
              .addArrayList (SORTED_CERT_PATH, 1)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("Identical representation as the <code>" +
                          JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON +
                          "</code> in ")
              .addLink (JSONSignatureDecoder.KEY_INFO_JSON)
              .addString (".")
          .newRow ()
            .newColumn ()
              .addProperty (LOCKED_JSON)
              .addUnquotedValue (LOCKED_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BOOLEAN)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("If this property is <code>true</code> the key associated " +
                          "with the credential is locked due to multiple PIN errors. " +
                          "The default value is <code>false</code>.  See ")
              .addPropertyLink (UNLOCK_KEYS_JSON, PROVISIONING_FINALIZATION_REQUEST_JSON)
              .addString (".");

        json.addSubItemTable (PUK_POLICY_SPECIFIERS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (ID_JSON)
              .addSymbolicValue (ID_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.ID)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPUKPolicy.ID</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (ENCRYPTED_PUK_JSON)
              .addSymbolicValue (ENCRYPTED_PUK_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPUKPolicy.EncryptedPUK</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (RETRY_LIMIT_JSON)
              .addUnquotedValue (RETRY_LIMIT_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.SHORT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPUKPolicy.RetryLimit</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (FORMAT_JSON)
              .addSymbolicValue (FORMAT_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPUKPolicy.Format</code>.")
          .newExtensionRow (new MAC ("createPUKPolicy"))
          .newRow ()
            .newColumn ()
              .addProperty (PIN_POLICY_SPECIFIERS_JSON)
              .addArrayLink (PIN_POLICY_SPECIFIERS_JSON, 1)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("List of PIN policy objects to be created and controlled by this PUK policy. " +
                          "See <code>SKS:createPINPolicy</code>.");

        json.addSubItemTable (PIN_POLICY_SPECIFIERS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (ID_JSON)
              .addSymbolicValue (ID_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.ID)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPINPolicy.ID</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (MIN_LENGTH_JSON)
              .addUnquotedValue (MIN_LENGTH_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.SHORT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPINPolicy.MinLength</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (MAX_LENGTH_JSON)
              .addUnquotedValue (MAX_LENGTH_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.SHORT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPINPolicy.MaxLength</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (RETRY_LIMIT_JSON)
              .addUnquotedValue (RETRY_LIMIT_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.SHORT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPINPolicy.RetryLimit</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (FORMAT_JSON)
              .addSymbolicValue (FORMAT_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createPINPolicy.Format</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (USER_MODIFIABLE_JSON)
              .addUnquotedValue (USER_MODIFIABLE_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BOOLEAN)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("Flag with the default value <code>true</code>." +
                          "<br>See <code>SKS:createPINPolicy.UserModifiable</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (GROUPING_JSON)
              .addSymbolicValue (GROUPING_JSON)
            .newColumn ()
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("Grouping specifier with the default value <code>none</code>." +
                          "<br>See <code>SKS:createPINPolicy.Grouping</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (INPUT_METHOD_JSON)
              .addSymbolicValue (INPUT_METHOD_JSON)
            .newColumn ()
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("Input method specifier with the default value <code>any</code>." +
                          "<br>See <code>SKS:createPINPolicy.InputMethod</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (PATTERN_RESTRICTIONS_JSON)
              .addArrayList (PATTERN_RESTRICTIONS_JSON, 1)
            .newColumn ()
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("List of pattern restrictions.  See <code>SKS:createPINPolicy.PatternRestrictions</code>." +
                          "<br>If this property is undefined, there are no PIN pattern restrictions.")
          .newExtensionRow (new MAC ("createPINPolicy"))
          .newRow ()
            .newColumn ()
              .addProperty (KEY_ENTRY_SPECIFIERS_JSON)
              .addArrayLink (KEY_ENTRY_SPECIFIERS_JSON, 1)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("List of key entries to be created and controlled by this PIN policy." +
                          "<br>See <code>SKS:createKeyEntry</code>.");

        json.addSubItemTable (KEY_ENTRY_SPECIFIERS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (ID_JSON)
              .addSymbolicValue (ID_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.ID)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry.ID</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (ENCRYPTED_PRESET_PIN_JSON)
              .addSymbolicValue (ENCRYPTED_PRESET_PIN_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry.PINValue</code>.<br>" + "" +
              		      "Note that if this property is defined, the " +
              		      "<code>SKS:createPINPolicy.UserDefined</code> " +
              		      "flag of the required embedding PIN policy is set to <code>false</code> " +
              		      "else it is set to <code>true</code>." + LINE_SEPARATOR +
              		      "Keys associated with a specific PIN policy " +
              		      "<b>must not</b> mix user-defined and preset PINs.")
          .newRow ()
            .newColumn ()
              .addProperty (ENABLE_PIN_CACHING_JSON)
              .addUnquotedValue (ENABLE_PIN_CACHING_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BOOLEAN)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("Flag with the default value <code>false</code>.<br>" +
                          "See <code>SKS:createKeyEntry." + ENABLE_PIN_CACHING_JSON + "</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (DEVICE_PIN_PROTECTION_JSON)
              .addUnquotedValue (DEVICE_PIN_PROTECTION_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BOOLEAN)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("Flag with the default value <code>false</code>.<br>" +
                          "See <code>SKS:createKeyEntry." + DEVICE_PIN_PROTECTION_JSON + "</code>. " + LINE_SEPARATOR +
                          "Note that this flag (if true) cannot be combined with PIN policy settings.")
          .newRow ()
            .newColumn ()
              .addProperty (APP_USAGE_JSON)
              .addSymbolicValue (APP_USAGE_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." + APP_USAGE_JSON + "</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (KEY_ALGORITHM_JSON)
              .addSymbolicValue (KEY_ALGORITHM_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.URI)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." + KEY_ALGORITHM_JSON + "</code>. " +
                          "Also see SKS &quot;Algorithm Support&quot;." + LINE_SEPARATOR +
                          "The currently recognized key algorithms include:" +
                          JSONBaseHTML.enumerateAlgorithms (KeyAlgorithms.values (), false, false, false))
          .newRow ()
            .newColumn ()
              .addProperty (KEY_PARAMETERS_JSON)
              .addSymbolicValue (KEY_PARAMETERS_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." + KEY_PARAMETERS_JSON + "</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (ENDORSED_ALGORITHMS_JSON)
              .addArrayList (URI_LIST, 1)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.URI)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry.EndorsedAlgorithm</code>. " +
                          "Also see SKS &quot;Algorithm Support&quot;." + LINE_SEPARATOR +
                          "Note that <i>endorsed algorithm URIs <b>must</b> be specified in strict lexical order</i>." + LINE_SEPARATOR +
                          "The currently recognized algorithms include:" +
                          JSONBaseHTML.enumerateAlgorithms (MACAlgorithms.values (), true, false, false) +
                          JSONBaseHTML.enumerateAlgorithms (AsymSignatureAlgorithms.values (), false, false, false) +
                          JSONBaseHTML.enumerateAlgorithms (AsymEncryptionAlgorithms.values (), false, false, false) +
                          JSONBaseHTML.enumerateAlgorithms (SymEncryptionAlgorithms.values (), true, false, false) +
                          "<ul><li><code>" + SecureKeyStore.ALGORITHM_ECDH_RAW + "</code></li></ul>" +
                          "<ul><li><code>" + SecureKeyStore.ALGORITHM_NONE + "</code></li></ul>")
          .newRow ()
            .newColumn ()
              .addProperty (SERVER_SEED_JSON)
              .addSymbolicValue (SERVER_SEED_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." + SERVER_SEED_JSON + "</code>. " +
                          "If this property is undefined, it is assumed to be a zero-length array.")
          .newRow ()
            .newColumn ()
              .addProperty (BIOMETRIC_PROTECTION_JSON)
              .addSymbolicValue (BIOMETRIC_PROTECTION_JSON)
            .newColumn ()
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." + BIOMETRIC_PROTECTION_JSON + "</code>. " +
                          "The default value is <code>none</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (DELETE_PROTECTION_JSON)
              .addSymbolicValue (DELETE_PROTECTION_JSON)
            .newColumn ()
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." + DELETE_PROTECTION_JSON + "</code>. " +
                          "The default value is <code>none</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (EXPORT_PROTECTION_JSON)
              .addSymbolicValue (EXPORT_PROTECTION_JSON)
            .newColumn ()
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." + EXPORT_PROTECTION_JSON + "</code>. " +
                          "The default value is <code style=\"white-space:nowrap\">non-exportable</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (FRIENDLY_NAME_JSON)
              .addSymbolicValue (FRIENDLY_NAME_JSON)
            .newColumn ()
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry." + FRIENDLY_NAME_JSON + "</code>." +
                          "If this property is undefined, it is assumed to be a zero-length array.")
          .newExtensionRow (new MAC ("createKeyEntry"));

        json.addSubItemTable (GENERATED_KEYS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (ID_JSON)
              .addSymbolicValue (ID_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.ID)
            .newColumn ()
            .newColumn ()
              .addString ("<code>" + ID_JSON + "</code> <b>must</b> match the identifier used in ")
              .addLink (KEY_CREATION_REQUEST_JSON)
              .addString (" for a specific key.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.PUBLIC_KEY_JSON)
              .addLink (JSONSignatureDecoder.PUBLIC_KEY_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry.PublicKey</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (KEY_ATTESTATION_JSON)
              .addSymbolicValue (KEY_ATTESTATION_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:createKeyEntry.KeyAttestation</code>.");

        json.addSubItemTable (ISSUED_CREDENTIALS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (ID_JSON)
              .addSymbolicValue (ID_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.ID)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:setCertificatePath.ID</code>")
              .addString (".<br><code>" + ID_JSON + "</code> <b>must</b> match the identifier used in ")
              .addLink (KEY_CREATION_REQUEST_JSON)
              .addString (" for a specific key.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON)
              .addArrayList (SORTED_CERT_PATH, 1)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("See <code>SKS:setCertificatePath.X509Certificate</code>")
              .addString (".<br>Identical representation as the <code>" +
                          JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON +
                          "</code> in ")
              .addLink (JSONSignatureDecoder.KEY_INFO_JSON)
              .addString (".")
          .newExtensionRow (new MAC ("setCertificatePath"))
          .newRow ()
            .newColumn ()
              .addProperty (TRUST_ANCHOR_JSON)
              .addUnquotedValue (TRUST_ANCHOR_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BOOLEAN)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("<i>Optional:</i> Flag (with the default value <code>false</code>), " +
                          "which tells if <code>" +
                          JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON +
                          "</code> contains a user-installable trust anchor as well." + LINE_SEPARATOR +
                          "Trust anchor installation is meant to be <i>independent</i> of SKS provisioning.")
          .newExtensionRow (new LinkedObject (IMPORT_SYMMETRIC_KEY_JSON,
                                              false,
                          "<i>Optional:</i> Import of raw symmetric key. See <code>SKS:importSymmetricKey</code>.", 2))
          .newExtensionRow (new LinkedObject (IMPORT_PRIVATE_KEY_JSON,
                                              false,
                          "<i>Optional:</i> Import of private key in PKCS #8 " +
                          json.createReference (JSONBaseHTML.REF_PKCS8) +
                          " format. See <code>SKS:importPrivateKey</code>."))
          .newExtensionRow (new TargetKeyReference (UPDATE_KEY_JSON, false, "postUpdateKey", true))
          .newExtensionRow (new TargetKeyReference (CLONE_KEY_PROTECTION_JSON, false, "postCloneKeyProtection", false))
          .newExtensionRow (new OptionalArrayObject (EXTENSIONS_JSON,
              1,
              "<i>Optional:</i> List of extension objects. See <code>" +
              "SKS:addExtension</code>."))
          .newExtensionRow (new OptionalArrayObject (ENCRYPTED_EXTENSIONS_JSON,
              1,
              "<i>Optional:</i> List of encrypted extension objects. See <code>" +
              "SKS:addExtension</code>."))
          .newExtensionRow (new OptionalArrayObject (PROPERTY_BAGS_JSON,
              1,
              "<i>Optional:</i> List of property objects. See <code>" +
              "SKS:addExtension</code>."))
          .newExtensionRow (new OptionalArrayObject (LOGOTYPES_JSON,
              1,
              "<i>Optional:</i> List of logotype objects. See <code>" +
              "SKS:addExtension</code>.")).setNotes (
                  "Due to the stateful MAC-scheme featured in SKS, " +
                  "the properties beginning with <code>" + IMPORT_SYMMETRIC_KEY_JSON + "</code> " +
                  "and ending with <code>" + LOGOTYPES_JSON + "</code>, <b>must</b> " +
                  "<i>be generated (by the issuer) and executed (by the SKS) in " +
                  "exactly the order they are declared in this table as well " +
                  "as in associated object arrays</i>." + LINE_SEPARATOR +
                  "Note that that credential <code>" + ID_JSON +
                  "</code>s are not guaranteed to be " +
                  "supplied in the same order as during the associated " +
                  "<a href=\"#" + KEY_CREATION_REQUEST_JSON + "\">" + KEY_CREATION_REQUEST_JSON + "</a>.");

        json.addSubItemTable (new String[]{CLONE_KEY_PROTECTION_JSON,
                                           DELETE_KEYS_JSON,
                                           UNLOCK_KEYS_JSON,
                                           UPDATE_KEY_JSON})
          .newRow ()
            .newColumn ()
              .addProperty (CertificateFilter.CF_FINGER_PRINT)
              .addSymbolicValue (CertificateFilter.CF_FINGER_PRINT)
            .newColumn ()
               .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("SHA256 fingerprint of target certificate.")
          .newRow ()
            .newColumn ()
              .addProperty (SERVER_SESSION_ID_JSON)
              .addSymbolicValue (SERVER_SESSION_ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("For locating the target key.")
          .newRow ()
            .newColumn ()
              .addProperty (CLIENT_SESSION_ID_JSON)
              .addSymbolicValue (CLIENT_SESSION_ID_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("For locating the target key.")
          .newRow ()
            .newColumn ()
              .addProperty (AUTHORIZATION_JSON)
              .addSymbolicValue (AUTHORIZATION_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("See &quot;Target Key Reference&quot; in the SKS reference.")
          .newExtensionRow (new MAC ("post* </code> methods<code>"));
        
        json.addSubItemTable (new String[]{ENCRYPTED_EXTENSIONS_JSON,
                                           EXTENSIONS_JSON})
          .newRow ()
            .newColumn ()
              .addProperty (TYPE_JSON)
              .addSymbolicValue (TYPE_JSON)
            .newColumn ()
               .setType (WEBPKI_DATA_TYPES.URI)
            .newColumn ()
            .newColumn ()
              .addString ("Extension type URI.")
          .newRow ()
            .newColumn ()
              .addProperty (EXTENSION_DATA_JSON)
              .addSymbolicValue (EXTENSION_DATA_JSON)
            .newColumn ()
               .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("Extension data.")
          .newExtensionRow (new MAC ("addExtension"));

        json.addSubItemTable (LOGOTYPES_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (TYPE_JSON)
              .addSymbolicValue (TYPE_JSON)
            .newColumn ()
               .setType (WEBPKI_DATA_TYPES.URI)
            .newColumn ()
            .newColumn ()
              .addString ("Logotype type URI.")
          .newRow ()
            .newColumn ()
              .addProperty (MIME_TYPE_JSON)
              .addSymbolicValue (MIME_TYPE_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("Logotype MIME type.")
          .newRow ()
            .newColumn ()
              .addProperty (EXTENSION_DATA_JSON)
              .addSymbolicValue (EXTENSION_DATA_JSON)
            .newColumn ()
               .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("Logotype image data.")
          .newExtensionRow (new MAC ("addExtension"));

        json.addSubItemTable (PROPERTY_BAGS_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (TYPE_JSON)
              .addSymbolicValue (TYPE_JSON)
            .newColumn ()
               .setType (WEBPKI_DATA_TYPES.URI)
            .newColumn ()
            .newColumn ()
              .addString ("Property bag type URI. See <code>SKS:addExtension</code>.")
          .newRow ()
            .newColumn ()
              .addProperty (PROPERTIES_JSON)
              .addArrayLink (PROPERTIES_JSON, 1)
            .newColumn ()
               .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("List of property values. See <code>SKS:addExtension</code>.")
          .newExtensionRow (new MAC ("addExtension"));

        json.addSubItemTable (PROPERTIES_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (NAME_JSON)
              .addSymbolicValue (NAME_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("Property name.")
          .newRow ()
            .newColumn ()
              .addProperty (VALUE_JSON)
              .addSymbolicValue (VALUE_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("Property value.")
          .newRow ()
            .newColumn ()
              .addProperty (WRITABLE_JSON)
              .addUnquotedValue (WRITABLE_JSON)
            .newColumn ()
               .setType (WEBPKI_DATA_TYPES.BOOLEAN)
            .newColumn ()
               .setUsage (false)
            .newColumn ()
              .addString ("Writable flag. Default is <code>false</code>.  See <code>SKS:setProperty</code>.");

        json.addSubItemTable (new String[]{IMPORT_PRIVATE_KEY_JSON, IMPORT_SYMMETRIC_KEY_JSON})
          .newRow ()
            .newColumn ()
              .addProperty (ENCRYPTED_KEY_JSON)
              .addSymbolicValue (ENCRYPTED_KEY_JSON)
            .newColumn ()
               .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("Encrypted key material.  See <code>SKS:import* </code> methods<code>." + ENCRYPTED_KEY_JSON + "</code>.")
          .newExtensionRow (new MAC ("import* </code>methods<code>"));

        json.addSubItemTable (CLIENT_ATTRIBUTES_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (TYPE_JSON)
              .addSymbolicValue (TYPE_JSON)
            .newColumn ()
               .setType (WEBPKI_DATA_TYPES.URI)
            .newColumn ()
            .newColumn ()
              .addString ("Client attribute type URI.")
          .newRow ()
            .newColumn ()
              .addProperty (VALUES_JSON)
              .addArrayList (VALUES_JSON, 0)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("List of attributes associated with <code>" + TYPE_JSON + "</code>.");

        json.addSubItemTable (IMAGE_PREFERENCES_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (TYPE_JSON)
              .addSymbolicValue (TYPE_JSON)
            .newColumn ()
               .setType (WEBPKI_DATA_TYPES.URI)
            .newColumn ()
            .newColumn ()
              .addString ("Image type URI. See ")
              .addLink (PLATFORM_NEGOTIATION_RESPONSE_JSON)
              .addString (".")
          .newRow ()
            .newColumn ()
              .addProperty (MIME_TYPE_JSON)
              .addSymbolicValue (MIME_TYPE_JSON)
            .newColumn ()
            .newColumn ()
            .newColumn ()
              .addString ("Image MIME type. See ")
              .addLink (PLATFORM_NEGOTIATION_RESPONSE_JSON)
              .addString (".")
          .newRow ()
            .newColumn ()
              .addProperty (WIDTH_JSON)
              .addSymbolicValue (WIDTH_JSON)
            .newColumn ()
               .setType (WEBPKI_DATA_TYPES.INT)
            .newColumn ()
            .newColumn ()
              .addString ("Image width. See ")
              .addLink (PLATFORM_NEGOTIATION_RESPONSE_JSON)
              .addString (".")
          .newRow ()
            .newColumn ()
              .addProperty (HEIGHT_JSON)
              .addSymbolicValue (HEIGHT_JSON)
            .newColumn ()
               .setType (WEBPKI_DATA_TYPES.INT)
            .newColumn ()
            .newColumn ()
              .addString ("Image height. See ")
              .addLink (PLATFORM_NEGOTIATION_RESPONSE_JSON)
              .addString (".");

        json.addSubItemTable (DEVICE_CERTIFICATE_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON)
              .addArrayList (SORTED_CERT_PATH, 1)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("Identical representation as the <code>" +
                          JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON +
                          "</code> in ")
              .addLink (JSONSignatureDecoder.KEY_INFO_JSON)
              .addString (".");
        
        json.addSubItemTable (SERVER_EPHEMERAL_KEY_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.PUBLIC_KEY_JSON)
              .addLink (JSONSignatureDecoder.PUBLIC_KEY_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("<code>" + SERVER_EPHEMERAL_KEY_JSON + 
                          "</code> <b>must</b> be an EC key matching the capabilities of the SKS.");
      
        json.addSubItemTable (CLIENT_EPHEMERAL_KEY_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.PUBLIC_KEY_JSON)
              .addLink (JSONSignatureDecoder.PUBLIC_KEY_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("<code>" + CLIENT_EPHEMERAL_KEY_JSON + 
                          "</code> <b>must</b> be an EC key using the same curve as <code>" + 
                          SERVER_EPHEMERAL_KEY_JSON + "</code>.");

        json.addJSONSignatureDefinitions (false, null, null);
        
        json.writeHTML ();
      }
  }
