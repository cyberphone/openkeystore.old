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
package org.webpki.json;

import java.io.IOException;

import org.webpki.json.JSONBaseHTML.RowInterface;
import org.webpki.json.JSONBaseHTML.Types;

/**
 * Create an HTML description of the JSON Clear-text Signature system.
 * 
 * @author Anders Rundgren
 */
public class JSONSignatureHTMLReference extends JSONBaseHTML.Types
  {
    
    static JSONBaseHTML json;
    static RowInterface row;

    public static void main (String args[]) throws IOException
      {
        json = new JSONBaseHTML (args, "JCS - JSON Cleartext Signature");
        
        json.addParagraphObject ().append ("<div style=\"margin-top:200pt;margin-bottom:200pt;text-align:center\"><span style=\"" + JSONBaseHTML.HEADER_STYLE + "\">JCS</span>" +
            "<br><span style=\"font-size:" + JSONBaseHTML.CHAPTER_FONT_SIZE + "\">&nbsp;<br>JSON Cleartext Signature</span></div>");
        
        json.addTOC ();

        json.addParagraphObject ("Introduction").append ("JCS is a scheme for signing data expressed as JSON ")
          .append (json.createReference (JSONBaseHTML.REF_JSON))
          .append (" objects. " +
            "It is loosely modeled after XML&nbsp;DSig's ")
          .append (json.createReference (JSONBaseHTML.REF_XMLDSIG))
          .append (" &quot;enveloped&quot; signatures. " +
            "Compared to its XML counterpart JCS is quite primitive but on the other hand it has proved to be " +
            "simple to implement and use.  That is, JCS follows the &quot;spirit&quot; of JSON." +
            Types.LINE_SEPARATOR +
            "Unlike for example IETF's JWS ")
          .append (json.createReference (JSONBaseHTML.REF_JOSE))
          .append (
            ", <i>JCS was designed to be an integral part of a JSON object</i> " +
            "rather than embedding the signed data.  There are (of course) pros and cons to both " +
            "approaches, but for information-rich messaging, " +
            "cleartext data at least have an advantage for documentation and debugging. " +
            "To cope with the primary disadvantage (the potential dependency on " +
            "canonicalization), this part has been extremely simplified compared to XML&nbsp;DSig. "+
            "In fact, JCS doesn't actually rely on canonicalization since it doesn't serve any purpose, " +
            "at least not in this context.");

        json.addParagraphObject ("Sample Signature").append (
"The following <i>cryptographically verifiable</i> sample signature is used to visualize the JCS specification:" +
"<div style=\"padding:10pt 0pt 10pt 20pt\"><code>" +
"{<br>" +
"&nbsp;&nbsp;&quot;Now&quot;:&nbsp;&quot;2013-12-23T23:25:10+01:00&quot;,<br>"+
"&nbsp;&nbsp;&quot;PaymentRequest&quot;:&nbsp;<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;{<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;Currency&quot;:&nbsp;&quot;USD&quot;,<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;VAT&quot;:&nbsp;1.45,<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;Specification&quot;:&nbsp;<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;[{<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;Units&quot;:&nbsp;3,<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;Description&quot;:&nbsp;&quot;USB&nbsp;cable&quot;,<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;SKU&quot;:&nbsp;&quot;TR-46565666&quot;,<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;UnitPrice&quot;:&nbsp;4.50<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;},<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;Units&quot;:&nbsp;1,<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;Description&quot;:&nbsp;&quot;4G&nbsp;Router&quot;,<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;SKU&quot;:&nbsp;&quot;JK-56566655&quot;,<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;UnitPrice&quot;:&nbsp;39.99<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}]<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;},<br>"+
"&nbsp;&nbsp;&quot;EscapeMe&quot;:&nbsp;&quot;\\u000F\\u000aA'\\u0042\\\\\\&quot;\\/&quot;,<br>"+
"&nbsp;&nbsp;&quot;Signature&quot;:&nbsp;<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;{<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;Algorithm&quot;:&nbsp;&quot;http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256&quot;,<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;KeyInfo&quot;:&nbsp;<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;PublicKey&quot;:&nbsp;<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;EC&quot;:&nbsp;<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;NamedCurve&quot;:&nbsp;&quot;http://xmlns.webpki.org/sks/algorithm#ec.nist.p256&quot;,<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;X&quot;:&nbsp;&quot;lNxNvAUEE8t7DSQBft93LVSXxKCiVjhbWWfyg023FCk&quot;,<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;Y&quot;:&nbsp;&quot;LmTlQxXB3LgZrNLmhOfMaCnDizczC_RfQ6Kx8iNwfFA&quot;<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;},<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;SignatureValue&quot;:&nbsp;&quot;MEUCIA1__ClTpOMBTCCA3oD3lzuaS3WACYR8qFDHpej5ZdEsAiEA3N5pWl2TOzzQfdtoc35S9n31mf-oP3_XBss8R8qjnvg&quot;<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;}<br>"+
"}</code></div>" +
"The sample signature's payload consists of the properties above <code>Signature</code>. " +
"Note: JCS does <i>not</i> mandate any specific ordering of properties like in the sample.");

        json.addParagraphObject ("Signature Scope").append (
            "The scope of a signature (=what is actually signed) comprises all " +
            "properties including possible child objects of the JSON " +
            "object holding the <code>Signature</code> property except for the actual <code>" + JSONSignatureDecoder.SIGNATURE_VALUE_JSON + "</code> property.");

        json.addParagraphObject ("Normalization and Signature Validation").append (
            "Prerequisite: A JSON object in accordance with ")
          .append (json.createReference (JSONBaseHTML.REF_JSON))
          .append (" containing a <code>Signature</code> property." + LINE_SEPARATOR +
            "Parsing restrictions:<ul>" +
            "<li>The original property order <b>must</b> be <i>preserved</i>.</li>" +
            "<li style=\"padding-top:4pt\">Property names <b>must not</b> be empty (<code>&quot;&quot;</code>)." +
            "<li style=\"padding-top:4pt\">Property names within an object <b>must</b> be <i>unique</i>.</li>" +
            "</ul>The normalization steps are as follows:<ul>" +
            "<li>Whitespace <b>must</b> be removed which in practical terms means removal of all characters outside of quoted strings having a value &lt;= ASCII space (0x32).</li>" +
            "<li style=\"padding-top:4pt\">JSON <code>'\\/'</code> escape sequences <b>must</b> be honored on <i>input</i> within quoted strings but be treated as a &quot;degenerate&quot; equivalents to <code>'/'</code> by rewriting them.</li>" +
            "<li style=\"padding-top:4pt\">Unicode escape sequences (<code>'\\uhhhh'</code>) within quoted strings <b>must</b> be adjusted as follows: " +
            "If the Unicode value falls within the traditional ASCII control character range (0x00 - 0x1f), " +
            "it <b>must</b> be rewritten in lower-case hexadecimal notation unless it is one of the pre-defined " +
            "JSON escapes (<code>'\\n'</code> etc.) because the latter have precedence. If the Unicode value is " +
            "outside of the ASCII control character range, it <b>must</b> be replaced by the corresponding Unicode character.</li>" +
            "<li style=\"padding-top:4pt\">The JSON object associated with the <code>Signature</code> <b>must</b> now be " +
            "<i>recreated</i> using the actual text left after applying the previous measures. <i>Rationale</i>: JSON numbers are ambiguously defined (&quot;unnormalized&quot;) " +
            "which means that a decoding/encoding sequence may produce a different representation compared to the original. " +
            "As an example, floating point data is often expressed like <code>4.50</code> in spite of the " +
            "trailing zero being redundant. To cope with this " +
            "potential problem, compliant parsers need to <i>preserve</i> the original textual representation of " +
            "properties internally in order to support JCS normalization requirements." + LINE_SEPARATOR +
            "Note that the <code>" + JSONSignatureDecoder.SIGNATURE_VALUE_JSON + "</code> " +
            "property including the comma (leading or trailing depending on the position of <code>" +
             JSONSignatureDecoder.SIGNATURE_VALUE_JSON + "</code> " + " in the <code>Signature</code> object), <b>must</b> be <i>excluded</i> from the normalization process.</li></ul>" +
            "Applied on the sample signature, a conforming JCS normalization process should return the following JSON object:" +
            "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>" +
            "{&quot;Now&quot;:&quot;2013-12-23T23:25:10+01:00&quot;,&quot;PaymentRequest&quot;:{&quot;Currency&quot;:&quot;USD&quot;,&quot;VAT&quot;:1.45,&quot;Specification&quot;:[{&quot;Units&quot;:3,&quot;Descr<br>" +
            "iption&quot;:&quot;USB cable&quot;,&quot;SKU&quot;:&quot;TR-46565666&quot;,&quot;UnitPrice&quot;:<b style=\"color:red;background:Yellow\">4.50</b>},{&quot;Units&quot;:1,&quot;Description&quot;:&quot;4G Router&quot;,&quot;SKU&quot;:&quot;JK-56566655&quot;,<br>" +
            "&quot;UnitPrice&quot;:39.99}]},&quot;EscapeMe&quot;:&quot;<b style=\"color:red;background:Yellow\">\\u000f\\n</b>A'<b style=\"color:red;background:Yellow\">B</b>\\\\\\&quot;<b style=\"color:red;background:Yellow\">/</b>&quot;,&quot;Signature&quot;:{&quot;Algorithm&quot;:&quot;http://www.w3.org/2001/04/xmldsig-more<br>" +
            "#ecdsa-sha256&quot;,&quot;KeyInfo&quot;:{&quot;PublicKey&quot;:{&quot;EC&quot;:{&quot;NamedCurve&quot;:&quot;http://xmlns.webpki.org/sks/algorithm#ec.nist.p256&quot;,&quot;X&quot;:<br>" +
            "&quot;lNxNvAUEE8t7DSQBft93LVSXxKCiVjhbWWfyg023FCk&quot;,&quot;Y&quot;:&quot;LmTlQxXB3LgZrNLmhOfMaCnDizczC_RfQ6Kx8iNwfFA&quot;}}}}}</code></div>" +
            "The text in <code><b style=\"color:red;background:Yellow\">red</b></code> highlights the core of the normalization process. " +
            "<i>Note that the output string was folded for improving readability</i>. " + LINE_SEPARATOR +
            "The signature can now be validated using the method specified in <a href=\"#Signature." + JSONSignatureDecoder.SIGNATURE_VALUE_JSON + "\">" + 
            JSONSignatureDecoder.SIGNATURE_VALUE_JSON + "</a>. " + LINE_SEPARATOR +
            "Path validation (when applicable), is out of scope for JCS, but is <i>preferably</i> carried out as described in X.509 " +
            json.createReference (JSONBaseHTML.REF_X509) +
            "." + LINE_SEPARATOR +
            "The next sections cover the JCS format.");
        
        json.addDataTypesDescription ("JCS consists of a top-level <code>" + JSONSignatureDecoder.SIGNATURE_JSON + "</code> property holding a composite JSON object. " + LINE_SEPARATOR);

        json.addProtocolTableEntry ("JCS Objects")
          .append ("The following tables describe the JCS JSON structures in detail.");
        
        json.setAppendixMode ();

        json.addParagraphObject ("Multiple Signatures").append (
            "Since JSON properties are single-valued, JCS does not intrinsically support multiple signings of the same object. " +
            "Although it would be technically feasible using an array of signature objects, this would greatly complicate message normalization. " +
            "However, there is a &quot;workaround&quot; which fits most real-world scenarios needing multiple signatures and that is using wrapping signatures. " + LINE_SEPARATOR +
            "Original signed JSON object:" +
    "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>{<br>" +
    "&nbsp;&nbsp;&quot;TimeStamp&quot;: &quot;2013-08-30T07:56:08+02:00&quot;,<br>" +
    "&nbsp;&nbsp;&quot;ID&quot;: &quot;lADU_sO067Wlgoo52-9L&quot;,<br>" +
    "&nbsp;&nbsp;&quot;Data&quot;: [&quot;One&quot;,&quot;Two&quot;,&quot;Three&quot;],<br>" +
    "&nbsp;&nbsp;&quot;Signature&quot;:<br>" +
    "&nbsp;&nbsp;&nbsp;&nbsp;{<br>" +
    "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</code><i>Original signature...</i><code><br>" +
    "&nbsp;&nbsp;&nbsp;&nbsp;}<br>" +
    "}</code></div>" +
    "Dual-signed JSON object:" +
    "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>{<br>" +
    "&nbsp;&nbsp;&quot;Container&quot;:<br>" +
    "&nbsp;&nbsp;&nbsp;&nbsp;{<br>" +
    "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;TimeStamp&quot;: &quot;2013-08-30T07:56:08+02:00&quot;,<br>" +
    "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;ID&quot;: &quot;lADU_sO067Wlgoo52-9L&quot;,<br>" +
    "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;Data&quot;: [&quot;One&quot;,&quot;Two&quot;,&quot;Three&quot;],<br>" +
    "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;Signature&quot;:<br>" +
    "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{<br>" +
    "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</code><i>Original signature...</i><code><br>" +
    "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br>" +
    "&nbsp;&nbsp;&nbsp;&nbsp;},<br>" +
    "&nbsp;&nbsp;&quot;Signature&quot;:<br>" +
    "&nbsp;&nbsp;&nbsp;&nbsp;{<br>" +
    "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</code><i>Wrapping signature...</i><code><br>" +
    "&nbsp;&nbsp;&nbsp;&nbsp;}<br>" +
    "}</code></div>" +
            "That is, using JCS there is no distinction between multiple signatures and counter-signatures.");

        json.addParagraphObject ("Usage in Applications").append ("JCS as well as the freestanding sub-objects <a href=\"#" + 
            JSONSignatureDecoder.KEY_INFO_JSON + "." + JSONSignatureDecoder.PUBLIC_KEY_JSON + "\">" +
            JSONSignatureDecoder.PUBLIC_KEY_JSON + "</a> and <a href=\"#" +
            JSONSignatureDecoder.KEY_INFO_JSON + "." + JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON + "\">" +
            JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON +
            "</a>, have been successfully integrated in a proof-of-concept application running on Android ")
         .append (json.createReference (JSONBaseHTML.REF_WEBPKI_FOR_ANDROID))
         .append ("." + LINE_SEPARATOR +
         "This application is based on an integrated " +
         "JSON encoder, decoder and signature solution which makes the code comparatively easy to grasp:" +
         "<div style=\"padding:10pt 0pt 0pt 20pt\"><code>" +
        "public void signAndVerifyJCS (final PublicKey public_key, final PrivateKey private_key) throws IOException<br>" +
        "&nbsp;&nbsp;{<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;// Create an empty JSON document<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;JSONObjectWriter writer = new JSONObjectWriter ();<br>" +
        "&nbsp;<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;// Fill it with some data<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;writer.setString (&quot;MyProperty&quot;, &quot;Some data&quot;);<br>" +
        "&nbsp;<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;// Sign the document<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;writer.setSignature (new JSONAsymKeySigner (new AsymKeySignerInterface ()<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;@Override<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public byte[] signData (byte[] data, AsymSignatureAlgorithms algorithm) throws IOException<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;try<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;Signature signature = Signature.getInstance (algorithm.getJCEName ()) ;<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;signature.initSign (private_key);<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;signature.update (data);<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return signature.sign ();<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;catch (Exception e)<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;throw new IOException (e);<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br>" +
        "&nbsp;<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;@Override<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;public PublicKey getPublicKey () throws IOException<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return public_key;<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}));<br>" +
        "&nbsp;<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;// Serialize the document<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;byte[] json = writer.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT);<br>" +
        "&nbsp;<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;// Print the signed document on the console<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;System.out.println (&quot;Signed doc:\\n&quot; + new String (json, &quot;UTF-8&quot;));<br>" +
        "&nbsp;<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;// Parse the document<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;JSONObjectReader reader = JSONParser.parse (json);<br>" +
        "&nbsp;<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;// Get and verify the signature<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;JSONSignatureDecoder json_signature = reader.getSignature ();<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;json_signature.verify (new JSONAsymKeyVerifier (public_key));<br>" +
        "&nbsp;<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;// Print the document payload on the console<br>" +
        "&nbsp;&nbsp;&nbsp;&nbsp;System.out.println (&quot;Returned data: &quot; + reader.getString (&quot;MyProperty&quot;));<br>" +
        "&nbsp;&nbsp;}" +
        "</code></div>");

        json.addParagraphObject ("Aknowledgements").append ("During the initial phases of the design process, highly appreciated " +
                                 "feedback were provided by Manu&nbsp;Sporny, Jim&nbsp;Klo, James&nbsp;Manger, " +
                                 "Jeffrey&nbsp;Walton, David&nbsp;Chadwick, Jim&nbsp;Schaad, David&nbsp;Waite, " +
                                 "Douglas&nbsp;Crockford, Arne&nbsp;Riiber, Brian&nbsp;Campbell and others."
                                 + LINE_SEPARATOR +
        "Funding has been provided by <i>PrimeKey Solutions AB</i> and the <i>Swedish Innovation Board (VINNOVA)</i>.");
        
        json.addReferenceTable ();
        
        json.addDocumentHistoryLine ("2013-12-17", "0.3", "Initial publication in HTML5");
        json.addDocumentHistoryLine ("2013-12-20", "0.4", "Changed from Base64 to Base64URL everywhere");
        json.addDocumentHistoryLine ("2013-12-29", "0.5", "Added the <code>" + JSONSignatureDecoder.EXTENSIONS_JSON + "</code> facility");
        json.addDocumentHistoryLine ("2014-01-21", "0.51", "Added clarification to public key parameter representation");
        json.addDocumentHistoryLine ("2014-01-26", "0.52", "Added note regarding the <code>" + JSONSignatureDecoder.SIGNATURE_CERTIFICATE_JSON + "</code> option");
        json.addDocumentHistoryLine ("2014-04-15", "0.53", "Embedded <code>bigint</code> in JS <i>string</i> making syntax fully JSON compatible");
        json.addDocumentHistoryLine ("2014-09-17", "0.54", "Changed canonicalization to normalization");

        json.addParagraphObject ("Author").append ("JCS was developed by Anders Rundgren (<code>anders.rundgren.net@gmail.com</code>) as a part " +
                                                   "of the SKS/KeyGen2 project " +
                                                   "(<a href=\"https://code.google.com/p/openkeystore\">https://code.google.com/p/openkeystore</a>).");

        json.addProtocolTable ("Top-level Property")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.SIGNATURE_JSON)
              .addLink (JSONSignatureDecoder.SIGNATURE_JSON)
            .newColumn ()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("The mandatory top-level property");
            
        json.addJSONSignatureDefinitions (true, "", "");

        json.writeHTML ();
      }
  }
