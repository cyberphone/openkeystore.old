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
        
        json.addParagraphObject ().append ("<p style=\"text-align:center\"><span style=\"" + JSONBaseHTML.HEADER_STYLE + "\">JCS</span>" +
            "<br><span style=\"font-size:" + JSONBaseHTML.SECTION_FONT_SIZE + "\">&nbsp;<br>JSON Cleartext Signature</span></p>");
        
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
            "To cope with the primary disadvantage (the dependency on " +
            "canonicalization), this part has been extremely simplified compared to XML&nbsp;DSig.");

        json.addParagraphObject ("Sample Signature").append (
"The following <i>cryptographically verifiable</i> sample signature is used to visualize the JCS specification:" +
"<div style=\"padding:10pt 0pt 10pt 20pt\"><code>" +
"{<br>" +
"&nbsp;&nbsp;&quot;Now&quot;:&nbsp;&quot;2013-12-10T19:54:13+01:00&quot;,<br>"+
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
"&nbsp;&nbsp;&quot;EscapeMe&quot;:&nbsp;&quot;\\u000F\\u000aA\\u0042\\\\\\&quot;\\/&quot;,<br>"+
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
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;X&quot;:&nbsp;&quot;lNxNvAUEE8t7DSQBft93LVSXxKCiVjhbWWfyg023FCk=&quot;,<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;Y&quot;:&nbsp;&quot;LmTlQxXB3LgZrNLmhOfMaCnDizczC/RfQ6Kx8iNwfFA=&quot;<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;},<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;SignatureValue&quot;:&nbsp;&quot;MEYCIQD8i2bwhYFogxRIMcawEfjqImuajyEIAUTIsHPPMgT/BgIhALmbeKL+Nyz9SftY3PkYYJCiqu+53LMTqiiOH3SwMvJs&quot;<br>"+
"&nbsp;&nbsp;&nbsp;&nbsp;}<br>"+
"}</code></div>" +
"The sample signature’s payload consists of the properties above <code>Signature</code>. " +
"Note: JCS does <i>not</i> mandate any specific ordering of properties like in the sample.");

        json.addParagraphObject ("Signature Scope").append (
            "The scope of a signature (=what is actually signed) comprises all " +
            "properties including possible child objects of the JSON " +
            "object holding the <code>Signature</code> property except for the actual <code>" + JSONSignature.SIGNATURE_VALUE_JSON + "</code> property.");

        json.addParagraphObject ("Canonicalization").append (
            "Prerequisite: A JSON object in accordance with the rules outlined in ")
          .append (json.createReference (JSONBaseHTML.REF_JSON))
          .append ("." + LINE_SEPARATOR +
            "Parsing Restrictions:<ul>" +
            "<li>The original property order <b>must</b> be preserved.</li>" +
            "<li style=\"padding-top:4pt\">Property names <b>must not</b> be empty (<code>&quot;&quot;</code>)." +
            "<li style=\"padding-top:4pt\">Property names within an object <b>must</b> be <i>unique</i>.</li>" +
            "</ul>The canonicalization steps are as follows:<ul>" +
            "<li>Whitespace <b>must</b> be removed which in practical terms means removal of all characters outside of quoted strings having a value <= ASCII space (0x32).</li>" +
            "<li style=\"padding-top:4pt\">JSON <code>'\\/'</code> escape sequences <b>must</b> be honored on <i>input</i> within quoted strings but be treated as a degenerate equivalents to <code>'/'</code> by rewriting them.</li>" +
            "<li style=\"padding-top:4pt\">Unicode escape sequences (<code>'\\uhhhh'</code>) within quoted strings <b>must</b> be normalized. " +
            "If the Unicode value falls within the traditional ASCII control character range (0x00 - 0x1f), " +
            "it <b>must</b> be rewritten in lower-case hexadecimal notation unless it is one of the pre-defined " +
            "JSON escapes (<code>'\\n'</code> etc.) because the latter have precedence. If the Unicode value is " +
            "outside of the ASCII control character range, it <b>must</b> be replaced by the corresponding Unicode character.</li>" +
            "<li style=\"padding-top:4pt\">The JSON object associated with the <code>Signature</code> <b>must</b> now be " +
            "<i>recreated</i> using the actual text left after applying the previous measures. <i>Rationale</i>: JSON numbers are ambiguously defined (&quot;unnormalized&quot;) " +
            "which means that a decoding/encoding sequence may produce a different representation compared to the original. " +
            "As an example, monetary data is often expressed like <code>4.50</code> in spite of the " +
            "trailing zero being redundant. Similar quirks are also likely to show-up in non-native JSON types " +
            "(stored in quoted strings), such as dates due to time-zone or resolution differences. To cope with these " +
            "potential problems, compliant parsers need to preserve the original textual representation of " +
            "properties internally in order to support JCS canonicalization." + LINE_SEPARATOR +
            "Note that the <code>" + JSONSignature.SIGNATURE_VALUE_JSON + "</code> " +
            "property including the comma (leading or trailing depending on the position of <code>" +
             JSONSignature.SIGNATURE_VALUE_JSON + "</code> " + " in the <code>Signature</code> object), <b>must</b> be <i>excluded</i> from the canonicalization process.</li></ul>" +
            "Applied on the sample signature, a proper canonicalization implementation should return the following JSON object:" +
            "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>" +
"{&quot;Now&quot;:&quot;2013-12-10T19:54:13+01:00&quot;,&quot;PaymentRequest&quot;:{&quot;Currency&quot;:&quot;USD&quot;,&quot;VAT&quot;:1.45,&quot;Specification&quot;:[{&quot;Units&quot;:3,&quot;Descr<br>" +
"iption&quot;:&quot;USB cable&quot;,&quot;SKU&quot;:&quot;TR-46565666&quot;,&quot;UnitPrice&quot;:<b style=\"color:red;background:Yellow\">4.50</b>},{&quot;Units&quot;:1,&quot;Description&quot;:&quot;4G Router&quot;,&quot;SKU&quot;:&quot;JK-56566655&quot;,<br>" +
"&quot;UnitPrice&quot;:39.99}]},&quot;EscapeMe&quot;:&quot;<b style=\"color:red;background:Yellow\">\\u000f\\n</b>A<b style=\"color:red;background:Yellow\">B</b>\\\\\\&quot;<b style=\"color:red;background:Yellow\">/</b>&quot;,&quot;Signature&quot;:{&quot;Algorithm&quot;:&quot;http://www.w3.org/2001/04/xmldsig-more#<br>" +
"ecdsa-sha256&quot;,&quot;KeyInfo&quot;:{&quot;PublicKey&quot;:{&quot;EC&quot;:{&quot;NamedCurve&quot;:&quot;http://xmlns.webpki.org/sks/algorithm#ec.nist.p256&quot;,&quot;X&quot;:&quot;<br>" +
"lNxNvAUEE8t7DSQBft93LVSXxKCiVjhbWWfyg023FCk=&quot;,&quot;Y&quot;:&quot;LmTlQxXB3LgZrNLmhOfMaCnDizczC/RfQ6Kx8iNwfFA=&quot;}}}}}</code></div>" +
"The text in <code><b style=\"color:red;background:Yellow\">red</b></code> highlights the core of the canonicalization process. " +
"<i>Note that the output string was folded for improving readability</i>. " + LINE_SEPARATOR +
"For a description on how the canonicalized data is to be used, see <a href=\"#Signature." + JSONSignature.SIGNATURE_VALUE_JSON + "\">" + 
 JSONSignature.SIGNATURE_VALUE_JSON + "</a>.");
        
        json.addParagraphObject ("Multiple Signatures").append (
        "Since JSON properties are single-valued, JCS does not intrinsically support multiple signings of the same object. " +
        "Although it would be technically feasible using an array of signature objects, this would greatly complicate canonicalization. " +
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

        json.addDataTypesDescription ("JCS consists of a top-level <code>" + JSONSignatureDecoder.SIGNATURE_JSON + "</code> property holding a composite JSON object. " + LINE_SEPARATOR);

        json.addProtocolTableEntry ();

        json.addParagraphObject ("Aknowledgements").append ("During the initial phases of the design process, highly appreciated " +
                                 "feedback were provided by Manu&nbsp;Sporny, Jim&nbsp;Klo, James&nbsp;Manger, " +
                                 "Jeffrey&nbsp;Walton, David&nbsp;Chadwick, Jim&nbsp;Schaad, David&nbsp;Waite, " +
                                 "Douglas&nbsp;Crockford, Arne&nbsp;Riiber, Brian&nbsp;Campbell and others.");
        
        json.addReferenceTable ();
        
        json.addDocumentHistoryLine ("2013-12-17", "0.3", "Initial publication in HTML");

        json.addParagraphObject ("Author").append ("JCS was developed by Anders Rundgren (<code>anders.rundgren.net@gmail.com</code>) as a part " +
                                                   "of the SKS/KeyGen2 project " +
                                                   "(<a href=\"https://code.google.com/p/openkeystore\">https://code.google.com/p/openkeystore</a>).");

        json.addProtocolTable ("JCS Top-level Property")
        .newRow ()
          .newColumn ()
            .addProperty (JSONSignature.SIGNATURE_JSON)
            .addLink (JSONSignature.SIGNATURE_JSON)
          .newColumn ()
            .setType (WEBPKI_DATA_TYPES.OBJECT)
          .newColumn ()
          .newColumn ()
            .addString ("The mandatory top-level property");
            
        json.addJSONSignatureDefinitions (true);

        json.writeHTML ();
      }
  }
