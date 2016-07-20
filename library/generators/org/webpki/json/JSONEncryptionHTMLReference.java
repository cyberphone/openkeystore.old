/*
 *  Copyright 2006-2015 WebPKI.org (http://webpki.org).
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
import org.webpki.json.JSONBaseHTML.ProtocolObject.Row.Column;
import org.webpki.json.JSONBaseHTML.Types.WEBPKI_DATA_TYPES;

/**
 * Create an HTML description of the JSON Clear-text Signature system.
 * 
 * @author Anders Rundgren
 */
public class JSONEncryptionHTMLReference extends JSONBaseHTML.Types
  {
    
    static JSONBaseHTML json;
    static RowInterface row;
    static String ECDH_PROPERTIES = "Additional ECDH properties";
    static String RSA_PROPERTIES = "Additional RSA encryption properties";
    
    private static final String INTEROPERABILITY = "Interoperability";

    private static final String ECMASCRIPT_MODE  = "ECMAScript Compatibility Mode";
    
    private static final String SAMPLE_SIGNATURE = "Sample Signature";

    static Column preAmble (String qualifier) throws IOException {
        return json.addProtocolTable (qualifier)
            .newRow ()
                .newColumn ()
                    .addProperty (JSONSignatureDecoder.VERSION_JSON)
                    .addValue (JSONDecryptionDecoder.ENCRYPTION_VERSION_ID)
                .newColumn ()
                    .setType (Types.WEBPKI_DATA_TYPES.URI)
                .newColumn ()
                    .setUsage (false)
                .newColumn ()
                    .addString ("Encryption object version identifier." +
                                " For future revisions of JEF, this property would be mandatory.")
            .newRow ()
                .newColumn ()
                    .addProperty (JSONSignatureDecoder.ALGORITHM_JSON)
                    .addSymbolicValue (JSONSignatureDecoder.ALGORITHM_JSON)
                .newColumn ()
                    .setType (Types.WEBPKI_DATA_TYPES.URI)
                .newColumn ()
                .newColumn ();
    }
    
    public static void main (String args[]) throws IOException
      {
        json = new JSONBaseHTML (args, "JEF - JSON Encryption Format");
        
        json.addParagraphObject ().append ("<div style=\"margin-top:200pt;margin-bottom:200pt;text-align:center\"><span style=\"" + JSONBaseHTML.HEADER_STYLE + "\">JEF</span>" +
            "<br><span style=\"font-size:" + JSONBaseHTML.CHAPTER_FONT_SIZE + "\">&nbsp;<br>JSON Encryption Format</span></div>");
        
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
            "Unlike IETF's JWS ")
          .append (json.createReference (JSONBaseHTML.REF_JWS))
          .append (
            ", <i>JCS was designed to be an integral part of a JSON object</i> " +
            "rather than embedding arbitrary signed data.  There are (of course) pros and cons to both " +
            "approaches, but for information-rich messaging, " +
            "clear-text data at least have an advantage for documentation and debugging. " +
            "To cope with the primary drawback (the potential dependency on " +
            "canonicalization), this part has been extremely simplified. "+
            "In fact, JCS only relies on <i>predictable serialization</i> of JSON data." + Types.LINE_SEPARATOR +
            "In order to make library support of JCS straightforward in spite of having a different structure compared to JWS ")
          .append (json.createReference (JSONBaseHTML.REF_JWS))
          .append (", JCS supports the same algorithms, curve names, signature blob representation, and public key objects. " +
            "The only crypto object that differs is JWS's &quot;<code>x5c</code>&quot; since it (presumably for historical reasons), uses Base64 ")
          .append (json.createReference (JSONBaseHTML.REF_BASE64))
          .append (" rather than Base64URL encoding." + Types.LINE_SEPARATOR +
            "Thanks to <i>predictable serialization</i> introduced in ECMAScript ")
          .append (json.createReference (JSONBaseHTML.REF_ES6))
          .append (", JCS may also be used for &quot;in-object&quot; JavaScript signatures, " +
             "making JCS ideal for HTML5 applications. See " +
             "<a href=\"#" + JSONBaseHTML.makeLink(ECMASCRIPT_MODE) + 
             "\"><span style=\"white-space:nowrap\">" +
             ECMASCRIPT_MODE + "</span></a>.");

        json.addParagraphObject (SAMPLE_SIGNATURE).append (
"The following <i>cryptographically verifiable</i> sample signature is used to visualize the JCS specification:" +
"<div style=\"padding:10pt 0pt 10pt 20pt\"><code>" +
"{<br>" +
"&nbsp;&nbsp;&quot;now&quot;:&nbsp;&quot;2015-01-12T09:22:36Z&quot;,<br>" +
"&nbsp;&nbsp;&quot;escapeMe&quot;:&nbsp;&quot;\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\&quot;\\/&quot;,<br>" +
"&nbsp;&nbsp;&quot;numbers&quot;:&nbsp;[1e0,&nbsp;4.50,&nbsp;6],<br>" +
"&nbsp;&nbsp;&quot;signature&quot;:&nbsp;{<br>" +
"&nbsp;&nbsp;&nbsp;&nbsp;&quot;algorithm&quot;:&nbsp;&quot;ES256&quot;,<br>" +
"&nbsp;&nbsp;&nbsp;&nbsp;&quot;publicKey&quot;:&nbsp;{<br>" +
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;type&quot;:&nbsp;&quot;EC&quot;,<br>" +
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;curve&quot;:&nbsp;&quot;P-256&quot;,<br>" +
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;x&quot;:&nbsp;&quot;lNxNvAUEE8t7DSQBft93LVSXxKCiVjhbWWfyg023FCk&quot;,<br>" +
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;y&quot;:&nbsp;&quot;LmTlQxXB3LgZrNLmhOfMaCnDizczC_RfQ6Kx8iNwfFA&quot;<br>" +
"&nbsp;&nbsp;&nbsp;&nbsp;}<span style=\"background:#f0f0f0\">,</span><br>" +
"&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"background:#f0f0f0\">&quot;value&quot;:&nbsp;&quot;C1qP8PghKOl6NT8gpoy6cDI1Uzls_o8mYECYnWT-CkRaIaiZd9u_4nDKRhQvjbbeWZ1FiHPMs3TKmXIBSCuUHg&quot;</span><br>" +
"&nbsp;&nbsp;}<br>" +
"}</code></div>" +
"The sample signature's payload consists of the properties above <code>" + JSONSignatureDecoder.SIGNATURE_JSON + "</code>. " +
"Note: JCS does <i>not</i> mandate any specific ordering of properties like in the sample.");

        json.addParagraphObject ("Signature Scope").append (
            "The scope of a signature (what is actually signed) comprises all " +
            "properties including possible child objects of the JSON " +
            "object holding the <code>" + JSONSignatureDecoder.SIGNATURE_JSON +
            "</code> property except for the <code>" + JSONSignatureDecoder.VALUE_JSON + "</code> property (shaded area in the sample).");

        json.addParagraphObject ("Normalization and Signature Validation").append (
            "Prerequisite: A JSON object in accordance with ")
          .append (json.createReference (JSONBaseHTML.REF_JSON))
          .append (" containing a properly formatted <code>" + JSONSignatureDecoder.SIGNATURE_JSON + "</code> sub-object." + LINE_SEPARATOR +
            "Parsing restrictions:<ul>" +
            "<li>The original property serialization order <b>must</b> be <i>preserved</i>.</li>" +
            "<li style=\"padding-top:4pt\">Property names <b>must not</b> be empty (<code>&quot;&quot;</code>)." +
            "<li style=\"padding-top:4pt\">Property names within an object <b>must</b> be <i>unique</i>.</li>" +
            "</ul>The normalization steps are as follows:<ul>" +
            "<li>Whitespace <b>must</b> be removed which in practical terms means removal of all characters outside of quoted strings " +
            "having a value of x09, x0a, x0d or x20.</li>" +
            "<li style=\"padding-top:4pt\">JSON <code>'\\/'</code> escape sequences <b>must</b> be honored on <i>input</i> within quoted strings but be treated as a &quot;degenerate&quot; equivalents to <code>'/'</code> by rewriting them.</li>" +
            "<li style=\"padding-top:4pt\">Unicode escape sequences (<code>'\\uhhhh'</code>) within quoted strings <b>must</b> be adjusted as follows: " +
            "If the Unicode value falls within the traditional ASCII control character range (0x00 - 0x1f), " +
            "it <b>must</b> be rewritten in lower-case hexadecimal notation unless it is one of the pre-defined " +
            "JSON escapes (<code>'\\n'</code> etc.) because the latter have precedence. If the Unicode value is " +
            "outside of the ASCII control character range, it <b>must</b> be replaced by the corresponding Unicode character " +
            "with the exception of <code>'&quot;'</code> and <code>'\\'</code> which always <b>must</b> be escaped as well.</li>" +
            "<li style=\"padding-top:4pt\">The JSON object associated with the <code>" + JSONSignatureDecoder.SIGNATURE_JSON + "</code> <b>must</b> now be " +
            "<i>recreated</i> using the actual text left after applying the previous measures. <i>Rationale</i>: JSON numbers are ambiguously defined (&quot;unnormalized&quot;) " +
            "which means that a decoding/encoding sequence may produce a different representation compared to the original. " +
            "As an example, floating point data is often expressed like <code>4.50</code> in spite of the " +
            "trailing zero being redundant. To cope with this " +
            "potential problem, compliant parsers <b>must</b> <i>preserve</i> the original textual representation of " +
            "properties internally in order to support JCS normalization requirements. " + LINE_SEPARATOR +
            "Also see <a href=\"#" + INTEROPERABILITY + "\">" + INTEROPERABILITY + "</a> and " +
            "<a href=\"#" + JSONBaseHTML.makeLink(ECMASCRIPT_MODE) + 
            "\"><span style=\"white-space:nowrap\">" +
            ECMASCRIPT_MODE + "</span></a>." + LINE_SEPARATOR +
            "Note that the <code>" + JSONSignatureDecoder.VALUE_JSON + "</code> " +
            "property including the comma (leading or trailing depending on the position of <code>" +
             JSONSignatureDecoder.VALUE_JSON + "</code> " + " in the <code>" + JSONSignatureDecoder.SIGNATURE_JSON +
             "</code> object), <b>must</b> be <i>excluded</i> from the normalization process.</li></ul>" +
            "Applied on the sample signature, a conforming JCS normalization process should return the following JSON string:" +
            "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>" +

            "{&quot;now&quot;:&quot;2015-01-12T09:22:36Z&quot;,&quot;escapeMe&quot;:&quot;<b style=\"color:red;background:Yellow\">&#x20AC;</b>$<b style=\"color:red;background:Yellow\">\\u000f\\n</b>A'<b style=\"color:red;background:Yellow\">B\\&quot;\\\\</b>\\\\\\&quot;<b style=\"color:red;background:Yellow\">/</b>&quot;,&quot;numbers&quot;:[<b style=\"color:red;background:Yellow\">1e0</b>,<b style=\"color:red;background:Yellow\">4.50</b>,6],&quot;signature&quot;:<br>" +
            "{&quot;algorithm&quot;:&quot;ES256&quot;,&quot;publicKey&quot;:{&quot;type&quot;:&quot;EC&quot;,&quot;curve&quot;:&quot;P-256&quot;,&quot;x&quot;:&quot;lNxNvAUEE8t7DSQBft93LVSXxKCiVjhbWW<br>" +
            "fyg023FCk&quot;,&quot;y&quot;:&quot;LmTlQxXB3LgZrNLmhOfMaCnDizczC_RfQ6Kx8iNwfFA&quot;}}}</code></div>" +
            "The text in <code><b style=\"color:red;background:Yellow\">red</b></code> highlights the core of the normalization process. " +
            "<i>Note that the output string was folded for improving readability</i>. " + LINE_SEPARATOR +
            "The signature <code>" + JSONSignatureDecoder.VALUE_JSON + "</code> can now be calculated by running the algorithm specified in the <code>" +
                  JSONSignatureDecoder.ALGORITHM_JSON + "</code> property using the signature key over the " +
                  "<span style=\"white-space:nowrap\">UTF-8</span> representation of the " +
                  "normalized data." + LINE_SEPARATOR +
            "Path validation (when applicable), is out of scope for JCS, but is <i>preferably</i> carried out as described in X.509 " +
            json.createReference (JSONBaseHTML.REF_X509) +
            "." + LINE_SEPARATOR +
            "The next sections cover the JCS format.");
        
        json.addDataTypesDescription ("JEF containers always start with a top-level JSON object. " + LINE_SEPARATOR);

        json.addProtocolTableEntry ("JEF Objects")
          .append ("The following tables describe the JEF JSON structures in detail.");
        
        json.setAppendixMode ();

        json.addParagraphObject (ECMASCRIPT_MODE).append ("ECMAScript mode in this context refers to " +
           "the ability to sign JavaScript objects as well as using the standard JSON support for parsing and " +
           "creating signed data." + LINE_SEPARATOR + 
           "The code snippet below shows a signed JavaScript object:" +
           "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>var&nbsp;signedObject&nbsp;=&nbsp;{<br>" +
           "&nbsp;&nbsp;<span style=\"color:green\">// The data</span><br>" +
           "&nbsp;&nbsp;statement:&nbsp;&quot;Hello&nbsp;signed&nbsp;world!&quot;,<br>" +
           "&nbsp;&nbsp;otherProperties:&nbsp;[2000,&nbsp;true],<br>" +
           "&nbsp;&nbsp;<span style=\"color:green\">// The signature</span><br>" +
           "&nbsp;&nbsp;signature:&nbsp;{<br>" +
           "&nbsp;&nbsp;&nbsp;&nbsp;algorithm:&nbsp;&quot;ES256&quot;,<br>" +
           "&nbsp;&nbsp;&nbsp;&nbsp;publicKey:&nbsp;{<br>" +
           "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;type:&nbsp;&quot;EC&quot;,<br>" +
           "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;curve:&nbsp;&quot;P-256&quot;,<br>" +
           "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x:&nbsp;&quot;vlYxD4dtFJOp1_8_QUcieWCW-4KrLMmFL2rpkY1bQDs&quot;,<br>" +
           "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;y:&nbsp;&quot;fxEF70yJenP3SPHM9hv-EnvhG6nXr3_S-fDqoj-F6yM&quot;<br>" +
           "&nbsp;&nbsp;&nbsp;&nbsp;},<br>" +
           "&nbsp;&nbsp;&nbsp;&nbsp;value:&nbsp;&quot;2H__TkcV28QpGWPkyVbR1CW0I8L4xARrVGL0LjOeHJLOPozdzRqCTyYfmAippJXqdzgNAonnFPVCSI5A6novMQ&quot;<br>" +
           "&nbsp;&nbsp;}<br>" +
           "};</code></div>" +
           "This signature could be verified by the following code:" +
           "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>function&nbsp;convertToUTF8(string)&nbsp;{<br>" +
            "&nbsp;&nbsp;var&nbsp;buffer&nbsp;=&nbsp;[];<br>" +
            "&nbsp;&nbsp;for&nbsp;(var&nbsp;i&nbsp;=&nbsp;0;&nbsp;i&nbsp;&lt;&nbsp;string.length;&nbsp;i++)&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;var&nbsp;c&nbsp;=&nbsp;string.charCodeAt(i);<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;if&nbsp;(c&nbsp;&lt;&nbsp;128)&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;buffer.push(c);<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;}&nbsp;else&nbsp;if&nbsp;((c&nbsp;&gt;&nbsp;127)&nbsp;&amp;&amp;&nbsp;(c&nbsp;&lt;&nbsp;2048))&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;buffer.push((c&nbsp;&gt;&gt;&nbsp;6)&nbsp;|&nbsp;0xC0);<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;buffer.push((c&nbsp;&amp;&nbsp;0x3F)&nbsp;|&nbsp;0x80);<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;}&nbsp;else&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;buffer.push((c&nbsp;&gt;&gt;&nbsp;12)&nbsp;|&nbsp;0xE0);<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;buffer.push(((c&nbsp;&gt;&gt;&nbsp;6)&nbsp;&amp;&nbsp;0x3F)&nbsp;|&nbsp;0x80);<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;buffer.push((c&nbsp;&amp;&nbsp;0x3F)&nbsp;|&nbsp;0x80);<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;}<br>" +
            "&nbsp;&nbsp;}<br>" +
            "&nbsp;&nbsp;return&nbsp;new&nbsp;Uint8Array(buffer);<br>" +
            "}<br>" +
            "<br>" +
            "function&nbsp;decodeBase64URL(encoded)&nbsp;{<br>" +
            "&nbsp;&nbsp;var&nbsp;string&nbsp;=&nbsp;atob(encoded.replace(/-/g,'+').replace(/_/g,'/'));<br>" +
            "&nbsp;&nbsp;var&nbsp;buffer&nbsp;=&nbsp;[];<br>" +
            "&nbsp;&nbsp;for&nbsp;(var&nbsp;i&nbsp;=&nbsp;0;&nbsp;i&nbsp;&lt;&nbsp;string.length;&nbsp;i++)&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;buffer.push(string.charCodeAt(i));<br>" +
            "&nbsp;&nbsp;}<br>" +
            "&nbsp;&nbsp;return&nbsp;new&nbsp;Uint8Array(buffer);<br>" +
            "}<br>" +
            "<br>" +
            "function&nbsp;verifySignature(jcs)&nbsp;{<br>" +
            "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Perform&nbsp;JCS&nbsp;normalization</span><br>" +
            "&nbsp;&nbsp;var&nbsp;clone&nbsp;=&nbsp;Object.assign({},&nbsp;jcs.signature);&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Clone&nbsp;&quot;signature&quot;&nbsp;child object</span><br>" +
            "&nbsp;&nbsp;var&nbsp;signature&nbsp;=&nbsp;decodeBase64URL(clone.value);&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Get&nbsp;signature&nbsp;value</span><br>" +
            "&nbsp;&nbsp;delete&nbsp;jcs.signature.value;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Remove&nbsp;signature&nbsp;&quot;value&quot;&nbsp;property&nbsp;from&nbsp;signed&nbsp;object</span><br>" +
            "&nbsp;&nbsp;var&nbsp;data&nbsp;=&nbsp;convertToUTF8(JSON.stringify(jcs));&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Get&nbsp;normalized&nbsp;JSON&nbsp;string (signed data)</span><br>" +
            "&nbsp;&nbsp;jcs.signature&nbsp;=&nbsp;clone;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Restore&nbsp;signed&nbsp;object</span><br>" +
            "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Perform&nbsp;the&nbsp;actual&nbsp;crypto,&nbsp;here&nbsp;using&nbsp;W3C&nbsp;WebCrypto</span> </code>")
            .append (json.createReference (JSONBaseHTML.REF_WEB_CRYPTO))
            .append("<code><br>" +
            "&nbsp;&nbsp;crypto.subtle.importKey('jwk',&nbsp;{&nbsp;kty:&nbsp;clone.publicKey.type,&nbsp;<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;crv:&nbsp;clone.publicKey.curve,<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x:&nbsp;clone.publicKey.x,<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;y:&nbsp;clone.publicKey.y&nbsp;},<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{&nbsp;name:&nbsp;'ECDSA',&nbsp;namedCurve:&nbsp;clone.publicKey.curve&nbsp;},<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;true,&nbsp;['verify']).then(function(publicKey)&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;crypto.subtle.verify({&nbsp;name:&nbsp;'ECDSA',&nbsp;hash:&nbsp;{&nbsp;name:&nbsp;'SHA-256'&nbsp;}&nbsp;},&nbsp;<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;publicKey,&nbsp;signature,&nbsp;data).then(function(result)&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.debug('Success='&nbsp;+&nbsp;result);<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;});<br>" +
            "&nbsp;&nbsp;});<br>" +
            "}<br>" +
            "<br>" +
            "verifySignature(signedObject);<br></code></div>" + LINE_SEPARATOR +
            "<b>Constraints</b>" + LINE_SEPARATOR +
            "In order to use JCS with ECMAScript, the following <i>additional</i> constraints <b>must</b> " +
            "be taken in consideration:" +
            "<ul><li>Numbers <b>must</b> be expressed as specified by EMCAScript ")
            .append (json.createReference (JSONBaseHTML.REF_ES6))
            .append (" using the improved serialization algorithm featured in Google's V8 JavaScript engine ")
            .append (json.createReference (JSONBaseHTML.REF_V8))
            .append (". That is, in the ECMAScript compatibility mode <i>there are no requirements saving the textual value of numbers</i>. " +
                     "This also means that the JCS <a href=\"#" + JSONBaseHTML.makeLink(SAMPLE_SIGNATURE) + 
            "\"><span style=\"white-space:nowrap\">" +
            SAMPLE_SIGNATURE + "</span></a> in <i>incompatible</i> with the ECMAScript mode since it uses unnormalized numbers.</li>" +
            "<li style=\"padding-top:4pt\">If numeric property names are used, they <b>must</b> be " +
            "<i>provided in ascending numeric order</i> and inserted <i>before</i> possible non-numeric properties.</li>" +
            "</ul>" +
            "This level of compliance with the JCS specification is referred to as &quot;JCS/ES6&quot;.");

        json.addParagraphObject ("Multiple Signatures").append (
            "Since JSON properties are single-valued, JCS does not intrinsically support multiple signings of the same object. " +
            "Although it would be technically feasible using an array of signature objects, this would greatly complicate message normalization. " +
            "However, there is a &quot;workaround&quot; which fits most real-world scenarios needing multiple signatures and that is using wrapping signatures. " + LINE_SEPARATOR +
            "Original signed JSON object:" +
            "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>{<br>" +
            "&nbsp;&nbsp;&quot;timeStamp&quot;: &quot;2014-12-08T13:56:08Z&quot;,<br>" +
            "&nbsp;&nbsp;&quot;id&quot;: &quot;lADU_sO067Wlgoo52-9L&quot;,<br>" +
            "&nbsp;&nbsp;&quot;data&quot;: [&quot;One&quot;,&quot;Two&quot;,&quot;Three&quot;],<br>" +
            "&nbsp;&nbsp;&quot;" + JSONSignatureDecoder.SIGNATURE_JSON + "&quot;:&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;<span style=\"font-size:15pt\">&nbsp;</span></code><i>Original signature...</i><code><br>" +
            "&nbsp;&nbsp;}<br>" +
            "}</code></div>" +
            "Dual-signed JSON object:" +
            "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>{<br>" +
            "&nbsp;&nbsp;&quot;container&quot;:&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&quot;timeStamp&quot;: &quot;2014-12-08T13:56:08Z&quot;,<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&quot;id&quot;: &quot;lADU_sO067Wlgoo52-9L&quot;,<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&quot;data&quot;: [&quot;One&quot;,&quot;Two&quot;,&quot;Three&quot;],<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&quot;" + JSONSignatureDecoder.SIGNATURE_JSON + "&quot;:&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"font-size:15pt\">&nbsp;</span></code><i>Original signature...</i><code><br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;}<br>" +
            "&nbsp;&nbsp;},<br>" +
            "&nbsp;&nbsp;&quot;" + JSONSignatureDecoder.SIGNATURE_JSON + "&quot;:&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;<span style=\"font-size:15pt\">&nbsp;</span></code><i>Wrapping signature...</i><code><br>" +
            "&nbsp;&nbsp;}<br>" +
            "}</code></div>" +
            "That is, using JCS there is no distinction between multiple signatures and counter-signatures.");

        json.addParagraphObject ("Usage in Applications").append ("JCS as well as the freestanding sub-objects <a href=\"#" + 
            JSONSignatureDecoder.SIGNATURE_JSON + "." + JSONSignatureDecoder.PUBLIC_KEY_JSON + "\">" +
            JSONSignatureDecoder.PUBLIC_KEY_JSON + "</a> and <a href=\"#" +
            JSONSignatureDecoder.SIGNATURE_JSON + "." + JSONSignatureDecoder.CERTIFICATE_PATH_JSON + "\">" +
            JSONSignatureDecoder.CERTIFICATE_PATH_JSON +
            "</a>, have been utilized in a proof-of-concept application ")
         .append (json.createReference (JSONBaseHTML.REF_WEBPKI_FOR_ANDROID))
         .append (" running on Android." + LINE_SEPARATOR +
         "The sample code below is based on the Java reference implementation ")
         .append (json.createReference (JSONBaseHTML.REF_OPENKEYSTORE))
         .append(" which features an integrated " +
         "JSON encoder, decoder and signature solution:" +
         "<div style=\"padding:10pt 0pt 0pt 20pt\"><code>" +
         "public&nbsp;void&nbsp;signAndVerifyJCS(final&nbsp;PublicKey&nbsp;publicKey,&nbsp;final&nbsp;PrivateKey&nbsp;privateKey)&nbsp;throws&nbsp;IOException&nbsp;{<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Create&nbsp;an&nbsp;empty&nbsp;JSON&nbsp;document</span><br>" +
         "&nbsp;&nbsp;JSONObjectWriter&nbsp;writer&nbsp;=&nbsp;new&nbsp;JSONObjectWriter();<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Fill&nbsp;it&nbsp;with&nbsp;some&nbsp;data</span><br>" +
         "&nbsp;&nbsp;writer.setString(&quot;myProperty&quot;,&nbsp;&quot;Some&nbsp;data&quot;);<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Sign&nbsp;document</span><br>" +
         "&nbsp;&nbsp;writer.setSignature(new&nbsp;JSONAsymKeySigner(new&nbsp;AsymKeySignerInterface()&nbsp;{<br>" +
         "&nbsp;&nbsp;&nbsp;&nbsp;@Override<br>" +
         "&nbsp;&nbsp;&nbsp;&nbsp;public&nbsp;byte[]&nbsp;signData&nbsp;(byte[]&nbsp;data,&nbsp;AsymSignatureAlgorithms&nbsp;algorithm)&nbsp;throws&nbsp;IOException&nbsp;{<br>" +
         "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;try&nbsp;{<br>" +
         "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return&nbsp;new&nbsp;SignatureWrapper(algorithm,&nbsp;privateKey).update(data).sign();<br>" +
         "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}&nbsp;catch&nbsp;(GeneralSecurityException&nbsp;e)&nbsp;{<br>" +
         "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;throw&nbsp;new&nbsp;IOException(e);<br>" +
         "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;}<br>" +
         "&nbsp;&nbsp;&nbsp;&nbsp;}<br>" +
         "&nbsp;&nbsp;&nbsp;&nbsp;@Override<br>" +
         "&nbsp;&nbsp;&nbsp;&nbsp;public&nbsp;PublicKey&nbsp;getPublicKey()&nbsp;throws&nbsp;IOException&nbsp;{<br>" +
         "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;return&nbsp;publicKey;<br>" +
         "&nbsp;&nbsp;&nbsp;&nbsp;}<br>" +
         "&nbsp;&nbsp;}));<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Serialize&nbsp;document</span><br>" +
         "&nbsp;&nbsp;String&nbsp;json&nbsp;=&nbsp;writer.toString();<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Print&nbsp;document&nbsp;on&nbsp;the&nbsp;console</span><br>" +
         "&nbsp;&nbsp;System.out.println(&quot;Signed&nbsp;doc:\n&quot;&nbsp;+&nbsp;json);<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Parse&nbsp;document</span><br>" +
         "&nbsp;&nbsp;JSONObjectReader&nbsp;reader&nbsp;=&nbsp;JSONParser.parse(json);<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Get&nbsp;and&nbsp;verify&nbsp;signature</span><br>" +
         "&nbsp;&nbsp;JSONSignatureDecoder&nbsp;signature&nbsp;=&nbsp;reader.getSignature();<br>" +
         "&nbsp;&nbsp;signature.verify(new&nbsp;JSONAsymKeyVerifier(publicKey));<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Print&nbsp;document&nbsp;payload&nbsp;on&nbsp;the&nbsp;console</span><br>" +
         "&nbsp;&nbsp;System.out.println(&quot;Returned&nbsp;data:&nbsp;&quot;&nbsp;+&nbsp;reader.getString(&quot;myProperty&quot;));<br>" +
         "}</code></div>");
        
        json.addParagraphObject (INTEROPERABILITY).append ("Since serialization of floating point numbers as specified by JCS is " +
         "(at the time of writing) not a standard feature, it is <b>recommended</b> " + 
         "putting such data in quotes.  Albeit a limitation, financial data is not natively supported by JSON either " +
         "due to the fact that JavaScript lacks support for big decimals.  Note the handling of " +
         "<a href=\"#" + JSONSignatureDecoder.SIGNER_CERTIFICATE_JSON + "." + JSONSignatureDecoder.SERIAL_NUMBER_JSON +
         "\">certificate serial numbers</a> in JCS." + LINE_SEPARATOR +
         "JSON tool designers could also consider implementing the " +
         "<a href=\"#" + JSONBaseHTML.makeLink(ECMASCRIPT_MODE) + 
         "\"><span style=\"white-space:nowrap\">" +
         ECMASCRIPT_MODE + "</span></a> since it presumably requires very moderate adjustments of existing code." + LINE_SEPARATOR +
         "Fully JCS compatible reference implementations ")
         .append(json.createReference (JSONBaseHTML.REF_OPENKEYSTORE))
         .append (" are available both for Java and JavaScript." +
         " These implementations use ECMAScript number serialization when <i>creating</i> JSON data, making them compliant "+
         "with the <a href=\"#" + JSONBaseHTML.makeLink(ECMASCRIPT_MODE) + 
         "\"><span style=\"white-space:nowrap\">" + ECMASCRIPT_MODE + "</span></a> as well." + LINE_SEPARATOR + 
         "Pyhton users can get the required parser behavior (modulo floating point data...) by using the following constructs:<div style=\"padding:10pt 0pt 0pt 20pt\"><code>" +
         "jsonObject = json.loads(jcsSignedData,object_pairs_hook=collections.OrderedDict)&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"color:green\"># Parse JSON while keeping original property order</span><br>" +
         "signatureObject = jsonObject['" + JSONSignatureDecoder.SIGNATURE_JSON + 
          "']&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" +
          "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"color:green\"># As described in this document</span><br>" +
         "clonedSignatureObject = collections.OrderedDict(signatureObject)" +
          "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" +
         "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"color:green\"># For non-destructive signature validation</span><br>" +
         "signatureValue = signatureObject.pop('" + JSONSignatureDecoder.VALUE_JSON + "')" +
         "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" +
         "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"color:green\"># In Base64URL notation</span><br>" +
         "normalizedSignedData = json.dumps(jsonObject,separators=(',',':'),ensure_ascii=False)" +
         "&nbsp;&nbsp;<span style=\"color:green\"># In Unicode</span><br>" +
         "jsonObject['" + JSONSignatureDecoder.SIGNATURE_JSON + "'] = clonedSignatureObject" +
         "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;" +
         "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"color:green\"># Restore JSON object" + 
         "</span></code></div><div style=\"padding:5pt 0pt 0pt 200pt\"><i>... Signature Validation Code ...</i></div>");   

        json.addParagraphObject ("Acknowledgements").append ("During the initial phases of the design process, highly appreciated " +
       "feedback were provided by Manu&nbsp;Sporny, Jim&nbsp;Klo, " +
       "Jeffrey&nbsp;Walton, David&nbsp;Chadwick, Jim&nbsp;Schaad, David&nbsp;Waite, " +
       "Douglas&nbsp;Crockford, Arne&nbsp;Riiber, Brian&nbsp;Campbell, Sergey&nbsp;Beryozkin, and others."
       + LINE_SEPARATOR +
       "Special thanks go to James&nbsp;Manger who pointed out the ECMAScript ")
       .append (json.createReference (JSONBaseHTML.REF_ES6))
       .append(" number serialization scheme as well as reviewing a related Internet draft." + LINE_SEPARATOR +
        "Funding has been provided by <i>PrimeKey Solutions AB</i> and the <i>Swedish Innovation Board (VINNOVA)</i>.");
        
        json.addReferenceTable ();
        
        json.addDocumentHistoryLine ("2013-12-17", "0.3", "Initial publication in HTML5");
        json.addDocumentHistoryLine ("2013-12-20", "0.4", "Changed from Base64 to Base64URL everywhere");
        json.addDocumentHistoryLine ("2013-12-29", "0.5", "Added the <code>" + JSONSignatureDecoder.EXTENSIONS_JSON + "</code> facility");
        json.addDocumentHistoryLine ("2014-01-21", "0.51", "Added clarification to public key parameter representation");
        json.addDocumentHistoryLine ("2014-01-26", "0.52", "Added note regarding the <code>" + JSONSignatureDecoder.SIGNER_CERTIFICATE_JSON + "</code> option");
        json.addDocumentHistoryLine ("2014-04-15", "0.53", "Embedded <code>bigint</code> in JS <i>string</i> making syntax fully JSON compatible");
        json.addDocumentHistoryLine ("2014-09-17", "0.54", "Changed canonicalization to normalization");
        json.addDocumentHistoryLine ("2014-09-23", "0.55", "Aligned EC parameter representation with " + json.createReference (JSONBaseHTML.REF_JWS));
        json.addDocumentHistoryLine ("2014-12-08", "0.56", "Major upgrade including removal of " + json.createReference (JSONBaseHTML.REF_XMLDSIG) + " bloat and adding support for " + json.createReference (JSONBaseHTML.REF_JWS) + " algorithm identifiers");
        json.addDocumentHistoryLine ("2014-12-19", "0.57", "Added an interoperability section");
        json.addDocumentHistoryLine ("2015-01-12", "0.58", "Added clarification to signature <code>" + JSONSignatureDecoder.VALUE_JSON + "</code> representation");
        json.addDocumentHistoryLine ("2016-01-11", "0.59", "Added ECMAScript compatibility mode");

        json.addParagraphObject ("Author").append ("JCS was developed by Anders Rundgren (<code>anders.rundgren.net@gmail.com</code>) as a part " +
                                                   "of the OpenKeyStore project " +
                                                   json.createReference (JSONBaseHTML.REF_OPENKEYSTORE)  + ".");

        preAmble("encryptedData")
            .addString ("Encryption object version identifier." +
                                    " For future revisions of JEF, this property would be mandatory.")
            .newRow ()
        .newColumn ()
            .addProperty (JSONSignatureDecoder.KEY_ID_JSON)
            .addSymbolicValue (JSONSignatureDecoder.KEY_ID_JSON)
        .newColumn ()
            .setType (Types.WEBPKI_DATA_TYPES.STRING)
        .newColumn ()
             .setChoice (false, 2)
        .newColumn ()
            .addString ("Encryption object version identifier." +
                        " For future revisions of JEF, this property would be mandatory.")
                        .newRow()

        .newColumn ()
        .addProperty(JSONDecryptionDecoder.ENCRYPTED_KEY_JSON)
        .addLink(JSONDecryptionDecoder.ENCRYPTED_KEY_JSON)
    .newColumn ()
        .setType (Types.WEBPKI_DATA_TYPES.OBJECT)
    .newColumn ()
    .newColumn ()
        .addString ("Encryption object version identifier." +
                    " For future revisions of JEF, this property would be mandatory.")
        .newRow ()
        .newColumn ()
          .addProperty(JSONDecryptionDecoder.CIPHER_TEXT_JSON)
          .addSymbolicValue(JSONDecryptionDecoder.CIPHER_TEXT_JSON)
        .newColumn ()
          .setType (Types.WEBPKI_DATA_TYPES.BASE64)
        .newColumn ()
        .newColumn ()
          .addString ("Encrypted data");
          
        preAmble("encryptedKey")
                .addString ("Key encryption algorithm. Currently the following JWE " +
                          json.createReference (JSONBaseHTML.REF_JWE) + " algorithms are recognized:<ul>" +
                 "<li>" + code20(JSONDecryptionDecoder.JOSE_ECDH_ES_ALG_ID) + "See: ")
                .addLink (ECDH_PROPERTIES)
        .addString ("</li><li>" + code20(JSONDecryptionDecoder.JOSE_RSA_OAEP_256_ALG_ID) + "See: ")
        .addLink (RSA_PROPERTIES)
        .addString ("</li></ul>");
        
        json.addSubItemTable(ECDH_PROPERTIES);

        json.addSubItemTable(RSA_PROPERTIES)
        .newRow ()
        .newColumn ()
          .addProperty (JSONSignatureDecoder.PUBLIC_KEY_JSON)
          .addLink (JSONSignatureDecoder.PUBLIC_KEY_JSON)
        .newColumn ()
          .setType (Types.WEBPKI_DATA_TYPES.OBJECT)
        .newColumn ()
        .newColumn ()
          .addString ("RSA public key")
        .newRow ()
        .newColumn ()
          .addProperty(JSONDecryptionDecoder.CIPHER_TEXT_JSON)
          .addSymbolicValue(JSONDecryptionDecoder.CIPHER_TEXT_JSON)
        .newColumn ()
          .setType (Types.WEBPKI_DATA_TYPES.BASE64)
        .newColumn ()
        .newColumn ()
          .addString ("Encrypted symmetric key");

        json.addSubItemTable (JSONSignatureDecoder.PUBLIC_KEY_JSON)
        .newRow ()
          .newColumn ()
            .addProperty (JSONSignatureDecoder.TYPE_JSON)
            .addValue (JSONSignatureDecoder.EC_PUBLIC_KEY)
          .newColumn ()
            .setType (Types.WEBPKI_DATA_TYPES.STRING)
          .newColumn ()
          .newColumn ()
            .addString ("EC key type indicator.  For the additional properties see: ");
  //          .addLink (JCS_PUBLIC_KEY_EC)

        json.writeHTML ();
      }

    static String code20(String string) {
        StringBuffer s = new StringBuffer("<code>").append(string);
        int i = string.length();
        while (i++ <= 20) {
            s.append("&nbsp;");
        }
        return s.append("</code>").toString();
    }
}
