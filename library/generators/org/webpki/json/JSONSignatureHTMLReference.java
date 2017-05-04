/*
 *  Copyright 2006-2016 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
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
public class JSONSignatureHTMLReference extends JSONBaseHTML.Types {
    
    static JSONBaseHTML json;
    static RowInterface row;
    
    private static final String INTEROPERABILITY = "Interoperability";

    private static final String ECMASCRIPT_MODE  = "ECMAScript Mode";
    
    private static final String SAMPLE_SIGNATURE = "Sample Signature";

    public static void main (String args[]) throws IOException {
        json = new JSONBaseHTML(args, "JCS - JSON Cleartext Signature");
        
        json.addParagraphObject().append("<div style=\"margin-top:200pt;margin-bottom:200pt;text-align:center\"><span style=\"" + JSONBaseHTML.HEADER_STYLE + "\">JCS</span>" +
            "<br><span style=\"font-size:" + JSONBaseHTML.CHAPTER_FONT_SIZE + "\">&nbsp;<br>JSON Cleartext Signature</span></div>");
        
        json.addTOC();

        json.addParagraphObject("Introduction").append("JCS is a scheme for signing data expressed as JSON ")
          .append(json.createReference(JSONBaseHTML.REF_JSON))
          .append(" objects, loosely modeled after XML&nbsp;DSig's ")
          .append(json.createReference(JSONBaseHTML.REF_XMLDSIG))
          .append(" &quot;enveloped&quot; signatures. " +
            "Compared to its XML counterpart JCS is quite primitive but on the other hand it has proved to be " +
            "simple to implement and use." +
            Types.LINE_SEPARATOR +
            "Unlike JWS ")
          .append(json.createReference(JSONBaseHTML.REF_JWS))
          .append(
            " which was designed for signing <i>any</i> kind of data, " +
            "a JCS signature is intended to be an <i>integral part of a JSON object</i> " +
            "with message centric systems like Yasmin ")
          .append(json.createReference(JSONBaseHTML.REF_YASMIN))
          .append(" as the primary target. " +
            "This concept was not originally considered " +
            "due to the lack of a standardized normalization method for JSON data. " +
            "However, version 6 of ECMAScript ")
           .append(json.createReference(JSONBaseHTML.REF_ES6))
           .append(" introduced a <i>predictable serialization</i> scheme which enables both <i>data</i> " +
            "and <i>header information</i> to be featured as clear text." + Types.LINE_SEPARATOR +
            "In order to make library support of JCS straightforward in spite of having a different structure compared to JWS ")
          .append(json.createReference(JSONBaseHTML.REF_JWS))
          .append(", JCS supports the same algorithms ")
          .append(json.createReference(JSONBaseHTML.REF_JWA))
          .append(" as well as using JWK ")
          .append(json.createReference(JSONBaseHTML.REF_JWK))
          .append(" for representing public key data. " + Types.LINE_SEPARATOR +
            "Since JCS is rooted in ECMAScript" +
            ", JCS may also be used for &quot;in-object&quot; JavaScript signatures, " +
             "making JCS suitable for HTML5 applications. See " +
             "<a href=\"#" + JSONBaseHTML.makeLink(ECMASCRIPT_MODE) + 
             "\"><span style=\"white-space:nowrap\">" +
             ECMASCRIPT_MODE + "</span></a>." + Types.LINE_SEPARATOR +
             "There is also a &quot;companion&quot; specification coined JEF ")
          .append(json.createReference(JSONBaseHTML.REF_JEF))
          .append(" which deals with JSON encryption.");

        json.addParagraphObject(SAMPLE_SIGNATURE).append(
"The following <i>cryptographically verifiable</i> sample signature is used to visualize the JCS specification:" +
"<div style=\"padding:10pt 0pt 10pt 20pt\"><code>" +
"{<br>" +
"&nbsp;&nbsp;&quot;now&quot;:&nbsp;&quot;2017-04-16T11:23:06Z&quot;,<br>" +
"&nbsp;&nbsp;&quot;escapeMe&quot;:&nbsp;&quot;\\u20ac$\\u000F\\u000aA'\\u0042\\u0022\\u005c\\\\\\&quot;\\/&quot;,<br>" +
"&nbsp;&nbsp;&quot;numbers&quot;:&nbsp;[1e+30,4.5,6],<br>" +
"&nbsp;&nbsp;&quot;signature&quot;:&nbsp;{<br>" +
"&nbsp;&nbsp;&nbsp;&nbsp;&quot;algorithm&quot;:&nbsp;&quot;ES256&quot;,<br>" +
"&nbsp;&nbsp;&nbsp;&nbsp;&quot;publicKey&quot;:&nbsp;{<br>" +
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;kty&quot;:&nbsp;&quot;EC&quot;,<br>" +
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;crv&quot;:&nbsp;&quot;P-256&quot;,<br>" +
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;x&quot;:&nbsp;&quot;vlYxD4dtFJOp1_8_QUcieWCW-4KrLMmFL2rpkY1bQDs&quot;,<br>" +
"&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&quot;y&quot;:&nbsp;&quot;fxEF70yJenP3SPHM9hv-EnvhG6nXr3_S-fDqoj-F6yM&quot;<br>" +
"&nbsp;&nbsp;&nbsp;&nbsp;}<span style=\"background:#f0f0f0\">,</span><br>" +
"&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"background:#f0f0f0\">&quot;value&quot;:&nbsp;&quot;hp6af4GTZMr2fM8A1QeanPD4IcvlV0ToiKA0NDrtsmyGxDQST24ehsAVRzVHXSGM1O1GG0xO3ev4LbvNNRpH5g&quot;</span><br>" +
"&nbsp;&nbsp;}<br>" +
"}" +
"</code></div>" +
"The sample signature's payload consists of the properties above <code>" + JSONSignatureDecoder.SIGNATURE_JSON + "</code>. " +
"Note: JCS does <i>not</i> mandate any specific ordering of properties like in the sample.");

        json.addParagraphObject("Signature Scope").append(
            "The scope of a signature (what is actually signed) comprises all " +
            "properties including possible child objects of the JSON " +
            "object holding the <code>" + JSONSignatureDecoder.SIGNATURE_JSON +
            "</code> property except for the <code>" + JSONSignatureDecoder.VALUE_JSON + "</code> property (shaded area in the sample).");

        json.addParagraphObject("Normalization and Signature Validation").append(
            "Prerequisite: A JSON object in accordance with ")
          .append(json.createReference(JSONBaseHTML.REF_JSON))
          .append(" containing a properly formatted <code>" + JSONSignatureDecoder.SIGNATURE_JSON + "</code> sub-object." + LINE_SEPARATOR +
            "Parsing restrictions:<ul>" +
            "<li>The original property serialization order <b>must</b> be <i>preserved</i>.</li>" +
            "<li style=\"padding-top:4pt\">Property names <b>must not</b> be empty (<code>&quot;&quot;</code>)." +
            "<li style=\"padding-top:4pt\">Property names within an object <b>must</b> be <i>unique</i>.</li>" +
            "<li style=\"padding-top:4pt\">There <b>must not</b> be any not here defined properties inside of the <code>" + JSONSignatureDecoder.SIGNATURE_JSON + "</code> sub object." +
            "</ul>The normalization steps are as follows:<ul>" +
            "<li>The <code>" + JSONSignatureDecoder.VALUE_JSON + "</code> property " +
            "(including leading <i>or</i> trailing <code>','</code>) <b>must</b> be deleted from the " +
            "<code>" + JSONSignatureDecoder.SIGNATURE_JSON + "</code> sub object.</li>" +
            "<li style=\"padding-top:4pt\">Whitespace <b>must</b> be removed which in practical terms means removal of all characters outside of quoted strings " +
            "having a value of x09, x0a, x0d or x20.</li>" +
            "<li style=\"padding-top:4pt\">JSON <code>'\\/'</code> escape sequences <b>must</b> be honored on <i>input</i> within quoted strings but be treated as a &quot;degenerate&quot; equivalents to <code>'/'</code> by rewriting them.</li>" +
            "<li style=\"padding-top:4pt\">Unicode escape sequences (<code>'\\uhhhh'</code>) within quoted strings <b>must</b> be adjusted as follows: " +
            "If the Unicode value falls within the traditional ASCII control character range (0x00 - 0x1f), " +
            "it <b>must</b> be rewritten in lower-case hexadecimal notation unless it is one of the pre-defined " +
            "JSON escapes (<code>'\\n'</code> etc.) because the latter have precedence. If the Unicode value is " +
            "outside of the ASCII control character range, it <b>must</b> be replaced by the corresponding Unicode character " +
            "with the exception of <code>'&quot;'</code> and <code>'\\'</code> which always <b>must</b> be escaped as well.</li>" +
            "<li style=\"padding-top:4pt\">The JSON <code>Number</code> type <b>must</b> <i>already before validation</i> be "+
            "serialized according to ECMAScript " +
            json.createReference(JSONBaseHTML.REF_ES6) +
            " including the V8 " +
            json.createReference(JSONBaseHTML.REF_V8) +
            " option in order to achieve interoperability between different platforms and implementations.</li>" +
            "<li style=\"padding-top:4pt\">Now the JSON object associated with the <code>" +
            JSONSignatureDecoder.SIGNATURE_JSON + "</code> <b>must</b> be " +
            "<i>recreated</i> using the actual text left after applying the previous measures." + LINE_SEPARATOR +
            "Also see <a href=\"#" + INTEROPERABILITY + "\">" + INTEROPERABILITY + "</a> and " +
            "<a href=\"#" + JSONBaseHTML.makeLink(ECMASCRIPT_MODE) + 
            "\"><span style=\"white-space:nowrap\">" +
            ECMASCRIPT_MODE + "</span></a>." + LINE_SEPARATOR +
         "</li></ul>" +
            "Applied on the sample signature, a conforming JCS normalization process should return the following JSON string:" +
            "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>" +
            "{&quot;now&quot;:&quot;2017-04-16T11:23:06Z&quot;,&quot;escapeMe&quot;:&quot;" +
            "<b style=\"color:red;background:Yellow\">&#x20ac</b>$<b style=\"color:red;background:Yellow\">" +
            "\\u000f\\nA</b>'B<b style=\"color:red;background:Yellow\">\\&quot;\\\\</b>\\\\\\&quot;" +
            "<b style=\"color:red;background:Yellow\">/</b>&quot;,&quot;numbers&quot;:[1e+30,4.5,6],&quot;signature&quot;:<br>" +
            "{&quot;algorithm&quot;:&quot;ES256&quot;,&quot;publicKey&quot;:{&quot;kty&quot;" +
            ":&quot;EC&quot;,&quot;crv&quot;:&quot;P-256&quot;,&quot;x&quot;:&quot;vlYxD4dtFJOp1_8_QUcieWCW-4KrLMmFL2rpkY<br>" +
            "1bQDs&quot;,&quot;y&quot;:&quot;fxEF70yJenP3SPHM9hv-EnvhG6nXr3_S-fDqoj-F6yM&quot;}}}" +
            "</code></div>" +
            "The text in <code><b style=\"color:red;background:Yellow\">red</b></code> highlights the string normalization process. " +
            "<i>Note that the output string was folded for improving readability</i>. " + LINE_SEPARATOR +
            "The signature <code>" + JSONSignatureDecoder.VALUE_JSON + "</code> can now be calculated by running the algorithm specified in the <code>" +
                  JSONSignatureDecoder.ALGORITHM_JSON + "</code> property using the signature key over the " +
                  "<span style=\"white-space:nowrap\">UTF-8</span> representation of the " +
                  "normalized data." + LINE_SEPARATOR +
            "Path validation (when applicable), is out of scope for JCS, but is <i>preferably</i> carried out as described in X.509 " +
            json.createReference(JSONBaseHTML.REF_X509) +
            "." + LINE_SEPARATOR +
            "The next sections cover the JCS format.");
        
        json.addDataTypesDescription("JCS consists of a top-level <code>" + JSONSignatureDecoder.SIGNATURE_JSON + "</code> property holding a composite JSON object. " + LINE_SEPARATOR);

        json.addProtocolTableEntry("JCS Objects")
          .append("The following tables describe the JCS JSON structures in detail.");
        
        json.setAppendixMode();

        json.addParagraphObject(ECMASCRIPT_MODE).append("ECMAScript mode in this context refers to " +
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
           "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;kty:&nbsp;&quot;EC&quot;,<br>" +
           "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;crv:&nbsp;&quot;P-256&quot;,<br>" +
           "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;x:&nbsp;&quot;vlYxD4dtFJOp1_8_QUcieWCW-4KrLMmFL2rpkY1bQDs&quot;,<br>" +
           "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;y:&nbsp;&quot;fxEF70yJenP3SPHM9hv-EnvhG6nXr3_S-fDqoj-F6yM&quot;<br>" +
           "&nbsp;&nbsp;&nbsp;&nbsp;},<br>" +
           "&nbsp;&nbsp;&nbsp;&nbsp;value:&nbsp;&quot;bEkQ2Owed_oe8MbZjSTXffHOINm2fV5y7GzmGwdH9JrP6fV57tjuxLHQD-wf9eOp-zpu2U_v3RZgaobBkt9rNA&quot;<br>" +
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
            .append(json.createReference(JSONBaseHTML.REF_WEB_CRYPTO))
            .append("<code><br>" +
            "&nbsp;&nbsp;crypto.subtle.importKey('jwk',&nbsp;clone.publicKey,&nbsp;&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;JCS&nbsp;public&nbsp;key&nbsp;is&nbsp;a&nbsp;JWK</span><br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{&nbsp;name:&nbsp;'ECDSA',&nbsp;namedCurve:&nbsp;clone.publicKey.crv&nbsp;},<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;true,&nbsp;['verify']).then(function(publicKey)&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;crypto.subtle.verify({&nbsp;name:&nbsp;'ECDSA',&nbsp;hash:&nbsp;{&nbsp;name:&nbsp;'SHA-256'&nbsp;}&nbsp;},&nbsp;<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;publicKey,&nbsp;signature,&nbsp;data).then(function(result)&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.debug('Success='&nbsp;+&nbsp;result);<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;});<br>" +
            "&nbsp;&nbsp;});<br>" +
            "}<br>" +
            "<br>" +
            "verifySignature(signedObject);<br></code></div>" + LINE_SEPARATOR +
            "<b>Constraint when using JCS with ECMAScript</b>" + LINE_SEPARATOR +
            "If numeric property names are used, they <b>must</b> be " +
            "<i>provided in ascending numeric order</i> and inserted <i>before</i> possible non-numeric properties.");

        json.addParagraphObject("Multiple Signatures").append(
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

        json.addParagraphObject("Usage in Applications").append("JCS as well as the freestanding sub-objects <a href=\"#" + 
            JSONSignatureDecoder.SIGNATURE_JSON + "." + JSONSignatureDecoder.PUBLIC_KEY_JSON + "\">" +
            JSONSignatureDecoder.PUBLIC_KEY_JSON + "</a> and <a href=\"#" +
            JSONSignatureDecoder.SIGNATURE_JSON + "." + JSONSignatureDecoder.CERTIFICATE_PATH_JSON + "\">" +
            JSONSignatureDecoder.CERTIFICATE_PATH_JSON +
            "</a>, have been utilized in a proof-of-concept application ")
         .append(json.createReference(JSONBaseHTML.REF_WEBPKI_FOR_ANDROID))
         .append(" running on Android." + LINE_SEPARATOR +
         "The sample code below is based on the Java reference implementation ")
         .append(json.createReference(JSONBaseHTML.REF_OPENKEYSTORE))
         .append(" which features an integrated " +
         "JSON encoder, decoder and signature solution:" +
         "<div style=\"padding:10pt 0pt 0pt 20pt\"><code>" +
         "public&nbsp;void&nbsp;signAndVerifyJCS(PrivateKey&nbsp;privateKey,&nbsp;PublicKey&nbsp;publicKey)&nbsp;throws&nbsp;IOException&nbsp;{<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Create&nbsp;an&nbsp;empty&nbsp;JSON&nbsp;document</span><br>" +
         "&nbsp;&nbsp;JSONObjectWriter&nbsp;writer&nbsp;=&nbsp;new&nbsp;JSONObjectWriter();<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Fill&nbsp;it&nbsp;with&nbsp;some&nbsp;data</span><br>" +
         "&nbsp;&nbsp;writer.setString(&quot;myProperty&quot;,&nbsp;&quot;Some&nbsp;data&quot;);<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Sign&nbsp;document</span><br>" +
         "&nbsp;&nbsp;writer.setSignature(new&nbsp;JSONAsymKeySigner(privateKey,&nbsp;publicKey,&nbsp;null));<br>" +
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
        
        json.addParagraphObject(INTEROPERABILITY).append("Since serialization of floating point numbers as specified by JCS is " +
         "(at the time of writing) not available for all platforms, you <i>may</i> for highest possible " + 
         "interoperability need to put such data in quotes.  Albeit a limitation, financial data is not natively supported by JSON either " +
         "due to the fact that JavaScript lacks support for big decimals.  Note the handling of " +
         "<a href=\"#" + JSONSignatureDecoder.SIGNER_CERTIFICATE_JSON + "." + JSONSignatureDecoder.SERIAL_NUMBER_JSON +
         "\">certificate serial numbers</a> in JCS." + LINE_SEPARATOR +
         "JCS compatible reference implementations are available both for server Java and Android ")
         .append(json.createReference(JSONBaseHTML.REF_OPENKEYSTORE))
         .append(". These implementations use ECMAScript number serialization when <i>creating</i> JSON data, making them compliant "+
         "with browsers and Node.js as well." +
         LINE_SEPARATOR + 
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

        json.addParagraphObject("Acknowledgements").append("During the initial phases of the design process, highly appreciated " +
       "feedback were provided by Manu&nbsp;Sporny, Jim&nbsp;Klo, " +
       "Jeffrey&nbsp;Walton, David&nbsp;Chadwick, Jim&nbsp;Schaad, Mike&nbsp;Jones, David&nbsp;Waite, " +
       "Douglas&nbsp;Crockford, Arne&nbsp;Riiber, Brian&nbsp;Campbell, Sergey&nbsp;Beryozkin, and others."
       + LINE_SEPARATOR +
       "Special thanks go to James&nbsp;Manger who pointed out the ECMAScript ")
       .append(json.createReference(JSONBaseHTML.REF_ES6))
       .append(" number serialization scheme as well as reviewing a related Internet draft." + LINE_SEPARATOR +
        "Funding has been provided by <i>PrimeKey Solutions AB</i> and the <i>Swedish Innovation Board (VINNOVA)</i>.");
        
        json.addReferenceTable();
        
        json.addDocumentHistoryLine("2013-12-17", "0.3", "Initial publication in HTML5");
        json.addDocumentHistoryLine("2013-12-20", "0.4", "Changed from Base64 to Base64URL everywhere");
        json.addDocumentHistoryLine("2013-12-29", "0.5", "Added the <code>" + JSONSignatureDecoder.EXTENSIONS_JSON + "</code> facility");
        json.addDocumentHistoryLine("2014-01-21", "0.51", "Added clarification to public key parameter representation");
        json.addDocumentHistoryLine("2014-01-26", "0.52", "Added note regarding the <code>" + JSONSignatureDecoder.SIGNER_CERTIFICATE_JSON + "</code> option");
        json.addDocumentHistoryLine("2014-04-15", "0.53", "Embedded <code>bigint</code> in JS <i>string</i> making syntax fully JSON compatible");
        json.addDocumentHistoryLine("2014-09-17", "0.54", "Changed canonicalization to normalization");
        json.addDocumentHistoryLine("2014-09-23", "0.55", "Aligned EC parameter representation with JWS " + json.createReference(JSONBaseHTML.REF_JWS));
        json.addDocumentHistoryLine("2014-12-08", "0.56", "Removed " + json.createReference(JSONBaseHTML.REF_XMLDSIG) + " bloat and added support for JWA " + json.createReference(JSONBaseHTML.REF_JWS) + " algorithm identifiers");
        json.addDocumentHistoryLine("2014-12-19", "0.57", "Added an interoperability section");
        json.addDocumentHistoryLine("2015-01-12", "0.58", "Added clarification to signature <code>" + JSONSignatureDecoder.VALUE_JSON + "</code> representation");
        json.addDocumentHistoryLine("2016-01-11", "0.59", "Added ECMAScript compatibility mode");
        json.addDocumentHistoryLine("2017-04-19", "0.60", "Changed public keys to use JWK " + json.createReference(JSONBaseHTML.REF_JWK) + " format");

        json.addParagraphObject("Author").append("JCS was developed by Anders Rundgren (<code>anders.rundgren.net@gmail.com</code>) as a part " +
                                                 "of the OpenKeyStore project " +
                                                 json.createReference(JSONBaseHTML.REF_OPENKEYSTORE)  + ".");

        json.addProtocolTable("Top-level Property")
          .newRow()
            .newColumn()
              .addProperty (JSONSignatureDecoder.SIGNATURE_JSON)
              .addLink(JSONSignatureDecoder.SIGNATURE_JSON)
            .newColumn()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn()
            .newColumn()
              .addString("The mandatory top-level property");
            
        json.addJSONSignatureDefinitions(true, "", "", true);

        json.writeHTML();
    }
}
