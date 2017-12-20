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

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;

import java.util.Vector;

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.KeyStoreVerifier;

import org.webpki.json.JSONBaseHTML.RowInterface;
import org.webpki.json.JSONBaseHTML.Types;

import org.webpki.util.ArrayUtil;

/**
 * Create an HTML description of the JSON Clear-text Signature system.
 * 
 * @author Anders Rundgren
 */
public class JSONSignatureHTMLReference extends JSONBaseHTML.Types {
    
    static JSONBaseHTML json;
    static RowInterface row;
    
    static final String INTEROPERABILITY    = "Interoperability";

    static final String ECMASCRIPT_MODE     = "ECMAScript Mode";

    static final String TEST_VECTORS        = "Test Vectors";
    
    static final String MULTIPLE_SIGNATURES = "Multiple Signatures";

    static final String COUNTER_SIGNATURES  = "Counter Signatures";
    
    static final String SAMPLE_SIGNATURE    = "Sample Signature";

    static final String SECURITY_CONSIDERATIONS = "Security Considerations";

    static JSONObjectReader readJSON(String name) throws IOException {
        return JSONParser.parse(ArrayUtil.getByteArrayFromInputStream(JSONEncryptionHTMLReference.class.getResourceAsStream(name)));
    }
    
    static String formatCode(String code) {
        StringBuffer s = new StringBuffer("<div style=\"padding:10pt 0pt 10pt 20pt;word-break:break-all\"><code>");
        int lc = 0;
        for (char c : code.toCharArray()) {
            if (c == '\n') {
                lc = 0;
                s.append("<br>");
                continue;
            }
            if (lc == 109) {
                lc = 0;
                s.append("<br>");
            }
            if (c == ' ') {
                s.append("&nbsp;");
            } else if (c == '\"') {
                s.append("&quot;");
            } else {
                s.append(c);
            }
            lc++;
        }
        return s.append("</code></div>").toString();
    }
    
    static String formatCode(JSONObjectReader rd) {
        return formatCode(rd.toString());
    }

    static String formatCode(AsymKey asymKey) {
        return formatCode(asymKey.json);
    }
    
    static class AsymKey {
        String keyId;
        KeyPair keyPair;
        String json;
    }
    
    static AsymKey readAsymKey(String name) throws IOException {
        AsymKey asymKey = new AsymKey();
        JSONObjectReader key = json.readJson1(name);
        asymKey.json = key.toString();
        asymKey.keyId = key.getString("kid");
        key.removeProperty("kid");
        asymKey.keyPair = key.getKeyPair();
        return asymKey;
    }
    
    static String readSignature(String name) throws IOException {
        return new String(json.readFile2(name), "UTF-8");
    }
    
    static String readAsymSignature(String name, 
                                    AsymKey asymKey,
                                    JSONSignatureDecoder.Options options) throws IOException, GeneralSecurityException {
        String raw = readSignature(name);
        JSONObjectReader rd = JSONParser.parse(raw);
        JSONSignatureDecoder verifier = rd.getSignature(options);
        verifier.verify(new JSONAsymKeyVerifier(asymKey.keyPair.getPublic()));        
        return formatCode(raw);
    }

    static String readMultiSignature(String name, 
                                     AsymKey asymKey1,
                                     AsymKey asymKey2) throws IOException, GeneralSecurityException {
        String raw = readSignature(name);
        JSONObjectReader rd = JSONParser.parse(raw);
        Vector<JSONSignatureDecoder> verifiers = rd.getSignatures(new JSONSignatureDecoder.Options());
        verifiers.get(0).verify(new JSONAsymKeyVerifier(asymKey1.keyPair.getPublic()));
        verifiers.get(1).verify(new JSONAsymKeyVerifier(asymKey2.keyPair.getPublic()));
        return formatCode(raw);
    }

    static JSONX509Verifier certroot;

    static String readCertSignature(String name) throws IOException, GeneralSecurityException {
        String raw = readSignature(name);
        JSONParser.parse(raw).getSignature(new JSONSignatureDecoder.Options()).verify(certroot);
        return formatCode(raw);
    }

    static void updateNormalization(StringBuffer normalizedSampleSignature,
                                    String property,
                                    JSONObjectReader sampleSignatureDecoded) throws IOException {
        int i = normalizedSampleSignature.indexOf("\u0000");
        normalizedSampleSignature.deleteCharAt(i);
        normalizedSampleSignature.insert(i, sampleSignatureDecoded.getString(property));
    }
    
    static String readSymSignature(String[] encObjects) throws IOException, GeneralSecurityException {
        StringBuffer s = new StringBuffer();
        JSONObjectReader symmetricKeys = json.readJson1("symmetrickeys.json");
        for (String name : encObjects) {
            String signature = readSignature(name);
            JSONSignatureDecoder dec = JSONParser.parse(signature).getSignature(
                    new JSONSignatureDecoder.Options()
                        .setKeyIdOption(JSONSignatureDecoder.KEY_ID_OPTIONS.REQUIRED)
                        .setRequirePublicKeyInfo(false));
            for (String keyProp : symmetricKeys.getProperties()) {
                byte[] key = symmetricKeys.getBinary(keyProp);
                if (key.length == dec.getValue().length) {
                    s.append(LINE_SEPARATOR + "HMAC key named <code>&quot;")
                     .append(keyProp)
                     .append("&quot;</code> here provided in Base64URL notation:")
                     .append(formatCode(symmetricKeys.getString(keyProp)))
                     .append("Signature object requiring the key above for validation:")
                     .append(formatCode(signature));
                    dec.verify(new JSONSymKeyVerifier(key));
                    if (!keyProp.equals(dec.getKeyId())) {
                        throw new IOException("Sym sign");
                    }
                    break;
                }
            }
        }
        return s.toString();
    }

    public static void main (String args[]) throws Exception {
        json = new JSONBaseHTML(args, "JOSE/JCS - JSON Cleartext Signature");
        
        json.setFavIcon("../webpkiorg.png");

        AsymKey p256key = readAsymKey("p256privatekey.jwk");
        AsymKey p384key = readAsymKey("p384privatekey.jwk");
        AsymKey p521key = readAsymKey("p521privatekey.jwk");
        AsymKey r2048key = readAsymKey("r2048privatekey.jwk");

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load (null, null);
        keyStore.setCertificateEntry ("mykey",
                                      CertificateUtil.getCertificateFromBlob (json.readFile1("rootca.cer")));        
        certroot = new JSONX509Verifier(new KeyStoreVerifier(keyStore));
        
        json.addParagraphObject().append("<div style=\"margin-top:200pt;margin-bottom:200pt;text-align:center\"><span style=\"" + JSONBaseHTML.HEADER_STYLE + "\">JOSE-JCS</span>" +
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
           .append(" introduced a <i>predictable serialization</i> scheme which enables both <i>data " +
            "and header information to be provided in plain text</i>." + Types.LINE_SEPARATOR +
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

        String sampleSignature = readAsymSignature("p256keysigned.json", p256key, new JSONSignatureDecoder.Options());
        int beginValue = sampleSignature.indexOf("},");
        sampleSignature = sampleSignature.substring(0, ++beginValue) + "<span style=\"background:#f0f0f0\">,</span>" + sampleSignature.substring(++beginValue);
        beginValue = sampleSignature.indexOf("&quot;" + JSONSignatureDecoder.VALUE_JSON + "&quot;");
        sampleSignature = sampleSignature.substring(0, beginValue) + 
                "<span style=\"background:#f0f0f0\">" + 
                sampleSignature.substring(beginValue);
        beginValue = sampleSignature.indexOf("<br>", beginValue);
        sampleSignature = sampleSignature.substring(0, beginValue) + 
                "</span>" + 
                sampleSignature.substring(beginValue);

        StringBuffer normalizedSampleSignature = new StringBuffer(
            "{&quot;now&quot;:&quot;\u0000&quot;,&quot;escapeMe&quot;:&quot;" +
            "<b style=\"color:red;background:Yellow\">&#x20ac;</b>$<b style=\"color:red;background:Yellow\">" +
            "\\u000f\\nA</b>'B<b style=\"color:red;background:Yellow\">\\&quot;\\\\</b>\\\\\\&quot;" +
            "<b style=\"color:red;background:Yellow\">/</b>&quot;,&quot;numbers&quot;:[1e+30,4.5,6],&quot;signature&quot;<br>" + 
            ":{&quot;alg&quot;:&quot;ES256&quot;,&quot;jwk&quot;:{&quot;kty&quot;" +
            ":&quot;EC&quot;,&quot;crv&quot;:&quot;P-256&quot;,&quot;x&quot;:&quot;\u0000&quot;," +
            "&quot;y&quot;<br>:&quot;\u0000&quot;}}}");
        JSONObjectReader sampleSignatureDecoded = json.readJson2("p256keysigned.json");
        updateNormalization(normalizedSampleSignature, "now", sampleSignatureDecoded);
        updateNormalization(normalizedSampleSignature, "x", sampleSignatureDecoded = 
                       sampleSignatureDecoded.getObject(JSONSignatureDecoder.SIGNATURE_JSON)
                                                 .getObject(JSONSignatureDecoder.JWK_JSON));
        updateNormalization(normalizedSampleSignature, "y", sampleSignatureDecoded);
        
        json.addParagraphObject(SAMPLE_SIGNATURE).append(
            "The following <i>cryptographically verifiable</i> sample signature is used to visualize the JCS specification:")
        .append(sampleSignature)
        .append("The sample signature's payload consists of the properties above <code>" +
            JSONSignatureDecoder.SIGNATURE_JSON + "</code>. " +
            "Note: JCS does <i>not</i> mandate any specific ordering of properties like in the sample." + LINE_SEPARATOR +
            "For more examples see <a href=\"#" + JSONBaseHTML.makeLink(TEST_VECTORS) + 
               "\"><span style=\"white-space:nowrap\">" +
               TEST_VECTORS + "</span></a>.");

        json.addParagraphObject("Signature Scope").append(
            "The scope of a signature (what is actually signed) comprises all " +
            "properties including possible child objects of the JSON " +
            "object holding the <code>" + JSONSignatureDecoder.SIGNATURE_JSON +
            "</code> property except for the <code>" + JSONSignatureDecoder.VALUE_JSON + "</code> property (shaded area in the sample).");

        json.addParagraphObject("Normalization and Signature Validation").append(
            "Prerequisite: A JSON object in accordance with ")
          .append(json.createReference(JSONBaseHTML.REF_JSON))
          .append(" containing a properly formatted <code>" + JSONSignatureDecoder.SIGNATURE_JSON + "</code> sub object." + LINE_SEPARATOR +
            "Parsing constraints:<ul>" +
            "<li>The original property serialization order <b>must</b> be <i>preserved</i>" +
            " as described by ECMAScript " +
            json.createReference(JSONBaseHTML.REF_ES6) +
            " section <b>9.1.12</b>.</li>" +
            "<li style=\"padding-top:4pt\">JSON data of the type <code>&quot;Number&quot;</code>, <b>must</b> <i>already during " +
            "signature creation</i> have been serialized according to ECMAScript " +
            json.createReference(JSONBaseHTML.REF_ES6) +
            " section <b>7.1.12.1</b> including NOTE 2 (implemented by for example V8 " +
            json.createReference(JSONBaseHTML.REF_V8) +
            "), in order to achieve maximum interoperability.</li>" +
            "<li style=\"padding-top:4pt\">Property names <b>must not</b> be empty (<code>&quot;&quot;</code>)." +
            "<li style=\"padding-top:4pt\">Property names within an object <b>must</b> be <i>unique</i>.</li>" +
            "<li style=\"padding-top:4pt\">There <b>must not</b> be any not here defined properties inside of the <code>" + JSONSignatureDecoder.SIGNATURE_JSON + "</code> sub object." +
            "</ul>The normalization steps are as follows:<ul>" +
            "<li>The <code>" + JSONSignatureDecoder.VALUE_JSON + "</code> property " +
            "(including leading <i>or</i> trailing <code>','</code>) <b>must</b> be deleted from the " +
            "<code>" + JSONSignatureDecoder.SIGNATURE_JSON + "</code> sub object.</li>" +
            "<li style=\"padding-top:4pt\">Whitespace <b>must</b> be removed which in practical terms means removal of all characters outside of quoted strings " +
            "having a value of x09, x0a, x0d or x20.</li>" +
            "<li style=\"padding-top:4pt\">JSON <code>'\\/'</code> escape sequences within quoted strings <b>must</b> be treated as &quot;degenerate&quot; equivalents to <code>'/'</code> by rewriting them.</li>" +
            "<li style=\"padding-top:4pt\">As implied by ECMAScript " +
            json.createReference(JSONBaseHTML.REF_ES6) +
            " section <b>24.3.2.2</b>:<ul style=\"padding-top:2pt;padding-bottom:4pt\"><li>" +
            "Unicode escape sequences (<code>\\uhhhh</code>) within quoted strings <b>must</b> be adjusted as follows: " +
            "If the Unicode value falls within the traditional ASCII control character range (0x00 - 0x1f), " +
            "it <b>must</b> be rewritten in <i>lowercase</i> hexadecimal notation unless it is one of the predefined " +
            "JSON escapes (<code>\\\"&nbsp;\\\\&nbsp;\\b&nbsp;\\f&nbsp;\\n&nbsp;\\r&nbsp;\\t</code>) " +
            "because the latter have <i>precedence</i>. If the Unicode value is " +
            "outside of the ASCII control character range, it <b>must</b> be replaced by the corresponding Unicode character.</li></ul></li>" +
            "<li style=\"padding-top:4pt\">Now the JSON object associated with the <code>" +
            JSONSignatureDecoder.SIGNATURE_JSON + "</code> <b>must</b> be " +
            "<i>recreated</i> using the actual text left after applying the previous measures." + LINE_SEPARATOR +
            "Also see <a href=\"#" + INTEROPERABILITY + "\">" + INTEROPERABILITY + "</a> and " +
            "<a href=\"#" + JSONBaseHTML.makeLink(ECMASCRIPT_MODE) + 
            "\"><span style=\"white-space:nowrap\">" +
            ECMASCRIPT_MODE + "</span></a>." + LINE_SEPARATOR +
            "</li></ul>" +
            "Applied on the sample signature, a conforming JCS normalization process should return the following JSON string:" +
            "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>")
         .append(normalizedSampleSignature)
         .append("</code></div>" +
            "The text in <code><b style=\"color:red;background:Yellow\">red</b></code> highlights the string normalization process. " +
            "<i>Note that the output string was folded for improving readability</i>. " + LINE_SEPARATOR +
            "The signature <code>" + JSONSignatureDecoder.VALUE_JSON + "</code> can now be calculated by running the algorithm specified in the <code>" +
                  JSONSignatureDecoder.ALG_JSON + "</code> property using the signature key over the " +
                  "<span style=\"white-space:nowrap\">UTF-8</span> representation of the " +
                  "normalized data." + LINE_SEPARATOR +
            "Path validation (when applicable), is out of scope for JCS, but is <i>preferably</i> carried out as described in X.509 " +
            json.createReference(JSONBaseHTML.REF_X509) +
            "." + LINE_SEPARATOR +
            "The next sections cover the JCS format.");
        
        json.addDataTypesDescription("JCS consists of a top-level <code>" + JSONSignatureDecoder.SIGNATURE_JSON + "</code> property holding a composite JSON object. " + LINE_SEPARATOR);

        json.addProtocolTableEntry("JCS Objects")
          .append("The following tables describe the JCS JSON structures in detail.");
        
        json.addParagraphObject(MULTIPLE_SIGNATURES).append("Multiple signatures enable different keys to " +
        "<i>independently of each other</i> add a signature to a JSON object." + LINE_SEPARATOR +
        "The normalization procedure is essentially the same as for simple signatures but <b>must</b> also take the following in account as well:<ul>" +
        "<li>The signature property <b>must</b> be <code>&quot;" + JSONSignatureDecoder.SIGNATURES_JSON + "&quot;</code>.</li>" +
        "<li>The <code>'['</code> and <code>']'</code> characters <b>must</b> be <i>included</i> in the normalized data for each " +
        "<a href=\"#" + JSONSignatureDecoder.SIGNATURE_JSON + "\">signature object</a>.</li>" +
        "<li>Each signature requires its own normalization process. During this process the other signature objects <b>must</b> (temporarily) be removed.</li>" +
        "<li>The <code>','</code> characters separating signature objects <b>must</b> be <i>excluded</i> from the normalized data.</li>" +
        "</ul>" +
        "Also see <a href=\"#" + JSONBaseHTML.makeLink(COUNTER_SIGNATURES) + "\">" + COUNTER_SIGNATURES + "</a> and " +
        "the <a href=\"#multisignaturesample\">multiple signature sample</a>.");
        
        json.addParagraphObject(SECURITY_CONSIDERATIONS ).append("This specification does (to the author's " +
        "knowledge), not introduce additional vulnerabilities " +
        "over what is specified for JWS " + json.createReference(JSONBaseHTML.REF_JWS) + ".");
        
        json.setAppendixMode();

        json.addParagraphObject(TEST_VECTORS).append(
       "This section holds test data which can be used to verify the correctness of a JCS implementation." + LINE_SEPARATOR +
       "The <a href=\"#" + JSONBaseHTML.makeLink(SAMPLE_SIGNATURE) + "\">" + SAMPLE_SIGNATURE + "</a>" +
       " can be verified by the <i>public part</i> of the following EC key in JWK " + 
       json.createReference(JSONBaseHTML.REF_JWK) + " format:" +
       formatCode(p256key) + LINE_SEPARATOR +
       "The following signature object which uses a <code>" + JSONSignatureDecoder.KID_JSON +
       "</code> for identifying the public key can be verified with the <i>public part</i> of the key above:" + 
        readAsymSignature("p256implicitkeysigned.json", p256key, new JSONSignatureDecoder.Options()
            .setRequirePublicKeyInfo(false)
            .setKeyIdOption(JSONSignatureDecoder.KEY_ID_OPTIONS.REQUIRED)) +
        "The following signature object uses the same key as in the previous example but featured in " +
        "a certificate path:" +
        readCertSignature("p256certsigned.json") + LINE_SEPARATOR +
        "EC key for verifying the subsequent object:" +
        formatCode(p384key) +
        "The following signature object can be verified by the <i>public part</i> of the key above:" +
        readAsymSignature("p384keysigned.json", p384key, new JSONSignatureDecoder.Options()) +
        "The following signature object uses the same key as in the previous example but featured in " +
        "a certificate path:" +
        readCertSignature("p384certsigned.json") + LINE_SEPARATOR +
        "EC key for verifying the subsequent object:" +
        formatCode(p521key) +
        "The following signature object can be verified by the <i>public part</i> of the key above:" +
        readAsymSignature("p521keysigned.json", p521key, new JSONSignatureDecoder.Options()) +
        "The following signature object uses the same key as in the previous example but builds on that " +
        "the key to use is <i>implicitly known</i> since the object neither contains a <code>" +
        JSONSignatureDecoder.KID_JSON + "</code>, nor a <code>" + 
        JSONSignatureDecoder.JWK_JSON + "</code> property:" +
        readAsymSignature("p521implicitkeysigned.json", p521key, new JSONSignatureDecoder.Options()
            .setRequirePublicKeyInfo(false)) +
        "The following signature object uses the same key as in the previous example but featured in " +
        "a certificate path:" +
        readCertSignature("p521certsigned.json") + LINE_SEPARATOR +
        "RSA key for verifying the subsequent object:" +
        formatCode(r2048key) +
        "The following signature object can be verified by the <i>public part</i> of the key above:" +
        readAsymSignature("r2048keysigned.json", r2048key, new JSONSignatureDecoder.Options()) +
        "The following signature object uses the same key as in the previous example but featured in " +
        "a certificate path:" +
        readCertSignature("r2048certsigned.json") + 
        "JWK " + json.createReference(JSONBaseHTML.REF_JWK) + " key set for verifying the subsequent object:" +
        formatCode(json.readJson1("r2048.jwks")) +
        "<span id=\"remotekeyexample\">The</span> following signature object is referring to a " +
        json.globalLinkRef(JSONSignatureDecoder.JKU_JSON) +
        " which in turn should be identical to the key used in the previous RSA examples:" +
        formatCode(readSignature("r2048remotekeysigned.json")) +
        readSymSignature(new String[]{"hs256signed.json",
                                      "hs384signed.json",
                                      "hs512signed.json"}) + LINE_SEPARATOR +
        "The following is a multiple signature (see " +
        "<a href=\"#" + JSONBaseHTML.makeLink(MULTIPLE_SIGNATURES) + "\">" +
        MULTIPLE_SIGNATURES +
        "</a>) using the <code id=\"multisignaturesample\">&quot;" +  p256key.keyId + "&quot;</code>" +
        " and <code>&quot;" +  r2048key.keyId + "&quot;</code> keys:" +
        readMultiSignature("p256+r2048keysigned.json", p256key, r2048key) +
        LINE_SEPARATOR +
        "The certificate based signatures share a common root (here supplied in PEM ")
        .append(json.createReference(JSONBaseHTML.REF_PEM))
        .append(" format), which can be used for path validation:" +
        formatCode(new String(json.readFile1("rootca.pem"), "UTF-8")
                          .replace("END CERTIFICATE-----\n", 
                                   "END CERTIFICATE-----")).replace(" 10pt ", " 0pt "));

        String jsSignature = formatCode("var signedObject = " +
                                        new String(json.readFile2("p256keysigned.js"), "utf-8") + ";");
        beginValue = jsSignature.indexOf("{");
        jsSignature = jsSignature.substring(0, ++beginValue) +
                      "<br>&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Data&nbsp;to&nbsp;be&nbsp;signed</span>" +
                      jsSignature.substring(beginValue);
        beginValue = jsSignature.indexOf("<br>&nbsp;&nbsp;signature:");
        jsSignature = jsSignature.substring(0, beginValue) +
                      "<br>&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Signature</span>" +
                      jsSignature.substring(beginValue);

        json.addParagraphObject(ECMASCRIPT_MODE).append("ECMAScript mode in this context refers to " +
           "the ability to sign JavaScript objects as well as using the standard JSON support for parsing and " +
           "creating signed data." + LINE_SEPARATOR + 
           "The code snippet below shows a signed JavaScript object:")
        .append(jsSignature)
        .append(
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
            "&nbsp;&nbsp;delete&nbsp;jcs.signature." + JSONSignatureDecoder.VALUE_JSON +
            ";&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Remove&nbsp;signature&nbsp;value&nbsp;property&nbsp;from&nbsp;signed&nbsp;object</span><br>" +
            "&nbsp;&nbsp;var&nbsp;data&nbsp;=&nbsp;convertToUTF8(JSON.stringify(jcs));&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Get&nbsp;normalized&nbsp;JSON&nbsp;string (signed data)</span><br>" +
            "&nbsp;&nbsp;jcs.signature&nbsp;=&nbsp;clone;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Restore&nbsp;signed&nbsp;object</span><br>" +
            "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Perform&nbsp;the&nbsp;actual&nbsp;crypto,&nbsp;here&nbsp;using&nbsp;W3C&nbsp;WebCrypto</span> </code>")
            .append(json.createReference(JSONBaseHTML.REF_WEB_CRYPTO))
            .append("<code><br>" +
            "&nbsp;&nbsp;crypto.subtle.importKey('jwk',&nbsp;clone." + JSONSignatureDecoder.JWK_JSON +
            ",&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;JCS&nbsp;public&nbsp;key&nbsp;is&nbsp;a&nbsp;JWK</span><br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;{&nbsp;name:&nbsp;'ECDSA',&nbsp;namedCurve:&nbsp;clone." +
            JSONSignatureDecoder.JWK_JSON +
            ".crv&nbsp;},<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;true,&nbsp;['verify']).then(function(publicKey)&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;crypto.subtle.verify({&nbsp;name:&nbsp;'ECDSA',&nbsp;hash:&nbsp;{&nbsp;name:&nbsp;'SHA-256'&nbsp;}&nbsp;},&nbsp;<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;publicKey,&nbsp;signature,&nbsp;data).then(function(result)&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;console.log('Success='&nbsp;+&nbsp;result);<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;});<br>" +
            "&nbsp;&nbsp;});<br>" +
            "}<br>" +
            "<br>" +
            "verifySignature(signedObject);<br></code></div>" + LINE_SEPARATOR +
            "<b>Constraint when using JCS with ECMAScript</b>" + LINE_SEPARATOR +
            "If numeric property names are used, they <b>must</b> be " +
            "<i>provided in ascending numeric order</i> and inserted <i>before</i> possible non-numeric properties.");

        json.addParagraphObject(COUNTER_SIGNATURES).append(
            "For counter signatures there are two entirely different solutions. " +
            "One way dealing with counter signatures is using an " +
            "application level counter signing solution like the following:" +
            "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>{<br>" +
            "&nbsp;&nbsp;&quot;id&quot;: &quot;lADU_sO067Wlgoo52-9L&quot;,<br>" +
            "&nbsp;&nbsp;&quot;object&quot;: {&quot;type&quot;: &quot;house&quot;, &quot;price&quot;: &quot;$635,000&quot;},<br>" +
            "&nbsp;&nbsp;&quot;role&quot;: &quot;buyer&quot;,<br>" +
            "&nbsp;&nbsp;&quot;timeStamp&quot;: &quot;2016-12-08T13:56:08Z&quot;,<br>" +
            "&nbsp;&nbsp;&quot;" + JSONSignatureDecoder.SIGNATURE_JSON + "&quot;:&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;<span style=\"font-size:15pt\">&nbsp;</span></code><i>Original signature...</i><code><br>" +
            "&nbsp;&nbsp;}<br>" +
            "}</code></div>" +
            "Counter signed JSON object:" +
            "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>{<br>" +
            "&nbsp;&nbsp;&quot;attesting&quot;:&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&quot;id&quot;: &quot;lADU_sO067Wlgoo52-9L&quot;,<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&quot;object&quot;: {&quot;type&quot;: &quot;house&quot;, &quot;price&quot;: &quot;$635,000&quot;},<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&quot;role&quot;: &quot;buyer&quot;,<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&quot;timeStamp&quot;: &quot;2016-12-08T13:56:08Z&quot;,<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&quot;" + JSONSignatureDecoder.SIGNATURE_JSON + "&quot;:&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"font-size:15pt\">&nbsp;</span></code><i>Original signature...</i><code><br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;}<br>" +
            "&nbsp;&nbsp;},<br>" +
            "&nbsp;&nbsp;&quot;role&quot;: &quot;notary&quot;,<br>" +
            "&nbsp;&nbsp;&quot;timeStamp&quot;: &quot;2016-12-08T13:58:42Z&quot;,<br>" +
            "&nbsp;&nbsp;&quot;" + JSONSignatureDecoder.SIGNATURE_JSON + "&quot;:&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;<span style=\"font-size:15pt\">&nbsp;</span></code><i>Counter signature...</i><code><br>" +
            "&nbsp;&nbsp;}<br>" +
            "}</code></div>" +
            "For sophisticated <i>peer based</i> counter signature schemes another possibility is using " +
            "<a href=\"#" + JSONBaseHTML.makeLink(MULTIPLE_SIGNATURES) + "\">" + MULTIPLE_SIGNATURES +
            "</a>, <i>optionally</i> including JCS " + json.globalLinkRef(JSONSignatureDecoder.EXTENSIONS_JSON) +
            " holding application specific (per signature) metadata.");

        json.addParagraphObject("Usage in Applications").append("JCS as well as the freestanding sub objects <a href=\"#" + 
            JSONSignatureDecoder.SIGNATURE_JSON + "." + JSONSignatureDecoder.JWK_JSON + "\">" +
            JSONSignatureDecoder.JWK_JSON + "</a> and <a href=\"#" +
            JSONSignatureDecoder.SIGNATURE_JSON + "." + JSONSignatureDecoder.X5C_JSON + "\">" +
            JSONSignatureDecoder.X5C_JSON +
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
         "&nbsp;&nbsp;JSONSignatureDecoder&nbsp;signature&nbsp;=&nbsp;reader.getSignature(new JSONSignatureDecoder.Options());<br>" +
         "&nbsp;&nbsp;signature.verify(new&nbsp;JSONAsymKeyVerifier(publicKey));<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Print&nbsp;document&nbsp;payload&nbsp;on&nbsp;the&nbsp;console</span><br>" +
         "&nbsp;&nbsp;System.out.println(&quot;Returned&nbsp;data:&nbsp;&quot;&nbsp;+&nbsp;reader.getString(&quot;myProperty&quot;));<br>" +
         "}</code></div>");
        
        json.addParagraphObject(INTEROPERABILITY).append("Since serialization of floating point numbers as specified by JCS is " +
         "(at the time of writing) not available for all platforms, you <i>may</i> for highest possible " + 
         "interoperability need to put such data in quotes.  Albeit a limitation, financial data is not natively supported by JSON either " +
         "due to the fact that JavaScript lacks support for big decimals." + LINE_SEPARATOR +
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
        "An early prototype was funded by <i>PrimeKey Solutions AB</i> and the <i>Swedish Innovation Board (VINNOVA)</i>.");
        
        json.addReferenceTable();
        
        json.addDocumentHistoryLine("2013-12-17", "0.3", "Initial publication in HTML5");
        json.addDocumentHistoryLine("2013-12-20", "0.4", "Changed from Base64 to Base64URL everywhere");
        json.addDocumentHistoryLine("2013-12-29", "0.5", "Added the <code>" + JSONSignatureDecoder.EXTENSIONS_JSON + "</code> facility");
        json.addDocumentHistoryLine("2014-01-21", "0.51", "Added clarification to public key parameter representation");
        json.addDocumentHistoryLine("2014-01-26", "0.52", "Added note regarding the (now obsoleted) <code>signerCertificate</code> option");
        json.addDocumentHistoryLine("2014-04-15", "0.53", "Embedded <code>bigint</code> in JS <i>string</i> making syntax fully JSON compatible");
        json.addDocumentHistoryLine("2014-09-17", "0.54", "Changed canonicalization to normalization");
        json.addDocumentHistoryLine("2014-09-23", "0.55", "Aligned EC parameter representation with JWS " + json.createReference(JSONBaseHTML.REF_JWS));
        json.addDocumentHistoryLine("2014-12-08", "0.56", "Removed " + json.createReference(JSONBaseHTML.REF_XMLDSIG) + " bloat and added support for JWA " + json.createReference(JSONBaseHTML.REF_JWS) + " algorithm identifiers");
        json.addDocumentHistoryLine("2014-12-19", "0.57", "Added an interoperability section");
        json.addDocumentHistoryLine("2015-01-12", "0.58", "Added clarification to signature <code>" + JSONSignatureDecoder.VALUE_JSON + "</code> representation");
        json.addDocumentHistoryLine("2016-01-11", "0.59", "Added ECMAScript compatibility mode");
        json.addDocumentHistoryLine("2017-04-19", "0.60", "Changed public keys to use JWK " + json.createReference(JSONBaseHTML.REF_JWK) + " format");
        json.addDocumentHistoryLine("2017-05-18", "0.70", "Added multiple signatures and test vectors");
        json.addDocumentHistoryLine("2017-11-18", "0.71", "Added detailed references to ECMAScript " + json.createReference(JSONBaseHTML.REF_ES6));
        json.addDocumentHistoryLine("2017-12-19", "0.80", "Rewritten to reuse JWS " + json.createReference(JSONBaseHTML.REF_JWS) + " property names");

        json.addParagraphObject("Author").append("JCS was developed by Anders Rundgren (<code>anders.rundgren.net@gmail.com</code>) as a part " +
                                                 "of the OpenKeyStore project " +
                                                 json.createReference(JSONBaseHTML.REF_OPENKEYSTORE)  + ".");

        json.addProtocolTable("Top Level Property")
          .newRow()
            .newColumn()
              .addProperty (JSONSignatureDecoder.SIGNATURE_JSON)
              .addLink(JSONSignatureDecoder.SIGNATURE_JSON)
            .newColumn()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn()
              .setChoice (true, 2)
            .newColumn()
              .addString("Mandatory top level property for <i>simple</i> signatures.")
            .newRow()
           .newColumn()
             .addProperty(JSONSignatureDecoder.SIGNATURES_JSON)
             .addArrayLink(JSONSignatureDecoder.SIGNATURE_JSON, 1)
           .newColumn()
             .setType(WEBPKI_DATA_TYPES.OBJECT)
           .newColumn()
           .newColumn()
             .addString("Mandatory top level property for ")
             .addLink(MULTIPLE_SIGNATURES)
             .addString(".");
           
        json.addJSONSignatureDefinitions();

        json.writeHTML();
    }

}
