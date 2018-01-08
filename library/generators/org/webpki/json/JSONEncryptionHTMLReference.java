/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
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
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.Vector;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.json.JSONBaseHTML.Extender;
import org.webpki.json.JSONBaseHTML.RowInterface;
import org.webpki.json.JSONBaseHTML.Types;
import org.webpki.json.JSONBaseHTML.ProtocolObject.Row.Column;
import org.webpki.util.ArrayUtil;

/**
 * Create an HTML description of JEF (JSON Encryption Format).
 * 
 * @author Anders Rundgren
 */
public class JSONEncryptionHTMLReference extends JSONBaseHTML.Types {
    
    static JSONBaseHTML json;
    static RowInterface row;
    static String ECDH_PROPERTIES       = "Additional ECDH Properties";
    static String ECDH_KW_PROPERTIES    = "Additional ECDH+KW Properties";
    static String RSA_PROPERTIES        = "Additional RSA Encryption Properties";

    static final String ENCRYPTED_DATA  = "encryptedData";
    
    static final String TEST_VECTORS    = "Test Vectors";
    
    static final String SAMPLE_OBJECT   = "Sample Object";

    static final String SECURITY_CONSIDERATIONS = "Security Considerations";

    static String enumerateJoseEcCurves() throws IOException  {
        StringBuffer buffer = new StringBuffer("<ul>");
        for (KeyAlgorithms algorithm : KeyAlgorithms.values()) {
            if (algorithm.isECKey()) {
                String joseName = algorithm.getAlgorithmId(AlgorithmPreferences.JOSE_ACCEPT_PREFER);
                if (!joseName.contains (":")) {
                    buffer.append("<li><code>")
                          .append(joseName)
                          .append("</code></li>");
                }
            }
        }
        return buffer.append("</ul>").toString ();
    }

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

    static Column preAmble(String qualifier, boolean subItem) throws IOException {
        return (subItem ? json.addSubItemTable(qualifier) : json.addProtocolTable(qualifier))
            .newRow()
                .newColumn()
                    .addProperty(JSONCryptoDecoder.ALG_JSON)
                    .addSymbolicValue(JSONCryptoDecoder.ALG_JSON)
                .newColumn()
                    .setType(Types.WEBPKI_DATA_TYPES.STRING)
                .newColumn()
                .newColumn();
    }
    
    static byte[] dataToEncrypt;
    
    static Vector<AsymKey> asymmertricKeys = new Vector<AsymKey>();

    static class AsymKey {
        String keyId;
        KeyPair keyPair;
        X509Certificate[] certPath;
        String json;
    }
    
    static AsymKey readAsymKey(String keyType) throws IOException {
        AsymKey asymKey = new AsymKey();
        JSONObjectReader key = json.readJson1(keyType + "privatekey.jwk");
        asymKey.json = key.toString();
        asymKey.keyId = key.getString("kid");
        key.removeProperty("kid");
        asymKey.keyPair = key.getKeyPair();
        asymKey.certPath = json.readJson1(keyType + "certificate.x5c").getJSONArrayReader().getCertificatePath();
        return asymKey;
    }
    
    static void scanObject(JSONObjectReader recipient, JSONCryptoDecoder.Options options) throws IOException {
        if (recipient.hasProperty(JSONCryptoDecoder.KID_JSON) && 
            options.keyIdOption == JSONCryptoDecoder.KEY_ID_OPTIONS.FORBIDDEN) {
            options.setKeyIdOption(JSONCryptoDecoder.KEY_ID_OPTIONS.OPTIONAL);
        }
        if (recipient.hasProperty(JSONCryptoDecoder.JKU_JSON)) {
            options.setRemoteKeyReader(new WebKey(), JSONRemoteKeys.JWK_KEY_SET);
        } else if (recipient.hasProperty(JSONCryptoDecoder.X5U_JSON)) {
            options.setRemoteKeyReader(new WebKey(), JSONRemoteKeys.PEM_CERT_PATH);
        } else if (!recipient.hasProperty(JSONCryptoDecoder.X5C_JSON) &&
                   !recipient.hasProperty(JSONCryptoDecoder.JWK_JSON)) {
            options.setRequirePublicKeyInfo(false);
        }
        if (recipient.hasProperty(JSONCryptoDecoder.CRIT_JSON)) {
            options.setPermittedExtensions(new JSONCryptoDecoder.ExtensionHolder()
                .addExtension(Extension1.class, true)
                .addExtension(Extension2.class, true));
        }
    }

    static String validateAsymEncryption (String fileName) throws IOException {
        JSONCryptoDecoder.Options options = new JSONCryptoDecoder.Options();
        JSONObjectReader encryptedObject = json.readJson2(fileName);
        try {
            JSONObjectReader checker = encryptedObject.clone();
            Vector<JSONDecryptionDecoder> recipients = new Vector<JSONDecryptionDecoder>();
            if (checker.hasProperty(JSONCryptoDecoder.KID_JSON)) {
                options.setKeyIdOption(JSONCryptoDecoder.KEY_ID_OPTIONS.REQUIRED);
            }
            if (checker.hasProperty(JSONCryptoDecoder.RECIPIENTS_JSON)) {
                JSONArrayReader recipientArray = checker.getArray(JSONCryptoDecoder.RECIPIENTS_JSON);
                do {
                    scanObject(recipientArray.getObject(), options);
                } while (recipientArray.hasMore());
                recipients = encryptedObject.getEncryptionObjects(options);
            } else {
                scanObject(checker, options);
                recipients.add(encryptedObject.getEncryptionObject(options));
            }
            for (JSONDecryptionDecoder decoder : recipients) {
                String keyId = decoder.getKeyId();
                AsymKey validationKey = null;
                if (keyId != null) {
                    for (AsymKey localKey : asymmertricKeys) {
                        if (keyId.equals(localKey.keyId)) {
                            validationKey = localKey;
                            break;
                        }
                    }
                }
                PublicKey publicKey = decoder.getPublicKey();
                if (publicKey != null) {
                    for (AsymKey localKey : asymmertricKeys) {
                        if (publicKey.equals(localKey.keyPair.getPublic())) {
                            validationKey = localKey;
                            break;
                        }
                    }
                }
                X509Certificate[] certPath = decoder.getCertificatePath();
                if (certPath != null) {
                    for (AsymKey localKey : asymmertricKeys) {
                        if (certPath[0].equals(localKey.certPath[0])) {
                            validationKey = localKey;
                            break;
                        }
                    }
                }
                if (validationKey == null) {
                    for (AsymKey localKey : asymmertricKeys) {
                        if (decoder.getKeyEncryptionAlgorithm().isRsa() ==
                            (localKey.keyPair.getPublic() instanceof RSAPublicKey)) {
                            validationKey = localKey;
                            break;
                        }
                    }
                }
                System.out.println(fileName + " found=" + (validationKey != null));
                if (!ArrayUtil.compare(decoder.getDecryptedData(validationKey.keyPair.getPrivate()), dataToEncrypt)) {
                    throw new IOException(fileName);
                }
            }
        } catch (Exception e) {
            throw new IOException("Failed on file " + fileName + ", " + e.getMessage());
        }
        return formatCode(encryptedObject.toString());
    }
 
    static X509Certificate[] readCertPath(String name) throws IOException {
        return json.readJson1(name + "certificate.x5c").getJSONArrayReader().getCertificatePath();
    }

    static String aesCrypto(String[] encObjects) throws IOException, GeneralSecurityException {
        StringBuffer s = new StringBuffer();
        JSONObjectReader symmetricKeys = json.readJson1("symmetrickeys.json");
        for (String name : encObjects) {
            JSONObjectReader rd = json.readJson2(name);
            JSONCryptoDecoder.Options options = new JSONCryptoDecoder.Options();
            if (rd.hasProperty(JSONCryptoDecoder.KID_JSON)) {
                options.setKeyIdOption(JSONCryptoDecoder.KEY_ID_OPTIONS.REQUIRED);
            }
            JSONDecryptionDecoder dec = rd.getEncryptionObject(options);
            for (String keyProp : symmetricKeys.getProperties()) {
                byte[] key = symmetricKeys.getBinary(keyProp);
                if (key.length == dec.getDataEncryptionAlgorithm().getKeyLength()) {
                    s.append(LINE_SEPARATOR + "AES key");
                    if (dec.getKeyId() != null) {
                        s.append(" named <code>&quot;")
                         .append(keyProp)
                         .append("&quot;</code>");
                    }
                    s.append(" here provided in Base64URL notation:")
                     .append(formatCode(symmetricKeys.getString(keyProp)))
                     .append("Encryption object requiring the ");
                    if (dec.getKeyId() == null) {
                        s.append("<i>implicit</i> ");
                    }
                    s.append("key above for decryption:")
                     .append(formatCode(rd));
                    if (!ArrayUtil.compare(dec.getDecryptedData(key), dataToEncrypt)) {
                        throw new IOException("Sym enc");
                    }
                    break;
                }
            }
        }
        return s.toString();
    }

    public static void main (String args[]) throws Exception {
        CustomCryptoProvider.forcedLoad(true);

        json = new JSONBaseHTML(args, "JEF - JSON Encryption Format");
        
        json.setFavIcon("../webpkiorg.png");
        
        dataToEncrypt = json.readFile2("datatobeencrypted.txt");
     
        AsymKey p256key = readAsymKey("p256");
        AsymKey p384key = readAsymKey("p384");
        AsymKey p521key = readAsymKey("p521");
        AsymKey r2048key = readAsymKey("r2048");
        asymmertricKeys.add(p256key);
        asymmertricKeys.add(p384key);
        asymmertricKeys.add(p521key);
        asymmertricKeys.add(r2048key);

        validateAsymEncryption("p256#ecdh-es+a128kw@kid.json");
        validateAsymEncryption("p256#ecdh-es+a256kw@x5c.json");
        validateAsymEncryption("p256#ecdh-es+a256kw@crit@jwk.json");
        validateAsymEncryption("p256#ecdh-es+a256kw@jwk.json");
        validateAsymEncryption("p256#ecdh-es+a256kw@kid.json");
        validateAsymEncryption("p256#ecdh-es+a256kw@x5u.json");
        validateAsymEncryption("p256#ecdh-es+a256kw,p256#ecdh-es+a256kw@mult-glob+alg+kid.json");
        validateAsymEncryption("p256#ecdh-es+a256kw,p384#ecdh-es+a256kw@mult-glob+alg-jwk.json");
        validateAsymEncryption("p256#ecdh-es+a256kw,p384#ecdh-es+a256kw@mult-glob+alg-kid.json");
        validateAsymEncryption("p256#ecdh-es+a256kw,r2048#rsa-oaep-256@mult-kid.json");
        validateAsymEncryption("p384#ecdh-es@jwk.json");
        validateAsymEncryption("p521#ecdh-es+a128kw@jwk.json");
        validateAsymEncryption("r2048#rsa-oaep-256@x5c.json");
        validateAsymEncryption("r2048#rsa-oaep-256@jwk.json");
        validateAsymEncryption("r2048#rsa-oaep-256@kid.json");
        validateAsymEncryption("r2048#rsa-oaep-256@x5u.json");
        validateAsymEncryption("r2048#rsa-oaep@kid.json");
        validateAsymEncryption("r2048#rsa-oaep-256@imp.json");
        validateAsymEncryption("p256#ecdh-es+a128kw@imp.json");

        JSONObjectReader ecdhEncryption = json.readJson2("p256#ecdh-es+a256kw@kid.json");
        JSONObjectReader authData = ecdhEncryption.clone();
        authData.removeProperty(JSONCryptoDecoder.TAG_JSON);
        authData.removeProperty(JSONCryptoDecoder.CIPHER_TEXT_JSON);
        String formattedAuthData = authData.serializeToString(JSONOutputFormats.NORMALIZED);
        for (int l = formattedAuthData.length(), j = 0, i = 0; i < l; i++) {
            if (i % 120 == 0 && i > 0) {
                formattedAuthData = formattedAuthData.substring(0, i + j) + 
                        "<br>" + formattedAuthData.substring(i + j);
                j += 4;
            }
        }
        formattedAuthData = formattedAuthData.replace("\"", "&quot;");
        
        json.addParagraphObject().append("<div style=\"margin-top:200pt;margin-bottom:200pt;text-align:center\"><span style=\"" + JSONBaseHTML.HEADER_STYLE + "\">JEF</span>" +
            "<br><span style=\"font-size:" + JSONBaseHTML.CHAPTER_FONT_SIZE + "\">&nbsp;<br>JSON Encryption Format</span></div>");
        
        json.addTOC();

        json.addParagraphObject("Introduction")
          .append("This document specifies a container formatted in JSON ")
          .append(json.createReference(JSONBaseHTML.REF_JSON))
          .append(" for holding encrypted binary data, coined JEF (JSON Encryption Format)." + LINE_SEPARATOR +
            "JEF was derived from IETF's JWE ")
          .append(json.createReference(JSONBaseHTML.REF_JWE))
          .append(
            " specification and supports a <i>subset</i> of the same algorithms ")
          .append(json.createReference(JSONBaseHTML.REF_JWA))
          .append(". Public keys are represented as JWK ")
          .append(json.createReference(JSONBaseHTML.REF_JWK))
          .append(" objects while the encryption container itself utilizes a notation similar to JCS ")
          .append(json.createReference(JSONBaseHTML.REF_JCS))
          .append(" in order to maintain a consistent &quot;style&quot; in applications using encryption and signatures, " +
                  "<i>including providing header information in plain text</i>."
                  + LINE_SEPARATOR +
                  "The JEF encryption scheme is fully compatible with the ES6 ")
          .append(json.createReference(JSONBaseHTML.REF_ES6))
          .append(" JSON/JavaScript serialization and parsing specification.");

        json.addParagraphObject(SAMPLE_OBJECT).append(
              "The following sample object is used to visualize the JEF specification:" +
               formatCode(ecdhEncryption) +
               "The sample object can be decrypted by using the EC private key " +
               "defined in <a href=\"#" + JSONBaseHTML.makeLink(TEST_VECTORS) + 
               "\"><span style=\"white-space:nowrap\">" +
               TEST_VECTORS + "</span></a>.");

        
        json.addDataTypesDescription("JEF containers always start with a top-level JSON object. " + LINE_SEPARATOR);

        json.addProtocolTableEntry("JEF Objects")
          .append("The following tables describe the JEF JSON structures in detail.");
        
        json.addParagraphObject("Operation").append(
                "Prerequisite: A JSON object in accordance with ")
              .append(json.createReference(JSONBaseHTML.REF_JSON))
              .append(" containing properly formatted JEF data." + LINE_SEPARATOR +
                "Parsing restrictions:<ul>" +
                "<li>The original property serialization order <b>must</b> be <i>preserved</i>.</li>" +
                "<li style=\"padding-top:4pt\">There <b>must not</b> be any not here defined properties inside of a JEF object.</li>" +
                "</ul>Since JEF uses the same algorithms as JWE " +
                json.createReference(JSONBaseHTML.REF_JWE) +
                " the JWA " + json.createReference(JSONBaseHTML.REF_JWA) +
                " reference apply with one important exception: <i>Additional Authenticated Data</i> " +
                "used by the symmetric ciphers. " +
                "This difference is due to the way encryption meta-data is formatted. " +
                "The process for creating <i>Additional Authenticated Data</i> is as follows:<ul>" +
                "<li>The <i>top level</i> properties " +
                "<code>" + JSONCryptoDecoder.TAG_JSON + "</code> and <code>" + 
                JSONCryptoDecoder.CIPHER_TEXT_JSON +
                "</code> (including leading <i>or</i> trailing <code>','</code> characters) " +
                "<b>must</b> " + "be deleted from the JEF object.</li>" +
                "<li style=\"padding-top:4pt\">Whitespace <b>must</b> be removed which in practical terms means removal of all characters outside of quoted strings " +
                "having a value of x09, x0a, x0d or x20.</li>" +
                "<li style=\"padding-top:4pt\">Now the JEF object <b>must</b> be " +
                "<i>recreated</i> using the actual text left after applying the previous measures.</li>" +
                "</ul>" +
                "Applied on the <a href=\"#" + JSONBaseHTML.makeLink(SAMPLE_OBJECT) + "\">" + SAMPLE_OBJECT +
                "</a>, a conforming JEF <i>Additional Authenticated Data</i> process should return the following JSON string:" +
                "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>" + formattedAuthData + "</code></div>" +
                "<i>Note that the output string was folded for improving readability</i>. " + LINE_SEPARATOR +
                "The <i>Additional Authenticated Data</i> string is subsequently <span style=\"white-space:nowrap\">UTF-8</span> encoded " +
                "before being applied to the encryption algorithm.");

        json.addParagraphObject(SECURITY_CONSIDERATIONS ).append("This specification does (to the author's " +
        "knowledge), not introduce additional vulnerabilities " +
        "over what is specified for JWE " + json.createReference(JSONBaseHTML.REF_JWE) + ".");

        json.setAppendixMode();

        json.addParagraphObject(TEST_VECTORS).append("This section holds test data which can be used to verify the correctness " +
            "of a JEF implementation." + LINE_SEPARATOR + 
           "All encryption tests encrypt the string below (after first having converted it to UTF-8):" +
           "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>&quot;" + new String(dataToEncrypt, "UTF-8") +
           "&quot;</code></div>" + LINE_SEPARATOR +
           "The <a href=\"#" + JSONBaseHTML.makeLink(SAMPLE_OBJECT) + "\">" + SAMPLE_OBJECT + "</a>" +
            " can be decrypted by the <i>private</i> part of the following EC key in JWK " + 
           json.createReference(JSONBaseHTML.REF_JWK) + " format:" +
           formatCode(p256key) +
           validateAsymEncryption(
                   "ECDH encryption object <i>requiring the same private key</i> " +
                           "as in the sample object while using a different set of " +
                           "algorithms both for key encryption and content encryption:" ,
                   "p256#ecdh-es+a128kw@kid.json") +
           validateAsymEncryption(
                   "ECDH encryption object <i>requiring the same private key</i> " +
                           "as in the sample object while providing the public key information in line, " +
                           "instead of using a <code>" + JSONCryptoDecoder.KID_JSON + "</code>:",
                   "p256#ecdh-es+a256kw@jwk.json") + 
           validateAsymEncryption(
                   "ECDH encryption object <i>requiring the same private key</i> " +
                           "as in the sample object but assuming it is known through the <i>context</i>:",
                   "p256#ecdh-es+a128kw@imp.json") + 
           validateAsymEncryption("ECDH encryption object <i>requiring the same private key</i> " +
                   "as in the sample object while providing the key information " +
                   "through an in-line certificate path:",
                   "p256#ecdh-es+a256kw@x5c.json") + 
           validateAsymEncryption(
                   "ECDH encryption object <i>requiring the same private key</i> " +
                           "as in the sample object while providing the key information " +
                           "through an <i>external</i> certificate path:",
                   "p256#ecdh-es+a256kw@x5u.json") + 
           validateAsymEncryption("ECDH encryption object <i>requiring the same private key</i> " +
                   "as in the sample object while providing the key information " +
                   "through an <i>external</i> public key:",
                   "p256#ecdh-es+a256kw@jku.json") + 
           validateAsymEncryption(
                   "ECDH encryption object <i>requiring the same private key</i> " +
                           "as in the sample object while providing the key information " +
                           "in line.  In addition, this object declares <code>" +
                           JSONCryptoDecoder.CRIT_JSON + "</code> extensions:",
                    "p256#ecdh-es+a256kw@crit@jwk.json") + 
           LINE_SEPARATOR +
           "EC private key for decrypting the subsequent object:" +
           formatCode(p384key) +
           validateAsymEncryption(
                   "ECDH encryption object <i>requiring the private key above</i>:",
                   "p384#ecdh-es@jwk.json") + 
           LINE_SEPARATOR +
           "EC private key for decrypting the subsequent object:" +
           formatCode(p521key) +
           validateAsymEncryption(
                   "ECDH encryption object <i>requiring the private key above</i>:",
                   "p521#ecdh-es+a128kw@jwk.json") + 
           LINE_SEPARATOR +
           "RSA private key for decrypting the subsequent object:" +
           formatCode(r2048key) +
           validateAsymEncryption(
                   "RSA encryption object <i>requiring the private key above</i>:",
                   "r2048#rsa-oaep-256@jwk.json") +
            validateAsymEncryption(
                   "RSA encryption object <i>requiring the same private key</i> " +
                           "as in the previous example but relying on that this being " +
                           "<i>implicitly known</i> since the encryption object " +
                           "neither contains a <code>" +
                           JSONCryptoDecoder.KID_JSON + "</code>, nor a <code>" +
                           JSONCryptoDecoder.JWK_JSON + "</code> property:",
                    "r2048#rsa-oaep-256@imp.json") +
           validateAsymEncryption(
                   "RSA encryption object <i>requiring the same private key</i> " +
                           "as in the previous example while using a different set of " +
                           "algorithms both for key encryption and content encryption:",
                    "r2048#rsa-oaep@kid.json") + 
           LINE_SEPARATOR +
           validateAsymEncryption(
                   "Multiple recipient encryption object <i>requiring the same private keys</i> " +
                   "as in the previous examples:",
                   "p256#ecdh-es+a256kw,r2048#rsa-oaep-256@mult-kid.json") +
           LINE_SEPARATOR +
           validateAsymEncryption(
                   "Multiple recipient encryption object <i>requiring the same private keys</i> " +
                           "as in the previous examples as well as using a <i>global</i> <code>" +
                           JSONCryptoDecoder.ALG_JSON + "</code> property:",
                   "p256#ecdh-es+a256kw,p384#ecdh-es+a256kw@mult-glob+alg-jwk.json") +
           LINE_SEPARATOR +
           validateAsymEncryption(
                   "Multiple recipient encryption object <i>requiring the same private keys</i> " +
                           "as in the previous examples as well as using <i>global</i> <code>" +
                           JSONCryptoDecoder.ALG_JSON + "</code> and <code>" +
                           JSONCryptoDecoder.KID_JSON + "</code> properties:",
                   "p256#ecdh-es+a256kw,p256#ecdh-es+a256kw@mult-glob+alg+kid.json") +
           aesCrypto(new String[]{"a128gcm@kid.json",
                                  "a128cbc-hs256@kid.json",
                                  "a256gcm@imp.json",
                                  "a256gcm@kid.json",
                                  "a256cbc-hs512@kid.json"}));

        json.addReferenceTable();
        
        json.addDocumentHistoryLine("2016-08-03", "0.3", "Initial publication in HTML5");
        json.addDocumentHistoryLine("2017-04-19", "0.4", "Changed public keys to use JWK " + json.createReference(JSONBaseHTML.REF_JWK) + " format");
        json.addDocumentHistoryLine("2017-04-25", "0.5", "Added KW and GCM algorithms");
        json.addDocumentHistoryLine("2017-05-15", "0.51", "Added test vectors and missing RSA-OAEP algorithm");

        json.addParagraphObject("Author").append("JEF was developed by Anders Rundgren (<code>anders.rundgren.net@gmail.com</code>) as a part " +
                                                 "of the OpenKeyStore " +
                                                 json.createReference(JSONBaseHTML.REF_OPENKEYSTORE) + " project .");

    preAmble(ENCRYPTED_DATA, false)
        .addString("Data encryption algorithm. Currently the following JWE " +
            json.createReference(JSONBaseHTML.REF_JWE) +
            " algorithms are recognized:<ul>")
        .newExtensionRow(new Extender() {
            @Override
            public Column execute(Column column) throws IOException {
                for (DataEncryptionAlgorithms dea : DataEncryptionAlgorithms.values()) {
                    column.addString("<li><code>")
                          .addString(dea.toString())
                          .addString("</code></li>");
                }
                return column;
            }
        })
        .addString("</ul>")
            .newRow()
        .newColumn()
            .addProperty(JSONCryptoDecoder.KID_JSON)
            .addSymbolicValue(JSONCryptoDecoder.KID_JSON)
        .newColumn()
            .setType(Types.WEBPKI_DATA_TYPES.STRING)
        .newColumn()
             .setChoice (false, 2)
        .newColumn()
            .addString("If the <code>" + JSONCryptoDecoder.KID_JSON +
                   "</code> property is defined, data is supposed to be encrypted by a specific named (symmetric) key.")
            .newRow()

        .newColumn()
        .addProperty("@@@")
        .addLink("@@@")
    .newColumn()
        .setType(Types.WEBPKI_DATA_TYPES.OBJECT)
    .newColumn()
    .newColumn()
        .addString("If the <code>" + "@@@" +
                   "</code> property is defined, the (symmetric) data encryption key is supposed to be provided " +
                   "in-line, but encrypted.")
        .newRow()
        .newColumn()
          .addProperty(JSONCryptoDecoder.IV_JSON)
          .addSymbolicValue(JSONCryptoDecoder.IV_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("Initialization vector.")
        .newRow()
        .newColumn()
          .addProperty(JSONCryptoDecoder.TAG_JSON)
          .addSymbolicValue(JSONCryptoDecoder.TAG_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("Authentication tag.")
        .newRow()
        .newColumn()
          .addProperty(JSONCryptoDecoder.CIPHER_TEXT_JSON)
          .addSymbolicValue(JSONCryptoDecoder.CIPHER_TEXT_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("Encrypted data.").setNotes("Note that if neither <code>" + JSONCryptoDecoder.KID_JSON +
                      "</code> nor <code>" + "@@@" + 
                      "</code> are defined, the (symmetric) data encryption key is assumed to known by the recipient.");
          
        preAmble("@@@", true)
            .addString("Key encryption algorithm. Currently the following JWE " +
                                json.createReference (JSONBaseHTML.REF_JWE) +
                                " algorithms are recognized:<ul>")
            .newExtensionRow(new Extender() {
                @Override
                public Column execute(Column column) throws IOException {
                    for (KeyEncryptionAlgorithms kea : KeyEncryptionAlgorithms.values()) {
                        column.addString(new StringBuffer("<li>")
                                               .append(JSONBaseHTML.codeVer(kea.toString(), 16))
                                               .append("See: ").toString());
                        String link = ECDH_PROPERTIES;
                        if (kea.isRsa()) {
                            link = RSA_PROPERTIES;
                        } else if (kea.isKeyWrap()) {
                            link = ECDH_KW_PROPERTIES;
                        }
                        column.addLink(link).addString("</li>");
                    }
                    return column;
                }
            })
            .addString("</ul>")
      .newRow()
        .newColumn()
            .addProperty(JSONCryptoDecoder.KID_JSON)
            .addSymbolicValue(JSONCryptoDecoder.KID_JSON)
        .newColumn()
            .setType(Types.WEBPKI_DATA_TYPES.STRING)
        .newColumn()
             .setChoice (false, 2)
        .newColumn()
            .addString("If the <code>" + JSONCryptoDecoder.KID_JSON +
                   "</code> property is defined, it is supposed to identify the public key associated with the encrypted (or derived) key.")
        .newRow()
        .newColumn()
          .addProperty(JSONCryptoDecoder.JWK_JSON)
          .addLink (JSONCryptoDecoder.JWK_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.OBJECT)
        .newColumn()
        .newColumn()
          .addString("Public key associated with the encrypted (or derived) key.")
     .newRow(ECDH_PROPERTIES)
        .newColumn()
          .addProperty(JSONCryptoDecoder.EPK_JSON)
          .addLink (JSONCryptoDecoder.JWK_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.OBJECT)
        .newColumn()
        .newColumn()
          .addString("Ephemeral EC public key.")
    .newRow(ECDH_KW_PROPERTIES)
        .newColumn()
          .addProperty(JSONCryptoDecoder.EPK_JSON)
          .addLink (JSONCryptoDecoder.JWK_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.OBJECT)
        .newColumn()
        .newColumn()
          .addString("Ephemeral EC public key.")
        .newRow()
        .newColumn()
          .addProperty(JSONCryptoDecoder.ENCRYPTED_KEY_JSON)
          .addSymbolicValue(JSONCryptoDecoder.ENCRYPTED_KEY_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("Encrypted symmetric key.")
     .newRow(RSA_PROPERTIES)
        .newColumn()
          .addProperty(JSONCryptoDecoder.ENCRYPTED_KEY_JSON)
          .addSymbolicValue(JSONCryptoDecoder.ENCRYPTED_KEY_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("Encrypted symmetric key.")
              .setNotes("Note that if neither <code>" + JSONCryptoDecoder.KID_JSON +
                "</code> nor <code>" + JSONCryptoDecoder.JWK_JSON + 
                "</code> are defined, the associated key is assumed to known by the recipient.");

        json.AddPublicKeyDefinitions();

        json.writeHTML();
      }

    private static String validateAsymEncryption(String text, String encryptionFile) throws IOException {
        return "<b id=\"" + JSONBaseHTML.makeLink(encryptionFile) + "\">" + encryptionFile +
                "</b>" + LINE_SEPARATOR + text + validateAsymEncryption(encryptionFile);
    }

}
