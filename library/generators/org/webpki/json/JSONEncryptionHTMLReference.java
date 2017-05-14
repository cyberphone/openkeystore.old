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

import java.security.interfaces.RSAPublicKey;

import java.util.Vector;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.KeyAlgorithms;

import org.webpki.json.JSONBaseHTML.Extender;
import org.webpki.json.JSONBaseHTML.RowInterface;
import org.webpki.json.JSONBaseHTML.Types;
import org.webpki.json.JSONBaseHTML.ProtocolObject.Row.Column;

import org.webpki.json.encryption.KeyEncryptionAlgorithms;
import org.webpki.json.encryption.DataEncryptionAlgorithms;
import org.webpki.json.encryption.DecryptionKeyHolder;

import org.webpki.util.ArrayUtil;

/**
 * Create an HTML description of JEF (JSON Encryption Format).
 * 
 * @author Anders Rundgren
 */
public class JSONEncryptionHTMLReference extends JSONBaseHTML.Types {
    
    static JSONBaseHTML json;
    static RowInterface row;
    static String ECDH_PROPERTIES       = "Additional ECDH properties";
    static String ECDH_KW_PROPERTIES    = "Additional ECDH+KW properties";
    static String RSA_PROPERTIES        = "Additional RSA encryption properties";
    static String JCS_PUBLIC_KEY_EC     = "Additional EC key properties";
    static String JCS_PUBLIC_KEY_RSA    = "Additional RSA key properties";

    static final String ENCRYPTED_DATA  = "encryptedData";
    
    static final String TEST_VECTORS    = "Test Vectors";
    
    static final String SAMPLE_OBJECT   = "Sample Object";
    
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
        return "<div style=\"padding:10pt 0pt 10pt 20pt;word-break:break-all;width:600pt\"><code>" +
                code.replace(" ", "&nbsp;").replace("\"", "&quot;").replace("\n", "<br>") +
                "</code></div>";
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
                    .addProperty(JSONSignatureDecoder.VERSION_JSON)
                    .addValue(JSONDecryptionDecoder.ENCRYPTION_VERSION_ID)
                .newColumn()
                    .setType(Types.WEBPKI_DATA_TYPES.URI)
                .newColumn()
                    .setUsage(false)
                .newColumn()
                    .addString("Encryption object version identifier." +
                               " For future revisions of JEF, this property would be mandatory.")
            .newRow()
                .newColumn()
                    .addProperty(JSONSignatureDecoder.ALGORITHM_JSON)
                    .addSymbolicValue(JSONSignatureDecoder.ALGORITHM_JSON)
                .newColumn()
                    .setType(Types.WEBPKI_DATA_TYPES.URI)
                .newColumn()
                .newColumn();
    }
    
    static Vector<DecryptionKeyHolder> keys = new Vector<DecryptionKeyHolder>();
    
    static byte[] dataToEncrypt;

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
        for (KeyEncryptionAlgorithms kea : KeyEncryptionAlgorithms.values()) {
            if (kea.isRsa() == asymKey.keyPair.getPublic() instanceof RSAPublicKey) {
                keys.add(new DecryptionKeyHolder(asymKey.keyPair.getPublic(),
                                                 asymKey.keyPair.getPrivate(),
                                                 kea,
                                                 asymKey.keyId));
            }
        }
        return asymKey;
    }
    
    static String readAsymEncryption(String name) throws IOException, GeneralSecurityException {
        JSONObjectReader rd = json.readJson2(name);
        if (!ArrayUtil.compare(rd.getEncryptionObject().getDecryptedData(keys), dataToEncrypt)) {
            throw new IOException(name);
        }
        return formatCode(rd);
    }
    
    static String readAsymEncryption(String name, AsymKey asymKey) throws IOException, GeneralSecurityException {
        JSONObjectReader rd = json.readJson2(name);
        if (!ArrayUtil.compare(rd.getEncryptionObject().getDecryptedData(asymKey.keyPair.getPrivate()), dataToEncrypt)) {
            throw new IOException(name);
        }
        return formatCode(rd);
    }

    static String aesCrypto(String[] encObjects) throws IOException, GeneralSecurityException {
        StringBuffer s = new StringBuffer();
        JSONObjectReader symmetricKeys = json.readJson1("symmetrickeys.json");
        for (String name : encObjects) {
            JSONObjectReader rd = json.readJson2(name);
            JSONDecryptionDecoder dec = rd.getEncryptionObject();
            for (String keyProp : symmetricKeys.getProperties()) {
                byte[] key = symmetricKeys.getBinary(keyProp);
                if (key.length == dec.getDataEncryptionAlgorithm().getKeyLength()) {
                    s.append(LINE_SEPARATOR + "AES key named <code>&quot;")
                     .append(keyProp)
                     .append("&quot;</code> here provided in Base64URL notation:")
                     .append(formatCode(symmetricKeys.getString(keyProp)))
                     .append("Encryption object requiring the key above for decryption:")
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
     
        AsymKey p256key = readAsymKey("p256privatekey.jwk");
        AsymKey p384key = readAsymKey("p384privatekey.jwk");
        AsymKey p521key = readAsymKey("p521privatekey.jwk");
        AsymKey r2048key = readAsymKey("r2048privatekey.jwk");
        

        JSONObjectReader ecdhEncryption = json.readJson2("p256ecdh-es+a256kw.implicitkey.json");
        JSONObjectReader authData = ecdhEncryption.clone();
        authData.removeProperty(JSONDecryptionDecoder.TAG_JSON);
        authData.removeProperty(JSONDecryptionDecoder.IV_JSON);
        authData.removeProperty(JSONDecryptionDecoder.CIPHER_TEXT_JSON);
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
                  "<i>including providing header information in clear</i>."
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
                "<li>The <i>top level</i> properties <code>" + JSONDecryptionDecoder.IV_JSON + "</code>, " +
                "<code>" + JSONDecryptionDecoder.TAG_JSON + "</code>, and <code>" + 
                JSONDecryptionDecoder.CIPHER_TEXT_JSON +
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
           "ECDH encryption object <i>requiring the same private key</i> " +
           "as in the sample object while using a different set of " +
           "algorithms both for key encryption and content encryption:" +
           readAsymEncryption("p256ecdh-es+a128kw.implicitkey.json") +
           "ECDH encryption object <i>requiring the same private key</i> " +
           "as in the sample object while providing the public key information in line, " +
           "instead of using a <code>" + JSONSignatureDecoder.KEY_ID_JSON + "</code>:" +
           readAsymEncryption("p256ecdh-es+a256kw.encrypted.json") + LINE_SEPARATOR +
           "EC private key for decrypting the subsequent object:" +
           formatCode(p384key) +
           "ECDH encryption object <i>requiring the private key above</i>:" +
           readAsymEncryption("p384ecdh-es.encrypted.json") + LINE_SEPARATOR +
           "EC private key for decrypting the subsequent object:" +
           formatCode(p521key) +
           "ECDH encryption object <i>requiring the private key above</i>:" +
           readAsymEncryption("p521ecdh-es+a128kw.encrypted.json") + LINE_SEPARATOR +
           "RSA private key for decrypting the subsequent object:" +
           formatCode(r2048key) +
           "RSA encryption object <i>requiring the private key above</i>:" +
           readAsymEncryption("r2048rsa-oaep-256.encrypted.json") +
           "RSA encryption object <i>requiring the same private key</i> " +
           "as in the previous example but relying on that this being " +
           "<i>implicitely known</i> since the encryption object " +
           "neither contains a <code>" +
           JSONSignatureDecoder.KEY_ID_JSON + "</code>, nor a <code>" +
           JSONSignatureDecoder.PUBLIC_KEY_JSON + "</code> property:" +
           readAsymEncryption("r2048rsa-oaep-256.implicitkey.json", r2048key) +
           "RSA encryption object <i>requiring the same private key</i> " +
           "as in the previous example while using a different set of " +
           "algorithms both for key encryption and content encryption:" +
           readAsymEncryption("r2048rsa-oaep.implicitkey.json", r2048key) +
           aesCrypto(new String[]{"a128gcm.encrypted.json",
                                  "a128cbc-hs256.encrypted.json",
                                  "a256gcm.implicitkey.json",
                                  "a256gcm.encrypted.json",
                                  "a256cbc-hs512.encrypted.json"}));

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
            .addProperty(JSONSignatureDecoder.KEY_ID_JSON)
            .addSymbolicValue(JSONSignatureDecoder.KEY_ID_JSON)
        .newColumn()
            .setType(Types.WEBPKI_DATA_TYPES.STRING)
        .newColumn()
             .setChoice (false, 2)
        .newColumn()
            .addString("If the <code>" + JSONSignatureDecoder.KEY_ID_JSON +
                   "</code> property is defined, data is supposed to be encrypted by a specific named (symmetric) key.")
            .newRow()

        .newColumn()
        .addProperty(JSONDecryptionDecoder.KEY_ENCRYPTION_JSON)
        .addLink(JSONDecryptionDecoder.KEY_ENCRYPTION_JSON)
    .newColumn()
        .setType(Types.WEBPKI_DATA_TYPES.OBJECT)
    .newColumn()
    .newColumn()
        .addString("If the <code>" + JSONDecryptionDecoder.KEY_ENCRYPTION_JSON +
                   "</code> property is defined, the (symmetric) encryption key is supposed to be provided " +
                   "in-line, encrypted by a public key.")
        .newRow()
        .newColumn()
          .addProperty(JSONDecryptionDecoder.IV_JSON)
          .addSymbolicValue(JSONDecryptionDecoder.IV_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("Initialization vector.")
        .newRow()
        .newColumn()
          .addProperty(JSONDecryptionDecoder.TAG_JSON)
          .addSymbolicValue(JSONDecryptionDecoder.TAG_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("Authentication tag.")
        .newRow()
        .newColumn()
          .addProperty(JSONDecryptionDecoder.CIPHER_TEXT_JSON)
          .addSymbolicValue(JSONDecryptionDecoder.CIPHER_TEXT_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("Encrypted data.").setNotes("Note that if neither <code>" + JSONSignatureDecoder.KEY_ID_JSON +
                      "</code> nor <code>" + JSONDecryptionDecoder.KEY_ENCRYPTION_JSON + 
                      "</code> are defined, the (symmetric) encryption key is assumed to known by the recipient.");
          
        preAmble(JSONDecryptionDecoder.KEY_ENCRYPTION_JSON, true)
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
            .addString("</ul>");
        
        json.addSubItemTable(ECDH_PROPERTIES)
            .newRow()
        .newColumn()
            .addProperty(JSONSignatureDecoder.KEY_ID_JSON)
            .addSymbolicValue(JSONSignatureDecoder.KEY_ID_JSON)
        .newColumn()
            .setType(Types.WEBPKI_DATA_TYPES.STRING)
        .newColumn()
             .setChoice (false, 2)
        .newColumn()
            .addString("If the <code>" + JSONSignatureDecoder.KEY_ID_JSON +
                   "</code> property is defined, it is supposed to identify the static EC key pair.")
        .newRow()
        .newColumn()
          .addProperty(JSONSignatureDecoder.PUBLIC_KEY_JSON)
          .addLink (JSONSignatureDecoder.PUBLIC_KEY_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.OBJECT)
        .newColumn()
        .newColumn()
          .addString("Static EC public key.")
        .newRow()
        .newColumn()
          .addProperty(JSONDecryptionDecoder.EPHEMERAL_KEY_JSON)
          .addLink (JSONSignatureDecoder.PUBLIC_KEY_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.OBJECT)
        .newColumn()
        .newColumn()
          .addString("Ephemeral EC public key.")
            .setNotes("Note that if neither <code>" + JSONSignatureDecoder.KEY_ID_JSON +
                  "</code> nor <code>" + JSONSignatureDecoder.PUBLIC_KEY_JSON + 
                  "</code> are defined, the static EC key pair to use is assumed to known by the recipient.");

        json.addSubItemTable(ECDH_KW_PROPERTIES)
            .newRow()
        .newColumn()
            .addProperty(JSONSignatureDecoder.KEY_ID_JSON)
            .addSymbolicValue(JSONSignatureDecoder.KEY_ID_JSON)
        .newColumn()
            .setType(Types.WEBPKI_DATA_TYPES.STRING)
        .newColumn()
             .setChoice (false, 2)
        .newColumn()
            .addString("If the <code>" + JSONSignatureDecoder.KEY_ID_JSON +
                   "</code> property is defined, it is supposed to identify the static EC key pair.")
        .newRow()
        .newColumn()
          .addProperty(JSONSignatureDecoder.PUBLIC_KEY_JSON)
          .addLink (JSONSignatureDecoder.PUBLIC_KEY_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.OBJECT)
        .newColumn()
        .newColumn()
          .addString("Static EC public key.")
        .newRow()
        .newColumn()
          .addProperty(JSONDecryptionDecoder.EPHEMERAL_KEY_JSON)
          .addLink (JSONSignatureDecoder.PUBLIC_KEY_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.OBJECT)
        .newColumn()
        .newColumn()
          .addString("Ephemeral EC public key.")
        .newRow()
        .newColumn()
          .addProperty(JSONDecryptionDecoder.ENCRYPTED_KEY_JSON)
          .addSymbolicValue(JSONDecryptionDecoder.ENCRYPTED_KEY_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("Encrypted symmetric key.")
            .setNotes("Note that if neither <code>" + JSONSignatureDecoder.KEY_ID_JSON +
                  "</code> nor <code>" + JSONSignatureDecoder.PUBLIC_KEY_JSON + 
                  "</code> are defined, the static EC key pair to use is assumed to known by the recipient.");

        json.addSubItemTable(RSA_PROPERTIES)
            .newRow()
        .newColumn()
            .addProperty(JSONSignatureDecoder.KEY_ID_JSON)
            .addSymbolicValue(JSONSignatureDecoder.KEY_ID_JSON)
        .newColumn()
            .setType(Types.WEBPKI_DATA_TYPES.STRING)
        .newColumn()
             .setChoice (false, 2)
        .newColumn()
            .addString("If the <code>" + JSONSignatureDecoder.KEY_ID_JSON +
                   "</code> property is defined, it is supposed to identify the RSA key pair.")
        .newRow()
        .newColumn()
          .addProperty(JSONSignatureDecoder.PUBLIC_KEY_JSON)
          .addLink (JSONSignatureDecoder.PUBLIC_KEY_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.OBJECT)
        .newColumn()
        .newColumn()
          .addString("RSA public key.")
        .newRow()
        .newColumn()
          .addProperty(JSONDecryptionDecoder.ENCRYPTED_KEY_JSON)
          .addSymbolicValue(JSONDecryptionDecoder.ENCRYPTED_KEY_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("Encrypted symmetric key.")
              .setNotes("Note that if neither <code>" + JSONSignatureDecoder.KEY_ID_JSON +
                "</code> nor <code>" + JSONSignatureDecoder.PUBLIC_KEY_JSON + 
                "</code> are defined, the RSA key pair to use is assumed to known by the recipient.");

        json.AddPublicKeyDefinitions();

        json.writeHTML();
      }

}
