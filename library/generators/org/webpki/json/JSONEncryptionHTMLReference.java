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
import java.security.KeyPair;
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
import org.webpki.util.Base64URL;

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

    static final String JEF_TEST_STRING = "Hello encrypted world!";
    static final String JEF_SYM_KEY     = "ooQSGRnwUQYbvHjCMi0zPNARka2BuksLM7UK1RHiQwI";
    static final String JEF_EC_KEY_ID   = "20170101:mybank:ec";
    static final String JEF_RSA_KEY_ID  = "20170101:mybank:rsa";
    
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
    
    static String formatCode(JSONObjectReader rd) {
        return "<div style=\"padding:10pt 0pt 10pt 20pt;word-break:break-all;width:600pt\"><code>" +
                rd.toString().replace(" ", "&nbsp;").replace("\"", "&quot;").replace("\n", "<br>") +
                "</code></div>";
    }

    static Column preAmble(String qualifier) throws IOException {
        return json.addProtocolTable (qualifier)
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
    
    public static void main (String args[]) throws Exception {
        CustomCryptoProvider.forcedLoad(true);

        Vector<DecryptionKeyHolder> keys = new Vector<DecryptionKeyHolder>();

        JSONObjectReader ecprivatekey = readJSON("ecprivatekey.jwk");
        KeyPair keyPair = ecprivatekey.getKeyPair();
        keys.add(new DecryptionKeyHolder(keyPair.getPublic(), 
                                         keyPair.getPrivate(),
                                         KeyEncryptionAlgorithms.JOSE_ECDH_ES_ALG_ID,
                                         JEF_EC_KEY_ID));

        keys.add(new DecryptionKeyHolder(keyPair.getPublic(), 
                                         keyPair.getPrivate(),
                                         KeyEncryptionAlgorithms.JOSE_ECDH_ES_A128KW_ALG_ID,
                                         JEF_EC_KEY_ID));

        keys.add(new DecryptionKeyHolder(keyPair.getPublic(), 
                                         keyPair.getPrivate(),
                                         KeyEncryptionAlgorithms.JOSE_ECDH_ES_A192KW_ALG_ID,
                                         JEF_EC_KEY_ID));

        keys.add(new DecryptionKeyHolder(keyPair.getPublic(), 
                                         keyPair.getPrivate(),
                                         KeyEncryptionAlgorithms.JOSE_ECDH_ES_A256KW_ALG_ID,
                                         JEF_EC_KEY_ID));

        JSONObjectReader rsaprivatekey = readJSON("rsaprivatekey.jwk");
        keyPair = rsaprivatekey.getKeyPair();
        keys.add(new DecryptionKeyHolder(keyPair.getPublic(), 
                                         keyPair.getPrivate(),
                                         KeyEncryptionAlgorithms.JOSE_RSA_OAEP_256_ALG_ID,
                                         JEF_RSA_KEY_ID));

        JSONObjectReader ecdhEncryption = readJSON("ecdh-es.json");
        verifyDecryption(ecdhEncryption.getEncryptionObject().getDecryptedData(keys));

        JSONObjectReader authData = ecdhEncryption.clone();
        authData.removeProperty(JSONDecryptionDecoder.TAG_JSON);
        authData.removeProperty(JSONDecryptionDecoder.IV_JSON);
        authData.removeProperty(JSONDecryptionDecoder.CIPHER_TEXT_JSON);
        String formattedAuthData = authData.serializeToString(JSONOutputFormats.NORMALIZED);
        for (int l = formattedAuthData.length(), j = 0, i = 0; i < l; i++) {
            if (i % 118 == 0 && i > 0) {
                formattedAuthData = formattedAuthData.substring(0, i + j) + 
                        "<br>" + formattedAuthData.substring(i + j);
                j += 4;
            }
        }
        formattedAuthData = formattedAuthData.replace("\"", "&quot;");

        JSONObjectReader ecdhEncryption2 = readJSON("ecdh-es.2.json");
        verifyDecryption(ecdhEncryption2.getEncryptionObject().getDecryptedData(keys));
        
        JSONObjectReader ecdhEncryption3 = readJSON("ecdh-es.3.json");
        verifyDecryption(ecdhEncryption3.getEncryptionObject().getDecryptedData(keys));

        JSONObjectReader ecdhEncryption4 = readJSON("ecdh-es.4.json");
        verifyDecryption(ecdhEncryption4.getEncryptionObject().getDecryptedData(keys));

        JSONObjectReader ecdhEncryption5 = readJSON("ecdh-es.5.json");
        verifyDecryption(ecdhEncryption5.getEncryptionObject().getDecryptedData(keys));

        JSONObjectReader rsaEncryption = readJSON("rsa-oaep-256.json");
        verifyDecryption(rsaEncryption.getEncryptionObject().getDecryptedData(keys));

        JSONObjectReader rsaEncryption2 = readJSON("rsa-oaep-256.2.json");
        verifyDecryption(rsaEncryption2.getEncryptionObject().getDecryptedData(keys));

        JSONObjectReader aesEncryption = readJSON("a128cbc-hs256.json");
        verifyDecryption(aesEncryption.getEncryptionObject().getDecryptedData(Base64URL.decode(JEF_SYM_KEY)));

        json = new JSONBaseHTML(args, "JEF - JSON Encryption Format");
        
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
          .append(" objects while the encryption container itself utilizes JCS ")
          .append(json.createReference(JSONBaseHTML.REF_JCS))
          .append(" notation in order to maintain a consistent &quot;style&quot; in applications using encryption and signatures."
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
          .append("The following tables describe the JEF JSON structures in detail." +
                   " Note that <a href=\"#" + JSONDecryptionDecoder.KEY_ENCRYPTION_JSON + "\">" + 
                   JSONDecryptionDecoder.KEY_ENCRYPTION_JSON + "</a>" +
                   " can be used as a stand-alone object as well as a part of an <a href=\"#" + 
                   ENCRYPTED_DATA + "\">" + ENCRYPTED_DATA + "</a> object.");
        
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
                "used by the symmetric chipers. " +
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

        json.addParagraphObject(TEST_VECTORS).append("The following test data can be used to verify the correctness " +
            "of a JEF implementation." + LINE_SEPARATOR + 
           "All encryption tests encrypt the following string (after first having converted it to UTF-8):" +
           "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>&quot;" + JEF_TEST_STRING +
           "&quot;</code></div>" + LINE_SEPARATOR +
           "The <a href=\"#" + JSONBaseHTML.makeLink(SAMPLE_OBJECT) + "\">" + SAMPLE_OBJECT + "</a>" +
            " can be decrypted by the following private key (also known as <code>" +
           JEF_EC_KEY_ID + "</code>) in JWK " + 
           json.createReference(JSONBaseHTML.REF_JWK) + " format:" +
           formatCode(ecprivatekey) +
           "Alternative ECDH encryption object <i>using the same private key</i> " +
           "while providing the public key information in line, instead of using a <code>" +
           JSONSignatureDecoder.KEY_ID_JSON + "</code>:" +
           formatCode(ecdhEncryption2) +
           "Alternative ECDH encryption object <i>using the same private key</i> " +
           "while using a different set of " +
           "algorithms both for key derivation and content encryption:" +
           formatCode(ecdhEncryption3) +
           "Alternative ECDH encryption object <i>using the same private key</i> " +
           "while using a different set of " +
           "algorithms both for key derivation and content encryption:" +
           formatCode(ecdhEncryption4) +
           "Alternative ECDH encryption object <i>using the same private key</i> " +
           "while using a different set of " +
           "algorithms both for key derivation and content encryption:" +
           formatCode(ecdhEncryption5) + LINE_SEPARATOR +
           "AES encrypted data using RSA for key encryption:" +
           formatCode(rsaEncryption) +
           "Matching RSA private key (also known as <code>" +
           JEF_RSA_KEY_ID + "</code>) in JWK " + 
           json.createReference(JSONBaseHTML.REF_JWK) + " format:" +
           formatCode(rsaprivatekey) +
           "Alternative RSA encryption object <i>using the same private key</i> " +
           "while providing the public key information in line, instead of using a <code>" +
           JSONSignatureDecoder.KEY_ID_JSON + "</code>:" +
           formatCode(rsaEncryption2) + LINE_SEPARATOR +
           "AES encrypted data relying on a known symmetric key:" +
           formatCode(aesEncryption) +
           "Matching AES key, here in Base64URL notation:" +
           "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>&quot;" + JEF_SYM_KEY +
           "&quot;</code></div>");

        json.addReferenceTable();
        
        json.addDocumentHistoryLine("2016-08-03", "0.3", "Initial publication in HTML5");
        json.addDocumentHistoryLine("2017-04-19", "0.4", "Changed public keys to use JWK " + json.createReference(JSONBaseHTML.REF_JWK) + " format");
        json.addDocumentHistoryLine("2017-04-25", "0.5", "Added KW and GCM algorithms");

        json.addParagraphObject("Author").append("JEF was developed by Anders Rundgren (<code>anders.rundgren.net@gmail.com</code>) as a part " +
                                                 "of the OpenKeyStore " +
                                                 json.createReference(JSONBaseHTML.REF_OPENKEYSTORE) + " project .");

    preAmble(ENCRYPTED_DATA)
        .addString("Data encryption algorithm. Currently the following JWA " +
            json.createReference(JSONBaseHTML.REF_JWA) +
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
                      "</code> are defined, the (symmetric) encryption key is assumed to known by the recepient.");
          
        preAmble(JSONDecryptionDecoder.KEY_ENCRYPTION_JSON)
            .addString("Key encryption algorithm. Currently the following JWA " +
                                json.createReference (JSONBaseHTML.REF_JWA) +
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
                  "</code> are defined, the static EC key pair to use is assumed to known by the recepient.");

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
                  "</code> are defined, the static EC key pair to use is assumed to known by the recepient.");

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
                "</code> are defined, the RSA key pair to use is assumed to known by the recepient.");

        json.addSubItemTable (JSONSignatureDecoder.PUBLIC_KEY_JSON)
        .newRow()
          .newColumn()
            .addProperty(JSONSignatureDecoder.KTY_JSON)
            .addSymbolicValue(JSONSignatureDecoder.KTY_JSON)
          .newColumn()
            .setType(Types.WEBPKI_DATA_TYPES.STRING)
          .newColumn()
          .newColumn()
            .addString("Key type indicator.  Currently the following types are recognized:<ul>" +
                    "<li>" + JSONBaseHTML.codeVer(JSONSignatureDecoder.EC_PUBLIC_KEY, 6) + "See: ")
                    .addLink (JCS_PUBLIC_KEY_EC)
            .addString("</li><li>" + 
                     JSONBaseHTML.codeVer(JSONSignatureDecoder.RSA_PUBLIC_KEY, 6) + "See: ")
            .addLink (JCS_PUBLIC_KEY_RSA)
            .addString("</li></ul>");

    json.addSubItemTable (JCS_PUBLIC_KEY_EC)
       .newRow()
          .newColumn()
            .addProperty(JSONSignatureDecoder.CRV_JSON)
            .addSymbolicValue(JSONSignatureDecoder.CRV_JSON)
          .newColumn()
            .setType(Types.WEBPKI_DATA_TYPES.STRING)
          .newColumn()
          .newColumn()
            .addString("EC curve ID. The currently recognized EC curves include:")
            .addString(enumerateJoseEcCurves ())
      .newRow()
        .newColumn()
          .addProperty(JSONSignatureDecoder.X_JSON)
          .addSymbolicValue(JSONSignatureDecoder.X_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("EC curve point X." +
                  " The length of this field <b>must</b> " +
                  "be the full size of a coordinate for the curve specified in the <code>" + 
                  JSONSignatureDecoder.CRV_JSON + "</code> parameter.  For example, " +
                  "if the value of <code>" + JSONSignatureDecoder.CRV_JSON + "</code> is <code>" +
                  KeyAlgorithms.NIST_P_521.getAlgorithmId (AlgorithmPreferences.JOSE) +
                  "</code>, the <i>decoded</i> argument <b>must</b> be 66 bytes.")
      .newRow()
        .newColumn()
          .addProperty(JSONSignatureDecoder.Y_JSON)
          .addSymbolicValue(JSONSignatureDecoder.Y_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("EC curve point Y." +
                  " The length of this field <b>must</b> " +
                  "be the full size of a coordinate for the curve specified in the <code>" + 
                  JSONSignatureDecoder.CRV_JSON + "</code> parameter.  For example, " +
                  "if the value of <code>" + JSONSignatureDecoder.CRV_JSON + "</code> is <code>" +
                  KeyAlgorithms.NIST_P_521.getAlgorithmId (AlgorithmPreferences.JOSE) +
                  "</code>, the <i>decoded</i> argument <b>must</b> be 66 bytes.");

    json.addSubItemTable (JCS_PUBLIC_KEY_RSA)
      .newRow()
        .newColumn()
          .addProperty(JSONSignatureDecoder.N_JSON)
          .addSymbolicValue(JSONSignatureDecoder.N_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.CRYPTO)
        .newColumn()
        .newColumn()
          .addString("RSA modulus. Also see the ")
          .addDataTypeLink (Types.WEBPKI_DATA_TYPES.CRYPTO)
          .addString(" data type.")
      .newRow()
        .newColumn()
          .addProperty(JSONSignatureDecoder.E_JSON)
          .addSymbolicValue(JSONSignatureDecoder.E_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.CRYPTO)
        .newColumn()
        .newColumn()
          .addString("RSA exponent. Also see the ")
          .addDataTypeLink (Types.WEBPKI_DATA_TYPES.CRYPTO)
          .addString(" data type.");

        json.writeHTML();
      }

    static void verifyDecryption(byte[] decryptedData) throws IOException {
        if (!ArrayUtil.compare(JEF_TEST_STRING.getBytes("UTF-8"), decryptedData)) {
            throw new IOException("Decrypt");
        }
    }
}
