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
import java.io.Serializable;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;

import java.util.regex.Pattern;

import org.webpki.crypto.AlgorithmPreferences;

/**
 * Common crypto decoder classes for JEF and JCS.
 */
public class JSONCryptoDecoder implements Serializable {

    private static final long serialVersionUID = 1L;
    
    private JSONCryptoDecoder() {}

    // Arguments
    public static final String EC_PUBLIC_KEY           = "EC";

    public static final String RSA_PUBLIC_KEY          = "RSA";

    // JSON properties
    public static final String ALG_JSON                = "alg";

    public static final String CRV_JSON                = "crv";            // JWK

    public static final String E_JSON                  = "e";              // JWK

    public static final String EXCL_JSON               = "excl";           // JCS specific non-protected

    public static final String CRIT_JSON               = "crit";           // JWS extension

    public static final String JKU_JSON                = "jku";            // Remote JWK set url

    public static final String KID_JSON                = "kid";

    public static final String KEYS_JSON               = "keys";           // for JWK sets

    public static final String KTY_JSON                = "kty";            // JWK

    public static final String N_JSON                  = "n";              // JWK

    public static final String JWK_JSON                = "jwk";            // Public key holder

    public static final String SIGNATURE_JSON          = "signature";      // JCS - Single signatures

    public static final String SIGNATURES_JSON         = "signatures";     // JCS - Multiple signatures

    public static final String VAL_JSON                = "val";            // JCS specific signature value 

    public static final String X_JSON                  = "x";              // JWK

    public static final String Y_JSON                  = "y";              // JWK
    
    public static final String X5C_JSON                = "x5c";            // Certificate path

    public static final String X5T_JSON                = "x5t";            // Certificate SHA-1 thumbprint

    public static final String X5T_S256_JSON           = "x5t#s256";       // Certificate SHA-256 thumbprint

    public static final String X5U_JSON                = "x5u";            // PEM certificate path on URL
    
    public static final String ENCRYPTED_KEY_JSON      = "encrypted_key";

    public static final String EPK_JSON                = "epk";

    public static final String ENC_JSON                = "enc";

    public static final String AAD_JSON                = "aad";

    public static final String IV_JSON                 = "iv";

    public static final String TAG_JSON                = "tag";

    public static final String CIPHER_TEXT_JSON        = "ciphertext";

    public static final String RECIPIENTS_JSON         = "recipients";

    static final LinkedHashSet<String> jefReservedWords = new LinkedHashSet<String>();

    static {
        jefReservedWords.add(ALG_JSON);
        jefReservedWords.add(ENC_JSON);
        jefReservedWords.add(IV_JSON);
        jefReservedWords.add(TAG_JSON);
        jefReservedWords.add(AAD_JSON);
        jefReservedWords.add(ENCRYPTED_KEY_JSON);
        jefReservedWords.add(EPK_JSON);
        jefReservedWords.add(CIPHER_TEXT_JSON);
        jefReservedWords.add(RECIPIENTS_JSON);
        jefReservedWords.add(CRIT_JSON);
        jefReservedWords.add(KID_JSON);
        jefReservedWords.add(JWK_JSON);
        jefReservedWords.add(JKU_JSON);
        jefReservedWords.add(X5C_JSON);
        jefReservedWords.add(X5T_JSON);
        jefReservedWords.add(X5T_S256_JSON);
        jefReservedWords.add(X5U_JSON);
    }

    static final LinkedHashSet<String> jcsReservedWords = new LinkedHashSet<String>();

    static {
        jcsReservedWords.add(ALG_JSON);
        jcsReservedWords.add(CRIT_JSON);
        jcsReservedWords.add(EXCL_JSON);
        jcsReservedWords.add(KID_JSON);
        jcsReservedWords.add(JWK_JSON);
        jcsReservedWords.add(JKU_JSON);
        jcsReservedWords.add(X5C_JSON);
        jcsReservedWords.add(X5T_JSON);
        jcsReservedWords.add(X5T_S256_JSON);
        jcsReservedWords.add(X5U_JSON);
        jcsReservedWords.add(VAL_JSON);
    }

    static final LinkedHashSet<String> topLevelReserved = new LinkedHashSet<String>();

    static {
        topLevelReserved.add(SIGNATURE_JSON);
        topLevelReserved.add(SIGNATURES_JSON);
    }

    static final Pattern HTTPS_URL_PATTERN = Pattern.compile("^https://[-a-zA-Z0-9+&@#/%?=~_|!:,.;]*[-a-zA-Z0-9+&@#/%=~_|]");

    public static abstract class Extension {
        
        public abstract String getExtensionUri();
        
        protected abstract void decode(JSONObjectReader reader) throws IOException;
    }

    static class ExtensionEntry {
        Class<? extends Extension> extensionClass;
        boolean mandatory;
    }

    public static class ExtensionHolder {
        
        LinkedHashMap<String,ExtensionEntry> extensions = new LinkedHashMap<String,ExtensionEntry>();

        public ExtensionHolder addExtension(Class<? extends Extension> extensionClass,
                                            boolean mandatory) throws IOException {
            try {
                Extension extension = extensionClass.newInstance();
                ExtensionEntry extensionEntry = new ExtensionEntry();
                extensionEntry.extensionClass = extensionClass;
                extensionEntry.mandatory = mandatory;
                if ((extensions.put(extension.getExtensionUri(), extensionEntry)) != null) {
                    throw new IOException("Duplicate extension: " + extension.getExtensionUri());
                }
            } catch (InstantiationException e) {
                throw new IOException(e);
            } catch (IllegalAccessException e) {
                throw new IOException(e);
            }
            return this;
        }
    }

    /**
     * Parameter to Options
     *
     */
    public enum KEY_ID_OPTIONS {FORBIDDEN, REQUIRED, OPTIONAL};

    /**
     * Common JEF/JCS decoding options.
     * <p>This class holds options that are checked during decoding.</p>
     * The following options are currently recognized:
     * <ul>
     * <li>Algorithm preference.  Default: JOSE</li>
     * <li>Require public key info in line.  Default: true</li>
     * <li>keyId option.  Default: FORBIDDEN</li>
     * <li>Permitted extensions.  Default: none</li>
     * </ul>
     * In addition, the Options class is used for defining external readers for &quot;remoteKey&quot; support.
     *
     */
    public static class Options {
        
        AlgorithmPreferences algorithmPreferences = AlgorithmPreferences.JOSE;
        boolean requirePublicKeyInfo = true;
        KEY_ID_OPTIONS keyIdOption = KEY_ID_OPTIONS.FORBIDDEN;
        ExtensionHolder extensionHolder = new ExtensionHolder();
        JSONRemoteKeys.Reader remoteKeyReader;
        JSONRemoteKeys remoteKeyType;
        LinkedHashSet<String> exclusions;
        
        boolean encryptionMode;
        
        public Options setAlgorithmPreferences(AlgorithmPreferences algorithmPreferences) {
            this.algorithmPreferences = algorithmPreferences;
            return this;
        }

        public Options setRequirePublicKeyInfo(boolean flag) {
            this.requirePublicKeyInfo = flag;
            return this;
        }

        /**
         * Define external remote key reader class.
         * If set, the signature decoder assumes that there is no in-line public key or certificate information to process.   
         * @param remoteKeyReader Interface
         * @param remoteKeyType Expected type
         * @return this
         */
        public Options setRemoteKeyReader(JSONRemoteKeys.Reader remoteKeyReader,
                                          JSONRemoteKeys remoteKeyType) {
            this.remoteKeyReader = remoteKeyReader;
            this.remoteKeyType = remoteKeyType;
            return this;
        }

        public Options setKeyIdOption(KEY_ID_OPTIONS keyIdOption) {
            this.keyIdOption = keyIdOption;
            return this;
        }

        public Options setPermittedExtensions(ExtensionHolder extensionHolder) {
            this.extensionHolder = extensionHolder;
            return this;
        }

        public Options setPermittedExclusions(String[] exclusions) throws IOException {
            this.exclusions = JSONSignatureDecoder.checkExcluded(exclusions);
            return this;
        }

        void encryptionMode(boolean flag) throws IOException {
            encryptionMode = flag;
            if (flag) {
                if (exclusions != null) {
                    throw new IOException("\"setPermittedExclusions()\" is not applicable to encryption");
                }
            }
            for (String extension : extensionHolder.extensions.keySet()) {
                checkOneExtension(extension, flag);
            }
        }

        String getKeyId(JSONObjectReader reader) throws IOException {
            String keyId = reader.getStringConditional(JSONCryptoDecoder.KID_JSON);
            if (keyId == null) {
                if (keyIdOption == JSONCryptoDecoder.KEY_ID_OPTIONS.REQUIRED) {
                    throw new IOException("Missing \"" + JSONCryptoDecoder.KID_JSON + "\"");
                }
            } else if (keyIdOption == JSONCryptoDecoder.KEY_ID_OPTIONS.FORBIDDEN) {
                throw new IOException("Use of \"" + JSONCryptoDecoder.KID_JSON + "\" must be set in options");
            }
            return keyId;
        }

        void getExtensions(JSONObjectReader reader, LinkedHashMap<String, Extension> extensions) throws IOException {
            if (reader.hasProperty(JSONCryptoDecoder.CRIT_JSON)) {
                String[] properties = reader.getStringArray(JSONCryptoDecoder.CRIT_JSON);
                checkExtensions(properties, encryptionMode);
                if (extensionHolder.extensions.isEmpty()) {
                    throw new IOException("Use of \"" + JSONCryptoDecoder.CRIT_JSON + "\" must be set in options");
                }
                for (String name : properties) {
                    JSONCryptoDecoder.ExtensionEntry extensionEntry = extensionHolder.extensions.get(name);
                    if (extensionEntry == null) {
                        throw new IOException("Unexpected \"" + JSONCryptoDecoder.CRIT_JSON + "\" extension: " + name);
                    }
                    try {
                        JSONCryptoDecoder.Extension extension = extensionEntry.extensionClass.newInstance();
                        extension.decode(reader);
                        extensions.put(name, extension);
                    } catch (InstantiationException e) {
                        throw new IOException (e);
                    } catch (IllegalAccessException e) {
                        throw new IOException (e);
                    }
                }
            }
            for (String name : extensionHolder.extensions.keySet()) {
                if (!extensions.containsKey(name) && extensionHolder.extensions.get(name).mandatory) {
                    throw new IOException("Missing \"" + JSONCryptoDecoder.CRIT_JSON + "\" mandatory extension: " + name);
                }
            }
        }
    }

    private static void checkOneExtension(String property, boolean encryptionMode) throws IOException {
        if ((encryptionMode ? jefReservedWords : jcsReservedWords).contains(property)) {
            throw new IOException("Forbidden \"" + JSONCryptoDecoder.CRIT_JSON + "\" property: " + property);
        }
    }

    static void checkExtensions(String[] properties, boolean encryptionMode) throws IOException {
        if (properties.length == 0) {
            throw new IOException("Empty \"" + JSONCryptoDecoder.CRIT_JSON + "\" array not allowed");
        }
        for (String property : properties) {
            checkOneExtension(property, encryptionMode);
        }
    }
}
