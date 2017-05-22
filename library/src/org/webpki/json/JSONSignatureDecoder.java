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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import java.util.LinkedHashMap;
import java.util.Vector;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureWrapper;

/**
 * Decoder for JCS signatures.
 */
public class JSONSignatureDecoder implements Serializable {

    private static final long serialVersionUID = 1L;

    // Arguments
    public static final String EC_PUBLIC_KEY              = "EC";

    public static final String RSA_PUBLIC_KEY             = "RSA";

    public static final String SIGNATURE_VERSION_ID       = "http://xmlns.webpki.org/jcs/v1";

    // JSON properties
    public static final String ALGORITHM_JSON             = "algorithm";

    public static final String CERTIFICATE_PATH_JSON      = "certificatePath";

    public static final String CRV_JSON                   = "crv";          // JWK

    public static final String E_JSON                     = "e";            // JWK

    public static final String EXTENSIONS_JSON            = "extensions";

    public static final String FORMAT_JSON                = "format";       // Remote key argument

    public static final String ISSUER_JSON                = "issuer";

    public static final String KEY_ID_JSON                = "keyId";

    public static final String KTY_JSON                   = "kty";          // JWK

    public static final String N_JSON                     = "n";            // JWK

    public static final String PUBLIC_KEY_JSON            = "publicKey";

    public static final String REMOTE_KEY_JSON            = "remoteKey";    // Remote key

    public static final String SERIAL_NUMBER_JSON         = "serialNumber";

    public static final String SIGNATURE_JSON             = "signature";

    public static final String SIGNATURES_JSON            = "signatures";

    public static final String SIGNER_CERTIFICATE_JSON    = "signerCertificate";

    public static final String SUBJECT_JSON               = "subject";

    public static final String URI_JSON                   = "uri";          // Remote key argument

    public static final String VALUE_JSON                 = "value";

    public static final String VERSION_JSON               = "version";

    public static final String X_JSON                     = "x";            // JWK

    public static final String Y_JSON                     = "y";            // JWK

    public static abstract class Extension {
        
        protected abstract String getExtensionUri();
        
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
     * Signature decoding options.
     * <p>This class holds options that are checked during signature decoding.</p>
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

        public Options setAlgorithmPreferences(AlgorithmPreferences algorithmPreferences) {
            this.algorithmPreferences = algorithmPreferences;
            return this;
        }

        public Options setRequirePublicKeyInfo(boolean flag) {
            this.requirePublicKeyInfo = flag;
            return this;
        }

        /**
         * Define external &quot;remoteKey&quot; reader class.
         * If set, the signature decoder assumes that there is no in-line public key or certificate information to process.   
         * @param remoteKeyReader Interface
         * @return this
         */
        public Options setRemoteKeyReader(JSONRemoteKeys.Reader remoteKeyReader) {
            this.remoteKeyReader = remoteKeyReader;
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
    }

    SignatureAlgorithms algorithm;

    String algorithmString;

    byte[] normalizedData;

    byte[] signatureValue;

    X509Certificate[] certificatePath;

    PublicKey publicKey;

    String keyId;
    
    Options options;
    
    LinkedHashMap<String,Extension> extensions = new LinkedHashMap<String,Extension>();

    JSONSignatureDecoder(JSONObjectReader rd,
                         JSONObjectReader signature,
                         Options options) throws IOException {
        this.options = options;
        if (options.requirePublicKeyInfo && options.keyIdOption != KEY_ID_OPTIONS.FORBIDDEN) {
            throw new IOException("Incompatible keyId and publicKey options - Choose one");
        }
        String version = signature.getStringConditional(VERSION_JSON, SIGNATURE_VERSION_ID);
        if (!version.equals(SIGNATURE_VERSION_ID)) {
            throw new IOException("Unknown \"" + SIGNATURE_JSON + "\" version: " + version);
        }
        algorithmString = signature.getString(ALGORITHM_JSON);
        keyId = signature.getStringConditional(KEY_ID_JSON);
        if (keyId == null) {
            if (options.keyIdOption == KEY_ID_OPTIONS.REQUIRED) {
                throw new IOException("Missing \"" + KEY_ID_JSON + "\"");
            }
        } else if (options.keyIdOption == KEY_ID_OPTIONS.FORBIDDEN) {
            throw new IOException("Use of \"" + KEY_ID_JSON + "\" must be set in options");
        }
        if (options.requirePublicKeyInfo) {
            getPublicKeyInfo(signature);
        } else {
            for (AsymSignatureAlgorithms alg : AsymSignatureAlgorithms.values()) {
                if (algorithmString.equals(alg.getAlgorithmId(AlgorithmPreferences.JOSE_ACCEPT_PREFER)) ||
                        algorithmString.equals(alg.getAlgorithmId(AlgorithmPreferences.SKS))) {
                    algorithm = AsymSignatureAlgorithms.getAlgorithmFromId(algorithmString, 
                                                                           options.algorithmPreferences);
                    break;
                }
            }
            if (algorithm == null) {
                algorithm = MACAlgorithms.getAlgorithmFromId(algorithmString, options.algorithmPreferences);
            }
        }
        if (signature.hasProperty(EXTENSIONS_JSON)) {
            JSONObjectReader extensionReader = signature.getObject(EXTENSIONS_JSON);
            if (extensionReader.getProperties().length == 0) {
                throw new IOException("Empty \"" + EXTENSIONS_JSON + "\" object not allowed");
            }
            for (String name : extensionReader.getProperties()) {
                ExtensionEntry extensionEntry = options.extensionHolder.extensions.get(name);
                if (extensionEntry == null) {
                    throw new IOException("Unknown extension: " + name);
                }
                try {
                    Extension extension = extensionEntry.extensionClass.newInstance();
                    extension.decode(extensionReader);
                    extensions.put(name, extension);
                } catch (InstantiationException e) {
                    throw new IOException (e);
                } catch (IllegalAccessException e) {
                    throw new IOException (e);
                }
            }
        }
        for (String name : options.extensionHolder.extensions.keySet()) {
            if (!extensions.containsKey(name) && options.extensionHolder.extensions.get(name).mandatory) {
                throw new IOException("Missing mandatory extension: " + name);
            }
        }
        signatureValue = signature.getBinary(VALUE_JSON);

        //////////////////////////////////////////////////////////////////////////
        // Begin JCS normalization                                              //
        //                                                                      //
        // 1. Make a shallow copy of the signature object property list         //
        LinkedHashMap<String, JSONValue> savedProperties =
                new LinkedHashMap<String, JSONValue>(signature.root.properties);
        //                                                                      //
        // 2. Hide property for the serializer..                                //
        signature.root.properties.remove(VALUE_JSON);                           //
        //                                                                      //
        // 3. Serialize ("JSON.stringify()")                                    //
        normalizedData = rd.serializeToBytes(JSONOutputFormats.NORMALIZED);
        //                                                                      //
        // 4. Check for unread data                                             //
        signature.checkForUnread();                                             //
        //                                                                      //
        // 5. Restore signature property list                                   //
        signature.root.properties = savedProperties;
        //                                                                      //
        // End JCS normalization                                                //
        //////////////////////////////////////////////////////////////////////////

        if (options.requirePublicKeyInfo) switch (getSignatureType()) {
            case X509_CERTIFICATE:
                asymmetricSignatureVerification(certificatePath[0].getPublicKey());
                break;

            case ASYMMETRIC_KEY:
                asymmetricSignatureVerification(publicKey);
                break;

            default:
                // Should be a symmetric key then...
                break;
        }
    }

    void getPublicKeyInfo(JSONObjectReader rd) throws IOException {
        algorithm = AsymSignatureAlgorithms.getAlgorithmFromId(algorithmString, 
                                                               options.algorithmPreferences);
        if (options.remoteKeyReader != null) {
            JSONObjectReader remoteKeyInfo = rd.getObject(REMOTE_KEY_JSON);
            String url = remoteKeyInfo.getString(URI_JSON);
            JSONRemoteKeys format = JSONRemoteKeys.getFormatFromId(remoteKeyInfo.getString(FORMAT_JSON));
            if (format.certificatePath) {
                certificatePath = options.remoteKeyReader.readCertificatePath(url, format);
            } else {
                publicKey = options.remoteKeyReader.readPublicKey(url, format);
            }
        } else if (rd.hasProperty(CERTIFICATE_PATH_JSON)) {
            readCertificateData(rd);
        } else if (rd.hasProperty(PUBLIC_KEY_JSON)) {
            publicKey = rd.getPublicKey(options.algorithmPreferences);
        } else {
            throw new IOException("Missing key information");
        }
    }

    static BigInteger getCurvePoint(JSONObjectReader rd, String property, KeyAlgorithms ec) throws IOException {
        byte[] fixedBinary = rd.getBinary(property);
        if (fixedBinary.length != (ec.getPublicKeySizeInBits() + 7) / 8) {
            throw new IOException("Public EC key parameter \"" + property + "\" is not normalized");
        }
        return new BigInteger(1, fixedBinary);
    }

    static BigInteger getCryptoBinary(JSONObjectReader rd, String property) throws IOException {
        byte[] cryptoBinary = rd.getBinary(property);
        if (cryptoBinary[0] == 0x00) {
            throw new IOException("Public RSA key parameter \"" + property + "\" contains leading zeroes");
        }
        return new BigInteger(1, cryptoBinary);
    }

    static PublicKey decodePublicKey(JSONObjectReader rd,
                                     AlgorithmPreferences algorithmPreferences) throws IOException {
        PublicKey publicKey = null;
        try {
            String type = rd.getString(KTY_JSON);
            if (type.equals(RSA_PUBLIC_KEY)) {
                publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(getCryptoBinary(rd, N_JSON),
                        getCryptoBinary(rd, E_JSON)));
            } else if (type.equals(EC_PUBLIC_KEY)) {
                KeyAlgorithms ec = KeyAlgorithms.getKeyAlgorithmFromId(rd.getString(CRV_JSON), algorithmPreferences);
                if (!ec.isECKey()) {
                    throw new IOException("\"" + CRV_JSON + "\" is not an EC type");
                }
                ECPoint w = new ECPoint(getCurvePoint(rd, X_JSON, ec), getCurvePoint(rd, Y_JSON, ec));
                publicKey = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(w, ec.getECParameterSpec()));
            } else {
                throw new IOException("Unrecognized \"" + PUBLIC_KEY_JSON + "\": " + type);
            }
            return publicKey;
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    static X509Certificate[] makeCertificatePath(Vector<byte[]> certificateBlobs) throws IOException {
        X509Certificate lastCertificate = null;
        Vector<X509Certificate> certificates = new Vector<X509Certificate>();
        for (byte[] certificateBlob : certificateBlobs) {
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                X509Certificate certificate = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certificateBlob));
                certificates.add(pathCheck(lastCertificate, lastCertificate = certificate));
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
        }
        return certificates.toArray(new X509Certificate[0]);
    }

    static X509Certificate[] getCertificatePath(JSONObjectReader rd) throws IOException {
        return makeCertificatePath(rd.getBinaryArray(CERTIFICATE_PATH_JSON));
    }

    void readCertificateData(JSONObjectReader rd) throws IOException {
        certificatePath = getCertificatePath(rd);
        if (rd.hasProperty(SIGNER_CERTIFICATE_JSON)) {
            rd = rd.getObject(SIGNER_CERTIFICATE_JSON);
            String issuer = rd.getString(ISSUER_JSON);
            BigInteger serialNumber = rd.getBigInteger(SERIAL_NUMBER_JSON);
            String subject = rd.getString(SUBJECT_JSON);
            X509Certificate signatureCertificate = certificatePath[0];
            if (!signatureCertificate.getIssuerX500Principal().getName().equals(issuer) ||
                !signatureCertificate.getSerialNumber().equals(serialNumber) ||
                !signatureCertificate.getSubjectX500Principal().getName().equals(subject)) {
                throw new IOException("\"" + SIGNER_CERTIFICATE_JSON + "\" doesn't match actual certificate");
            }
        }
    }

    void checkVerification(boolean success) throws IOException {
        if (!success) {
            String key;
            switch (getSignatureType()) {
                case X509_CERTIFICATE:
                    key = certificatePath[0].getPublicKey().toString();
                    break;

                case ASYMMETRIC_KEY:
                    key = publicKey.toString();
                    break;

                default:
                    key = getKeyId();
            }
            throw new IOException("Bad signature for key: " + key);
        }
    }

    void asymmetricSignatureVerification(PublicKey publicKey) throws IOException {
        if (((AsymSignatureAlgorithms) algorithm).isRsa() != publicKey instanceof RSAPublicKey) {
            throw new IOException("\"" + algorithmString + "\" doesn't match key type: " + publicKey.getAlgorithm());
        }
        try {
            checkVerification(new SignatureWrapper((AsymSignatureAlgorithms) algorithm, publicKey)
                .update(normalizedData)
                .verify(signatureValue));
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    public byte[] getValue() {
        return signatureValue;
    }

    public SignatureAlgorithms getAlgorithm() {
        return algorithm;
    }

    public Extension getExtension(String name) {
        return extensions.get(name);
    }

    void checkRequest(JSONSignatureTypes signatureType) throws IOException {
        if (signatureType != getSignatureType()) {
            throw new IOException("Request doesn't match received signature: " + getSignatureType().toString());
        }
    }

    public X509Certificate[] getCertificatePath() throws IOException {
        checkRequest(JSONSignatureTypes.X509_CERTIFICATE);
        return certificatePath;
    }

    public PublicKey getPublicKey() throws IOException {
        checkRequest(JSONSignatureTypes.ASYMMETRIC_KEY);
        return publicKey;
    }

    public String getKeyId() {
        return keyId;
    }

    public byte[] getNormalizedData() {
        return normalizedData;
    }

    public JSONSignatureTypes getSignatureType() {
        if (certificatePath != null) {
            return JSONSignatureTypes.X509_CERTIFICATE;
        }
        return algorithm instanceof AsymSignatureAlgorithms ? JSONSignatureTypes.ASYMMETRIC_KEY : JSONSignatureTypes.SYMMETRIC_KEY;
    }

    /**
     * Simplified verify that only checks that there are no "keyId" or "extensions", and that the signature type matches.
     * Note that asymmetric key signatures are always checked for technical correctness unless
     * you have specified false for requirePublicKeyInfo.
     *
     * @param signatureType Type of signature :-)
     * @throws IOException &nbsp;
     */
    public void verify(JSONSignatureTypes signatureType) throws IOException {
        verify(new JSONVerifier(signatureType) {
            private static final long serialVersionUID = 1L;

                @Override
                void verify(JSONSignatureDecoder signatureDecoder) throws IOException {
            }
        });
    }

    public void verify(JSONVerifier verifier) throws IOException {
        checkRequest(verifier.signatureType);
        verifier.verify(this);
    }

    static X509Certificate pathCheck(X509Certificate child, X509Certificate parent) throws IOException {
        if (child != null) {
            String issuer = child.getIssuerX500Principal().getName();
            String subject = parent.getSubjectX500Principal().getName();
            if (!issuer.equals(subject)) {
                throw new IOException("Path issuer order error, '" + issuer + "' versus '" + subject + "'");
            }
            try {
                child.verify(parent.getPublicKey());
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
        }
        return parent;
    }

    static PrivateKey decodePrivateKey(JSONObjectReader rd, PublicKey publicKey) throws IOException {
        try {
            KeyAlgorithms keyAlgorithm = KeyAlgorithms.getKeyAlgorithm(publicKey);
            if (keyAlgorithm.isECKey()) {
                return KeyFactory.getInstance("EC")
                        .generatePrivate(new ECPrivateKeySpec(getCurvePoint(rd, "d", keyAlgorithm),
                                                              keyAlgorithm.getECParameterSpec()));
            }
            return KeyFactory.getInstance("RSA")
                    .generatePrivate(new RSAPrivateCrtKeySpec(((RSAPublicKey) publicKey).getModulus(),
                                                              ((RSAPublicKey) publicKey).getPublicExponent(),
                                                              getCryptoBinary(rd, "d"),
                                                              getCryptoBinary(rd, "p"),
                                                              getCryptoBinary(rd, "q"),
                                                              getCryptoBinary(rd, "dp"),
                                                              getCryptoBinary(rd, "dq"),
                                                              getCryptoBinary(rd, "qi")));
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }
}
