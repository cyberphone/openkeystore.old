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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;

import java.util.LinkedHashMap;
import java.util.Vector;

import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureWrapper;

/**
 * Decoder for JCS signatures.
 */
public class JSONSignatureDecoder implements Serializable
  {
    private static final long serialVersionUID = 1L;

    // Arguments
    public static final String EC_PUBLIC_KEY              = "EC";
    
    public static final String RSA_PUBLIC_KEY             = "RSA";
    
    public static final String SIGNATURE_VERSION_ID       = "http://xmlns.webpki.org/jcs/v1";
    
    // JSON properties
    public static final String ALGORITHM_JSON             = "algorithm";
  
    public static final String CURVE_JSON                 = "curve";
    
    public static final String E_JSON                     = "e";
    
    public static final String EXTENSIONS_JSON            = "extensions";

    public static final String ISSUER_JSON                = "issuer";
    
    public static final String KEY_ID_JSON                = "keyId";

    public static final String N_JSON                     = "n";
    
    public static final String PUBLIC_KEY_JSON            = "publicKey";
    
    public static final String SERIAL_NUMBER_JSON         = "serialNumber";
    
    public static final String SIGNATURE_JSON             = "signature";
    
    public static final String SIGNER_CERTIFICATE_JSON    = "signerCertificate";
  
    public static final String SUBJECT_JSON               = "subject";
    
    public static final String TYPE_JSON                  = "type";

    public static final String PEM_URL_JSON               = "pemUrl";
    
    public static final String VALUE_JSON                 = "value";
    
    public static final String VERSION_JSON               = "version";
    
    public static final String X_JSON                     = "x";
    
    public static final String CERTIFICATE_PATH_JSON      = "certificatePath";
    
    public static final String Y_JSON                     = "y";
  
    SignatureAlgorithms algorithm;
    
    String algorithm_string;
    
    byte[] normalized_data;
    
    byte[] signature_value;
    
    X509Certificate[] certificate_path;

    PublicKey public_key;

    String key_id;

    Vector<JSONObjectReader> extensions;
    
    JSONSignatureDecoder (JSONObjectReader rd, JSONAlgorithmPreferences jose_settings) throws IOException
      {
        JSONObjectReader signature = rd.getObject (SIGNATURE_JSON);
        String version = signature.getStringConditional (VERSION_JSON, SIGNATURE_VERSION_ID);
        if (!version.equals (SIGNATURE_VERSION_ID))
          {
            throw new IOException ("Unknown \"" + SIGNATURE_JSON + "\" version: " + version);
          }
        algorithm_string = algorithmCheck (signature.getString (ALGORITHM_JSON), jose_settings);
        getKeyInfo (signature, jose_settings);
        if (signature.hasProperty (EXTENSIONS_JSON))
          {
            extensions = new Vector<JSONObjectReader> ();
            JSONArrayReader ar = signature.getArray (EXTENSIONS_JSON);
            do
              {
                extensions.add (ar.getObject ());
                // Minimal syntax check
                extensions.lastElement ().getString (TYPE_JSON);
              }
            while (ar.hasMore ());
          }
        signature_value = signature.getBinary (VALUE_JSON);

        ////////////////////////////////////////////////////////////////////////
        // Begin JCS normalization                                            // 1. Make a shallow copy of the signature object property list
        LinkedHashMap<String,JSONValue> saved_properties = new LinkedHashMap<String,JSONValue> (signature.root.properties);
        //                                                                    //
        signature.root.properties.remove (VALUE_JSON);                        // 2. Hide property for the serializer..
        //                                                                    // 3. Serialize ("JSON.stringify()")
        normalized_data = rd.serializeJSONObject (JSONOutputFormats.NORMALIZED);
        signature.root.properties.remove (EXTENSIONS_JSON);                   // Hide the optional extensions property for the check method..
        signature.checkForUnread ();                                          // Check for unread data - extensions
        signature.root.properties = saved_properties;                         // 4. Restore signature property list
        // End JCS normalization                                              //
        ////////////////////////////////////////////////////////////////////////

        switch (getSignatureType ())
          {
            case X509_CERTIFICATE:
              asymmetricSignatureVerification (certificate_path[0].getPublicKey ());
              break;

            case ASYMMETRIC_KEY:
              asymmetricSignatureVerification (public_key);
              break;

            default:
              algorithm = MACAlgorithms.getAlgorithmFromID (algorithm_string);
          }
      }

    public static String algorithmCheck (String identifier, JSONAlgorithmPreferences jose_settings) throws IOException
      {
        if (identifier.contains (":"))
          {
            if (jose_settings == JSONAlgorithmPreferences.JOSE)
              {
                throw new IOException("Invalid JOSE identifier: " + identifier);
              }
          }
        else
          {
            if (jose_settings == JSONAlgorithmPreferences.SKS)
              {
                throw new IOException("Invalid SKS identifier: " + identifier);
              }
          }
        return identifier;
      }

    void getKeyInfo (JSONObjectReader rd, JSONAlgorithmPreferences jose_settings) throws IOException
      {
        key_id = rd.getStringConditional (KEY_ID_JSON);
        if (rd.hasProperty (CERTIFICATE_PATH_JSON))
          {
            readCertificateData (rd);
          }
        else if (rd.hasProperty (PUBLIC_KEY_JSON))
          {
            public_key = getPublicKey (rd, jose_settings);
          }
        else if (rd.hasProperty (PEM_URL_JSON))
          {
            throw new IOException ("\"" + PEM_URL_JSON + "\" not yet implemented");
          }
        else
          {
            // Should be a symmetric key then.  Just to be nice we perform a sanity check...
            for (AsymSignatureAlgorithms alg : AsymSignatureAlgorithms.values ())
              {
                if (algorithm_string.equals (alg.getJOSEName ()) || algorithm_string.equals (alg.getURI ()))
                  {
                    throw new IOException ("Missing key information");
                  }
              }
          }
      }

    static BigInteger getCurvePoint (JSONObjectReader rd, String property, KeyAlgorithms ec) throws IOException
      {
        byte[] fixed_binary = rd.getBinary (property);
        if (fixed_binary.length != (ec.getPublicKeySizeInBits () + 7) / 8)
          {
            throw new IOException ("Public EC key parameter \"" + property + "\" is not nomalized");
          }
        return new BigInteger (1, fixed_binary);
      }

    static BigInteger getCryptoBinary (JSONObjectReader rd, String property) throws IOException
      {
        byte[] crypto_binary = rd.getBinary (property);
        if (crypto_binary[0] == 0x00)
          {
            throw new IOException ("Public RSA key parameter \"" + property + "\" contains leading zeroes");
          }
        return new BigInteger (1, crypto_binary);
      }

    static PublicKey getPublicKey (JSONObjectReader rd, JSONAlgorithmPreferences jose_settings) throws IOException
      {
        rd = rd.getObject (PUBLIC_KEY_JSON);
        PublicKey public_key = null;
        try
          {
            String type = rd.getString (TYPE_JSON);
            if (type.equals (RSA_PUBLIC_KEY))
              {
                public_key = KeyFactory.getInstance ("RSA").generatePublic (new RSAPublicKeySpec (getCryptoBinary (rd, N_JSON),
                                                                                                  getCryptoBinary (rd, E_JSON)));
              }
            else if (type.equals (EC_PUBLIC_KEY))
              {
                KeyAlgorithms ec = KeyAlgorithms.getKeyAlgorithmFromID (algorithmCheck (rd.getString (CURVE_JSON), jose_settings));
                if (!ec.isECKey ())
                  {
                    throw new IOException ("\"" + CURVE_JSON + "\" is not an EC type");
                  }
                ECPoint w = new ECPoint (getCurvePoint (rd, X_JSON, ec), getCurvePoint (rd, Y_JSON, ec));
                public_key = KeyFactory.getInstance ("EC").generatePublic (new ECPublicKeySpec (w, ec.getECParameterSpec ()));
              }
            else
              {
                throw new IOException ("Unrecognized \"" + PUBLIC_KEY_JSON + "\": " + type);
              }
            rd.checkForUnread ();
            return public_key;
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }

    static X509Certificate[] getCertificatePath (JSONObjectReader rd) throws IOException
      {
        X509Certificate last_certificate = null;
        Vector<X509Certificate> certificates = new Vector<X509Certificate> ();
        for (byte[] certificate_blob : rd.getBinaryArray (CERTIFICATE_PATH_JSON))
          {
            try
              {
                CertificateFactory cf = CertificateFactory.getInstance ("X.509");
                X509Certificate certificate = (X509Certificate)cf.generateCertificate (new ByteArrayInputStream (certificate_blob));
                certificates.add (pathCheck (last_certificate, last_certificate = certificate));
              }
            catch (GeneralSecurityException e)
              {
                throw new IOException (e);
              }
          }
        return certificates.toArray (new X509Certificate[0]);
      }

    void readCertificateData (JSONObjectReader rd) throws IOException
      {
        certificate_path = getCertificatePath (rd);
        if (rd.hasProperty (SIGNER_CERTIFICATE_JSON))
          {
            rd = rd.getObject (SIGNER_CERTIFICATE_JSON);
            String issuer = rd.getString (ISSUER_JSON);
            BigInteger serial_number = rd.getBigInteger (SERIAL_NUMBER_JSON);
            String subject = rd.getString (SUBJECT_JSON);
            X509Certificate signature_certificate = certificate_path[0];
            if (!signature_certificate.getIssuerX500Principal ().getName ().equals (issuer) ||
                !signature_certificate.getSerialNumber ().equals (serial_number) ||
                !signature_certificate.getSubjectX500Principal ().getName ().equals (subject))
              {
                throw new IOException ("\"" + SIGNER_CERTIFICATE_JSON + "\" doesn't match actual certificate");
              }
          }
      }

    void checkVerification (boolean success) throws IOException
      {
        if (!success)
          {
            String key;
            switch (getSignatureType ())
              {
                case X509_CERTIFICATE:
                  key = certificate_path[0].getPublicKey ().toString ();
                  break;
  
                case ASYMMETRIC_KEY:
                  key = public_key.toString ();
                  break;
  
                default:
                  key = getKeyId ();
               }
            throw new IOException ("Bad signature for key: " + key);
          }
      }

    void asymmetricSignatureVerification (PublicKey public_key) throws IOException
      {
        algorithm = AsymSignatureAlgorithms.getAlgorithmFromID (algorithm_string);
        if (((AsymSignatureAlgorithms)algorithm).isRSA () != public_key instanceof RSAPublicKey)
          {
            throw new IOException ("\"" + algorithm_string + "\" doesn't match key type: " + public_key.getAlgorithm ());
          }
        try
          {
            checkVerification (new SignatureWrapper ((AsymSignatureAlgorithms) algorithm, public_key)
                                   .update (normalized_data)
                                   .verify (signature_value));
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }

    public byte[] getValue ()
      {
        return signature_value;
      }

    public SignatureAlgorithms getAlgorithm ()
      {
        return algorithm;
      }

    public JSONObjectReader[] getExtensions ()
      {
        return extensions == null ? null : extensions.toArray (new JSONObjectReader[0]);
      }

    void checkRequest (JSONSignatureTypes signature_type) throws IOException
      {
        if (signature_type != getSignatureType ())
          {
            throw new IOException ("Request doesn't match received signature: " + getSignatureType ().toString ());
          }
      }

    public X509Certificate[] getCertificatePath () throws IOException
      {
        checkRequest (JSONSignatureTypes.X509_CERTIFICATE);
        return certificate_path;
      }

    public PublicKey getPublicKey () throws IOException
      {
        checkRequest (JSONSignatureTypes.ASYMMETRIC_KEY);
        return public_key;
      }

    public String getKeyId ()
      {
        return key_id;
      }

    public byte[] getNormalizedData ()
      {
        return normalized_data;
      }

    public JSONSignatureTypes getSignatureType ()
      {
        if (certificate_path != null)
          {
            return JSONSignatureTypes.X509_CERTIFICATE;
          }
        return public_key == null ? JSONSignatureTypes.SYMMETRIC_KEY : JSONSignatureTypes.ASYMMETRIC_KEY;
      }

    /**
     * Simplified verify that only checks that there are no "keyId" or "extensions", and that the signature type matches.
     * Note that asymmetric key signatures are always checked for technical correctness.
     * @param signatureType
     * @throws IOException
     */
    public void verify (JSONSignatureTypes signatureType) throws IOException
      {
        verify (new JSONVerifier (signatureType) 
          {
            private static final long serialVersionUID = 1L;
  
            @Override
            void verify (JSONSignatureDecoder signature_decoder) throws IOException
              {
              }
          });
      }

    public void verify (JSONVerifier verifier) throws IOException
      {
        checkRequest(verifier.signatureType);
        if (!verifier.extensionsAllowed && extensions != null)
          {
            throw new IOException ("\"" + EXTENSIONS_JSON + "\" requires enabling in the verifier");
          }
        if (!verifier.keyIdAllowed && key_id != null)
          {
            throw new IOException ("\"" + KEY_ID_JSON + "\" requires enabling in the verifier");
          }
        verifier.verify (this);
      }

    static X509Certificate pathCheck (X509Certificate child, X509Certificate parent) throws IOException
      {
        if (child != null)
          {
            String issuer = child.getIssuerX500Principal ().getName ();
            String subject = parent.getSubjectX500Principal ().getName ();
            if (!issuer.equals (subject))
              {
                throw new IOException ("Path issuer order error, '" + issuer + "' versus '" + subject + "'");
              }
            try
              {
                child.verify (parent.getPublicKey ());
              }
            catch (GeneralSecurityException e)
              {
                throw new IOException (e);
              }
          }
        return parent;
      }
  }
