/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
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
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Vector;

import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.KeyAlgorithms;

/**
 * Decoder for JCS signatures.
 */
public class JSONSignatureDecoder implements Serializable
  {
    private static final long serialVersionUID = 1L;

    public static final String ALGORITHM_JSON             = "Algorithm";
  
    public static final String EC_JSON                    = "EC";
    
    public static final String EXPONENT_JSON              = "Exponent";
    
    public static final String EXTENSIONS_JSON            = "Extensions";

    public static final String ISSUER_JSON                = "Issuer";
    
    public static final String KEY_ID_JSON                = "KeyID";

    public static final String KEY_INFO_JSON              = "KeyInfo";
  
    public static final String MODULUS_JSON               = "Modulus";
    
    public static final String NAMED_CURVE_JSON           = "NamedCurve";
    
    public static final String PUBLIC_KEY_JSON            = "PublicKey";
    
    public static final String RSA_JSON                   = "RSA";
  
    public static final String SERIAL_NUMBER_JSON         = "SerialNumber";
    
    public static final String SIGNATURE_JSON             = "Signature";
    
    public static final String SIGNATURE_CERTIFICATE_JSON = "SignatureCertificate";
  
    public static final String SIGNATURE_VALUE_JSON       = "SignatureValue";
    
    public static final String SIGNATURE_VERSION_ID       = "http://xmlns.webpki.org/jcs/v1";
    
    public static final String SUBJECT_JSON               = "Subject";
    
    public static final String TYPE_JSON                  = "Type";

    public static final String URL_JSON                   = "URL";
    
    public static final String VERSION_JSON               = "Version";
    
    public static final String X_JSON                     = "X";
    
    public static final String X509_CERTIFICATE_PATH_JSON = "X509CertificatePath";
    
    public static final String Y_JSON                     = "Y";
  
    SignatureAlgorithms algorithm;
    
    String algorithm_string;
    
    byte[] normalized_data;
    
    byte[] signature_value;
    
    X509Certificate[] certificate_path;

    PublicKey public_key;

    String key_id;

    Vector<JSONObjectReader> extensions;
    
    JSONSignatureDecoder (JSONObjectReader rd) throws IOException
      {
        JSONObjectReader signature = rd.getObject (SIGNATURE_JSON);
        String version = signature.getStringConditional (VERSION_JSON, SIGNATURE_VERSION_ID);
        if (!version.equals (SIGNATURE_VERSION_ID))
          {
            throw new IOException ("Unknown \"" + SIGNATURE_JSON + "\" version: " + version);
          }
        algorithm_string = signature.getString (ALGORITHM_JSON);
        getKeyInfo (signature.getObject (KEY_INFO_JSON));
        if (signature.hasProperty (EXTENSIONS_JSON))
          {
            extensions = new Vector<JSONObjectReader> ();
            JSONArrayReader ar = signature.getArray (EXTENSIONS_JSON);
            do
              {
                extensions.add (ar.getObject ());
                if (!extensions.lastElement ().hasProperty (TYPE_JSON))
                  {
                    throw new IOException ("An \"" + EXTENSIONS_JSON + "\" object lack a \"" + TYPE_JSON + "\" property");
                  }
              }
            while (ar.hasMore ());
          }
        signature_value = signature.getBinary (SIGNATURE_VALUE_JSON);
        JSONValue save = signature.root.properties.get (SIGNATURE_VALUE_JSON);
        signature.root.properties.remove (SIGNATURE_VALUE_JSON);
        normalized_data = JSONObjectWriter.getNormalizedSubset (rd.root);
        signature.root.properties.put (SIGNATURE_VALUE_JSON, save);
        switch (getSignatureType ())
          {
            case X509_CERTIFICATE:
              asymmetricSignatureVerification (certificate_path[0].getPublicKey ());
              break;

            case ASYMMETRIC_KEY:
              asymmetricSignatureVerification (public_key);
              break;

            default:
              algorithm = MACAlgorithms.getAlgorithmFromURI (algorithm_string);
          }
      }

    void getKeyInfo (JSONObjectReader rd) throws IOException
      {
        if (rd.hasProperty (X509_CERTIFICATE_PATH_JSON))
          {
            readX509CertificateEntry (rd);
          }
        else if (rd.hasProperty (PUBLIC_KEY_JSON))
          {
            public_key = getPublicKey (rd);
          }
        else if (rd.hasProperty (KEY_ID_JSON))
          {
            key_id = rd.getString (KEY_ID_JSON);
          }
        else if (rd.hasProperty (URL_JSON))
          {
            throw new IOException ("\"" + URL_JSON + "\" not yet implemented");
          }
        else
          {
            throw new IOException ("Undecodable \"" + KEY_INFO_JSON + "\" object");
          }
      }

    static BigInteger getFixedBinary (JSONObjectReader rd, String property, KeyAlgorithms ec) throws IOException
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

    static PublicKey getPublicKey (JSONObjectReader rd) throws IOException
      {
        rd = rd.getObject (PUBLIC_KEY_JSON);
        try
          {
            if (rd.hasProperty (RSA_JSON))
              {
                rd = rd.getObject (RSA_JSON);
                return KeyFactory.getInstance ("RSA").generatePublic (new RSAPublicKeySpec (getCryptoBinary (rd, MODULUS_JSON),
                                                                                            getCryptoBinary (rd, EXPONENT_JSON)));
              }
            rd = rd.getObject (EC_JSON);
            String curve_name = rd.getString (NAMED_CURVE_JSON);
            KeyAlgorithms ec = curve_name.startsWith (KeyAlgorithms.XML_DSIG_CURVE_PREFIX) ?
                                           getXMLDSigNamedCurve (curve_name) : KeyAlgorithms.getKeyAlgorithmFromURI (curve_name);
            ECPoint w = new ECPoint (getFixedBinary (rd, X_JSON, ec), getFixedBinary (rd, Y_JSON, ec));
            return KeyFactory.getInstance ("EC").generatePublic (new ECPublicKeySpec (w, ec.getECParameterSpec ()));
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }

    static KeyAlgorithms getXMLDSigNamedCurve (String xml_dsig_curve_name) throws IOException
      {
        String oid = xml_dsig_curve_name.substring (KeyAlgorithms.XML_DSIG_CURVE_PREFIX.length ());
        for (KeyAlgorithms key_alg : KeyAlgorithms.values ())
          {
            if (oid.equals (key_alg.getECDomainOID ()))
              {
                return key_alg;
              }
          }
        throw new IOException ("Unknown \"" + NAMED_CURVE_JSON + "\": " + xml_dsig_curve_name);
      }

    static X509Certificate[] getX509CertificatePath (JSONObjectReader rd) throws IOException
      {
        X509Certificate last_certificate = null;
        Vector<X509Certificate> certificates = new Vector<X509Certificate> ();
        for (byte[] certificate_blob : rd.getBinaryArray (X509_CERTIFICATE_PATH_JSON))
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

    void readX509CertificateEntry (JSONObjectReader rd) throws IOException
      {
        certificate_path = getX509CertificatePath (rd);
        if (rd.hasProperty (SIGNATURE_CERTIFICATE_JSON))
          {
            rd = rd.getObject (SIGNATURE_CERTIFICATE_JSON);
            String issuer = rd.getString (ISSUER_JSON);
            BigInteger serial_number = rd.getBigInteger (SERIAL_NUMBER_JSON);
            String subject = rd.getString (SUBJECT_JSON);
            X509Certificate signature_certificate = certificate_path[0];
            if (!signature_certificate.getIssuerX500Principal ().getName ().equals (issuer) ||
                !signature_certificate.getSerialNumber ().equals (serial_number) ||
                !signature_certificate.getSubjectX500Principal ().getName ().equals (subject))
              {
                throw new IOException ("\"" + SIGNATURE_CERTIFICATE_JSON + "\" doesn't match actual certificate");
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
                  key = getKeyID ();
               }
            throw new IOException ("Bad signature for key: " + key);
          }
      }

    void asymmetricSignatureVerification (PublicKey public_key) throws IOException
      {
        algorithm = AsymSignatureAlgorithms.getAlgorithmFromURI (algorithm_string);
        try
          {
            Signature sig = Signature.getInstance (algorithm.getJCEName ());
            sig.initVerify (public_key);
            sig.update (normalized_data);
            checkVerification (sig.verify (signature_value));
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }

    public byte[] getSignatureValue ()
      {
        return signature_value;
      }

    public SignatureAlgorithms getSignatureAlgorithm ()
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

    public X509Certificate[] getX509CertificatePath () throws IOException
      {
        checkRequest (JSONSignatureTypes.X509_CERTIFICATE);
        return certificate_path;
      }

    public PublicKey getPublicKey () throws IOException
      {
        checkRequest (JSONSignatureTypes.ASYMMETRIC_KEY);
        return public_key;
      }

    public String getKeyID () throws IOException
      {
        checkRequest (JSONSignatureTypes.SYMMETRIC_KEY);
        return key_id;
      }

    public JSONSignatureTypes getSignatureType ()
      {
        if (certificate_path != null)
          {
            return JSONSignatureTypes.X509_CERTIFICATE;
          }
        return public_key == null ? JSONSignatureTypes.SYMMETRIC_KEY : JSONSignatureTypes.ASYMMETRIC_KEY;
      }

    public void verify (JSONVerifier verifier) throws IOException
      {
        if (verifier.getVerifierType () != getSignatureType ())
          {
            throw new IOException ("Verifier type doesn't match the received signature");
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
