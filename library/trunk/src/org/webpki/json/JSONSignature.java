/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
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
import java.io.Serializable;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

/**
 * Common class for JSON signatures.
 */
class JSONSignature implements Serializable
  {
    private static final long serialVersionUID = 1L;

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

    public static final String SIGNATURE_VERSION_ID       = "http://xmlns.webpki.org/jcs/v1";
    
    public static final String SIGNATURE_JSON             = "Signature";

    public static final String VERSION_JSON               = "Version";

    public static final String ALGORITHM_JSON             = "Algorithm";

    public static final String SIGNATURE_VALUE_JSON       = "SignatureValue";

    public static final String KEY_INFO_JSON              = "KeyInfo";

    public static final String URL_JSON                   = "URL";

    public static final String X509_CERTIFICATE_PATH_JSON = "X509CertificatePath";

    public static final String SIGNATURE_CERTIFICATE_JSON = "SignatureCertificate";

    public static final String ISSUER_JSON                = "Issuer";

    public static final String SERIAL_NUMBER_JSON         = "SerialNumber";

    public static final String SUBJECT_JSON               = "Subject";

    public static final String PUBLIC_KEY_JSON            = "PublicKey";

    public static final String RSA_JSON                   = "RSA";

    public static final String MODULUS_JSON               = "Modulus";
 
    public static final String EXPONENT_JSON              = "Exponent";

    public static final String EC_JSON                    = "EC";

    public static final String NAMED_CURVE_JSON           = "NamedCurve";

    public static final String X_JSON                     = "X";

    public static final String Y_JSON                     = "Y";

    public static final String KEY_ID_JSON                = "KeyID";
  }
