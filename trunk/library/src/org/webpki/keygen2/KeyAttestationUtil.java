/*
 *  Copyright 2006-2010 WebPKI.org (http://webpki.org).
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
package org.webpki.keygen2;

import javax.crypto.Cipher;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;

import java.security.interfaces.RSAKey;

import org.webpki.util.ArrayUtil;


public class KeyAttestationUtil 
  {
    private KeyAttestationUtil () {}

    static final String SHA256             = "SHA-256";

    static final String UNFORMATTED_RSA    = "RSA/ECB/NoPadding";

    static final byte[] PS_END_SEQUENCE    = new byte[] {(byte)0x00, (byte)'D',  (byte)'I',  (byte)'A',  (byte)'S'};

    static final byte[] DIGEST_INFO_SHA256 = new byte[] {(byte)0x30, (byte)0x31, (byte)0x30, (byte)0x0d, (byte)0x06,
                                                         (byte)0x09, (byte)0x60, (byte)0x86, (byte)0x48, (byte)0x01,
                                                         (byte)0x65, (byte)0x03, (byte)0x04, (byte)0x02, (byte)0x01,
                                                         (byte)0x05, (byte)0x00, (byte)0x04, (byte)0x20};

    /**
     * Create a KA1 package for signing or verification.  The
     * package is identified by the URI {@link  KeyGen2URIs.ALGORITHMS#KEY_ATTESTATION_1 KEY_ATTESTATION_1};
     * @param attesting_key The attesting (certifying) private or public key.
     * @param attested_public_key The attested (certified) key.
     * @param exportable True if exportable.
     * @param key_usage Tells how the key can be used.
     * @param nonce A "nonce" element.
     * @param opt_archival_key An optional public key used for issuer-backup of private keys.
     * @return The KA1 package.
     */
    public static byte[] createKA1Package (RSAKey attesting_key,
                                           PublicKey attested_public_key,
                                           boolean exportable,
                                           KeyUsage key_usage,
                                           byte[] nonce,
                                           PublicKey opt_archival_key)
    throws GeneralSecurityException
      {
        ////////////////////////////////////////////////////////////////////////////////////////
        // To make it feasible securely distinguishing standard RSASSA-PKCS1.5 / SHA255       //
        // signatures from KA1 signatures the latter are packaged in a different way which    //
        // should create errors if processed by a crypto library that does not support KA1.   //
        // The following shows the packaging differences in detail.                           //
        //                                                                                    //
        // EMSA-PKCS1-v1_5: EM = 0x00 || 0x01 || PS || 0x00 || T                              //
        //                                                                                    //
        // EMDIAS-PKCS1:    EM = 0x00 || 0x01 || PS || 0x00 || 'D' || 'I' || 'A' || 'S' || T  //
        ////////////////////////////////////////////////////////////////////////////////////////
        byte[] modulus = attesting_key.getModulus ().toByteArray ();
        int k = modulus.length;
        if (modulus[0] == 0) k--;
        byte[] encoded_message = new byte [k];
        encoded_message[0] = (byte)0;
        encoded_message[1] = (byte)1;
        MessageDigest md = MessageDigest.getInstance (SHA256);
        md.update (nonce);
        md.update (exportable ? (byte)1 : (byte)0);
        md.update ((byte)key_usage.ordinal ());
        md.update (attested_public_key.getEncoded ());
        if (opt_archival_key != null)
          {
            md.update (opt_archival_key.getEncoded ());
          }
        byte[] hash = md.digest ();
        int i = k - 2 - PS_END_SEQUENCE.length - hash.length - DIGEST_INFO_SHA256.length;
        int j = 2;
        while (i-- > 0)
          {
            encoded_message[j++] = (byte)0xff;
          }
        i = 0;
        while (i < PS_END_SEQUENCE.length)
          {
            encoded_message[j++] = PS_END_SEQUENCE[i++];
          }
        System.arraycopy (DIGEST_INFO_SHA256, 0, encoded_message, j, DIGEST_INFO_SHA256.length);
        System.arraycopy (hash, 0, encoded_message, j + DIGEST_INFO_SHA256.length, hash.length);
        return encoded_message;
      }


    /**
     * Verify a KeyGen2 KA1 signature
     * @param attestation_signature The signature to be verified.
     * @param attesting_public_key The attesting (certifying) public key.
     * @param attested_public_key The attested (certified) key.
     * @param exportable True if exportable.
     * @param key_usage Tells how the key can be used.
     * @param nonce A "nonce" element.
     * @param opt_archival_key An optional public key used for issuer-backup of private keys.
     */
    public static void verifyKA1Signature (byte[] attestation_signature,
                                           PublicKey attesting_public_key,
                                           PublicKey attested_public_key,
                                           boolean exportable,
                                           KeyUsage key_usage,
                                           byte[] nonce,
                                           PublicKey opt_archival_key)
    throws GeneralSecurityException
      {
        Cipher cipher = Cipher.getInstance (UNFORMATTED_RSA);
        cipher.init (Cipher.DECRYPT_MODE, attesting_public_key);
        byte[] received_signature_package = cipher.doFinal (attestation_signature);
        if ((received_signature_package.length & 1) != 0)
          {
            // BouncyCastle fix
            received_signature_package = ArrayUtil.add (new byte[]{0}, received_signature_package);
          }
        byte[] reference_signature_package = createKA1Package ((RSAKey)attesting_public_key,
                                                                attested_public_key,
                                                                exportable,
                                                                key_usage,
                                                                nonce,
                                                                opt_archival_key);
        if (reference_signature_package.length != received_signature_package.length)
          {
            throw new GeneralSecurityException ("Signature package length error");
          }
        for (int i = 0; i < received_signature_package.length ; i++)
          {
            if (received_signature_package[i] != reference_signature_package[i])
              {
                // A more comprehensive diagnostic would be preferable...
                throw new GeneralSecurityException ("Signature package content error");
              }
          }
      }

  }
