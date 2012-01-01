/*
 *  Copyright 2006-2012 WebPKI.org (http://webpki.org).
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
package org.webpki.keygen2.test;

import javax.crypto.Cipher;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.security.interfaces.RSAKey;

/**
 * SKAE (Subject Key Attestation Evidence).  The following J2SE compatible code is meant illustrate
 * the use of SKAE signatures.
 */
public class skae
  {
    static final String SHA_1            = "SHA-1";

    static final String UNFORMATTED_RSA  = "RSA/ECB/NoPadding";

//    static final byte[] PS_END_SEQUENCE  = new byte[] {(byte)0x00};  // PKCS1.5 standard for SHA1
    static final byte[] PS_END_SEQUENCE  = new byte[] {(byte)0x00, (byte)'S',  (byte)'K',  (byte)'A',  (byte)'E'};

    static final byte[] DIGEST_INFO_SHA1 = new byte[] {(byte)0x30, (byte)0x21, (byte)0x30, (byte)0x09, (byte)0x06,
                                                       (byte)0x05, (byte)0x2b, (byte)0x0e, (byte)0x03, (byte)0x02,
                                                       (byte)0x1a, (byte)0x05, (byte)0x00, (byte)0x04, (byte)0x14};


    /**
     * Create an SKAE package for signing or verification
     * @param rsa_key The certifying (attesting) private or public key.
     * @param certified_public_key The certified (attested) key.
     * @param optional_nonce An optional "nonce" element.
     * @return The SKAE package.
     */
    public static byte[] createSKAEPackage (RSAKey rsa_key,
                                            PublicKey certified_public_key,
                                            byte[] optional_nonce)
    throws GeneralSecurityException
      {
        ////////////////////////////////////////////////////////////////////////////////////////
        // To make it feasible securely distinguishing standard RSASSA-PKCS1.5 signatures     //
        // from SKAE signatures the latter are packaged in a different way which should       //
        // create errors if processed by a crypto library that does not support SKAE.         //
        // The following shows the packaging differences in detail.                           //
        //                                                                                    //
        // EMSA-PKCS1-v1_5: EM = 0x00 || 0x01 || PS || 0x00 || T                              //
        //                                                                                    //
        // EM-PKCS1-SKAE:   EM = 0x00 || 0x01 || PS || 0x00 || 'S' || 'K' || 'A' || 'E' || T  //
        ////////////////////////////////////////////////////////////////////////////////////////
        byte[] modulus = rsa_key.getModulus ().toByteArray ();
        int k = modulus.length;
        if (modulus[0] == 0) k--;
        byte[] encoded_message = new byte [k];
        encoded_message[0] = (byte)0;
        encoded_message[1] = (byte)1;
        MessageDigest md = MessageDigest.getInstance (SHA_1);
        if (optional_nonce != null)
          {
            md.update (optional_nonce);
          }
        byte[] hash = md.digest (certified_public_key.getEncoded ());
        int i = k - 2 - PS_END_SEQUENCE.length - hash.length - DIGEST_INFO_SHA1.length;
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
        System.arraycopy (DIGEST_INFO_SHA1, 0, encoded_message, j, DIGEST_INFO_SHA1.length);
        System.arraycopy (hash, 0, encoded_message, j + DIGEST_INFO_SHA1.length, hash.length);
        return encoded_message;
      }


    /**
     * Verify an SKAE signature
     * @param skae_signature The signature to be verified.
     * @param certifying_public_key The certifying (attesting) public key.
     * @param certified_public_key The certified (attested) key.
     * @param optional_nonce An optional "nonce" element.
     * @throws GeneralSecurityException if the signature is invalid or indata is incorrect.
     */
    public static void verifySKAESignature (byte[] skae_signature,
                                            PublicKey certifying_public_key,
                                            PublicKey certified_public_key,
                                            byte[] optional_nonce)
    throws GeneralSecurityException
      {
        Cipher cipher = Cipher.getInstance (UNFORMATTED_RSA);
        cipher.init (Cipher.ENCRYPT_MODE, certifying_public_key);
        byte[] received_signature_package = cipher.doFinal (skae_signature);
        byte[] reference_signature_package = createSKAEPackage ((RSAKey)certifying_public_key,
                                                                certified_public_key,
                                                                optional_nonce);
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


    public static class GeneratedKey
      {
        PublicKey certified_public_key;
        PublicKey certifying_public_key;
        byte[] skae_signature;
      }


    public static class SecurityElement
      {
        PublicKey certifying_public_key;

        private PrivateKey certifying_private_key;

        public SecurityElement () throws GeneralSecurityException
          {
            /////////////////////////////////////////////////////////////////
            // Key-certifying keys are typically created once during       //
            // device manufacturing. The public key part is also most      //
            // likely distributed in an X.509 certificate issued by a CA   //
            // setup specifically for certifying crypto hardware.          //
            // That is, the following lines are just for showing the       //
            // cryptography, without any infrastructural considerations.   //
            /////////////////////////////////////////////////////////////////
            KeyPairGenerator certifier = KeyPairGenerator.getInstance ("RSA");
            certifier.initialize (2048);
            KeyPair certifying_key_pair = certifier.generateKeyPair ();
            certifying_public_key = certifying_key_pair.getPublic ();
            certifying_private_key = certifying_key_pair.getPrivate ();
          }


        /**
         * Create a certified key-pair.
         * @param size The size of the RSA key.
         * @param optional_nonce An optional "nonce" element.
         * @return A container with a generated public key and attesting signature.
         */
        public GeneratedKey generateCertifiedKeyPair (int size, byte[] optional_nonce)
        throws GeneralSecurityException
          {
            /////////////////////////////////////////////////////////////////
            // Generate a new key-pair in the Security Element.  The       //
            // private key is presumably stored securely in hardware and   //
            // never leave its container, unless "sealed" by the latter.   //
            /////////////////////////////////////////////////////////////////
            KeyPairGenerator kpg = KeyPairGenerator.getInstance ("RSA");
            kpg.initialize (size);
            KeyPair new_key_pair = kpg.generateKeyPair ();

            /////////////////////////////////////////////////////////////////
            // Now let the Security Element attest that the new key-pair   //
            // actually was created inside of the Security Element.        //
            //                                                             //
            // NOTE 1: The Security Element MUST NOT expose an API that    //
            // allows unformatted RSA decryptions like used below to be    //
            // performed with the key-certifying key, otherwise "malware"  //
            // could easily create fake attestations for any externally    //
            // supplied key-pair!                                          //
            //                                                             //
            // NOTE 2: Due to the fact that SKAE signatures are only to    //
            // be created for generated keys, the key-certifying key MAY   //
            // also be used for creating ordinary PKCS1.5 signatures for   //
            // things like authentications and securing message integrity  //
            /////////////////////////////////////////////////////////////////
            GeneratedKey gk = new GeneratedKey ();
            gk.certified_public_key = new_key_pair.getPublic ();
            Cipher cipher = Cipher.getInstance (UNFORMATTED_RSA);
            cipher.init (Cipher.DECRYPT_MODE, certifying_private_key);
            gk.skae_signature = cipher.doFinal (createSKAEPackage ((RSAKey)certifying_private_key,
                                                                   gk.certified_public_key,
                                                                   optional_nonce));
            gk.certifying_public_key = certifying_public_key;
            return gk; 
          }
      }


    public static void main (String[] args) throws Exception
      {

        /////////////////////////////////////////////////////////////////
        //                                                             //
        //                     CLIENT Operations                       //
        //                                                             //
        // It is assumed that the critical operations are performed    //
        // inside of the Security Element, otherwise attestations      //
        // would not be more trustworthy than the environment where    //
        // the Security Element is actually running in!                //
        /////////////////////////////////////////////////////////////////
        SecurityElement se = new SecurityElement ();

        /////////////////////////////////////////////////////////////////
        // Generate a new key-pair in the Security Element.  The       //
        // private key is presumably stored securely in hardware and   //
        // never leave its container, unless "sealed" by the latter.   //
        /////////////////////////////////////////////////////////////////
        byte[] nonce = null; // Didn't use a nonce in the sample run
        GeneratedKey gk = se.generateCertifiedKeyPair (1024, nonce);

        /////////////////////////////////////////////////////////////////
        //                                                             //
        //                     VERIFIER Operations                     //
        //                                                             //
        // The certifying public key is supposed to be transferred to  //
        // the verifier by some kind of protocol, together with the    //
        // SKAE-signature, certified public key, and the optional      //
        // nonce.  A nonce (if used) would preferably be created by    //
        // the verifier during an earlier (not shown) protocol phase.  //
        /////////////////////////////////////////////////////////////////
        verifySKAESignature (gk.skae_signature,
                             gk.certifying_public_key,
                             gk.certified_public_key,
                             nonce);

        System.out.println ("The SKAE signature appears to be valid!");
/*
        // PKCS1.5 test code
        java.security.Signature signature = java.security.Signature.getInstance ("SHA1withRSA");
        signature.initVerify (gk.certifying_public_key);
        if (nonce != null)
          {
            signature.update (nonce);
          }
        signature.update (gk.certified_public_key.getEncoded ());
        if (!signature.verify (gk.skae_signature))
          {
            throw new GeneralSecurityException ("Failed to VERIFY");
          }
*/
      }

  }
