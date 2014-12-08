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
package org.webpki.webapps.wcpppaymentdemo;

import java.io.IOException;

import java.security.PublicKey;
import java.security.SecureRandom;

import java.security.cert.X509Certificate;

import java.util.Date;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.KeyStoreSigner;
import org.webpki.crypto.KeyStoreVerifier;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.VerifierInterface;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONX509Signer;
import org.webpki.json.JSONX509Verifier;

import org.webpki.util.ArrayUtil;

import org.webpki.webutil.ServletUtil;

public class PaymentProviderServlet extends HttpServlet implements BaseProperties
  {
    private static final long serialVersionUID = 1L;

    static Logger logger = Logger.getLogger (PaymentProviderServlet.class.getName ());
    
    static int transaction_id = 164006;
    
    private X509Certificate verifyMerchantSignature (JSONObjectReader signed_object) throws IOException
      {
        VerifierInterface verifier = new KeyStoreVerifier (PaymentDemoService.merchant_root);
        signed_object.getSignature ().verify (new JSONX509Verifier (verifier));
        return verifier.getSignerCertificatePath ()[0];
      }

    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        JSONObjectWriter result = Messages.createBaseMessage (Messages.TRANSACTION_RESPONSE);
        try
          {
            JSONObjectReader trans_req = Messages.parseBaseMessage (Messages.TRANSACTION_REQUEST,
                                                                    JSONParser.parse (ServletUtil.getData (request)));
            String request_transaction_id = trans_req.getString (TRANSACTION_ID_JSON);
            String client_ip_address = trans_req.getString (CLIENT_IP_ADDRESS_JSON);
            trans_req.getDateTime (DATE_TIME_JSON);  // We have no DB...
            logger.info ("Transaction Request [" + client_ip_address + "," + request_transaction_id + "]:\n" +
                         new String (new JSONObjectWriter (trans_req).serializeJSONObject (JSONOutputFormats.PRETTY_PRINT), "UTF-8"));
            JSONObjectReader encrypted_auth_data = trans_req.getObject (AUTH_DATA_JSON).getObject (ENCRYPTED_DATA_JSON);

            // "working" simulation - the prototype is simply too quick :-)
            Thread.sleep (1000);

            JSONObjectReader auth_data = null;
            if (encrypted_auth_data.hasProperty (ALGORITHM_JSON))
              {
                SymEncryptionAlgorithms sym_alg = SymEncryptionAlgorithms.getAlgorithmFromID (encrypted_auth_data.getString (ALGORITHM_JSON));
                if (sym_alg != SymEncryptionAlgorithms.AES256_CBC)
                  {
                    throw new IOException ("Unexpected \"" + ALGORITHM_JSON + "\": " + sym_alg.getURI ());
                  }
                JSONObjectReader encrypted_key = encrypted_auth_data.getObject (ENCRYPTED_KEY_JSON);
                String key_encryption_algorithm = encrypted_key.getString (ALGORITHM_JSON);
                byte[] raw_aes_key = null;
                if (key_encryption_algorithm.equals (AsymEncryptionAlgorithms.RSA_OAEP_SHA256_MGF1P.getJOSEName ()))
                  {
                    PublicKey received_public_key = encrypted_key.getPublicKey ();
                    if (!ArrayUtil.compare (PaymentDemoService.bank_encryption_key.getEncoded (), received_public_key.getEncoded ()))
                      {
                        throw new IOException ("Unexpected encryption key:\n" + received_public_key.toString ());
                      }
                    Cipher cipher = Cipher.getInstance (AsymEncryptionAlgorithms.RSA_OAEP_SHA256_MGF1P.getJCEName ());
                    cipher.init (Cipher.DECRYPT_MODE, PaymentDemoService.bank_decryption_key.getKey ("mykey", PaymentDemoService.key_password.toCharArray ()));
                    raw_aes_key = cipher.doFinal (encrypted_key.getBinary (CIPHER_TEXT_JSON));
                  }
                else
                  {
                    if (!key_encryption_algorithm.equals (ECDH_ALGORITHM_URI))
                      {
                        throw new IOException ("Unexpected \"" + ALGORITHM_JSON + "\": " + key_encryption_algorithm);
                      }
                    PublicKey received_payment_provider_key = encrypted_key.getObject (PAYMENT_PROVIDER_KEY_JSON).getPublicKey ();
                    if (!ArrayUtil.compare (PaymentDemoService.bank_encryption_key.getEncoded (), received_payment_provider_key.getEncoded ()))
                      {
                        throw new IOException ("Unexpected encryption key:\n" + received_payment_provider_key.toString ());
                      }
                    PublicKey ephemeral_sender_key = encrypted_key.getObject (EPHEMERAL_CLIENT_KEY_JSON).getPublicKey ();
                    KeyAgreement key_agreement = KeyAgreement.getInstance ("ECDH");
                    key_agreement.init (PaymentDemoService.bank_decryption_key.getKey ("mykey", PaymentDemoService.key_password.toCharArray ()));
                    key_agreement.doPhase (ephemeral_sender_key, true);
                    byte[] Z = key_agreement.generateSecret ();
                    JSONObjectReader concat = encrypted_key.getObject (KEY_DERIVATION_METHOD_JSON);
                    if (!concat.getString (ALGORITHM_JSON).equals (CONCAT_ALGORITHM_URI))
                      {
                        throw new IOException ("Unexpected \"" + ALGORITHM_JSON + "\": " + concat.getString (ALGORITHM_JSON));
                      }
                    HashAlgorithms hash_algorithm = HashAlgorithms.getAlgorithmFromID (concat.getString (HASH_ALGORITHM_JSON));
                    byte[] algorithm_id = concat.getBinary (ALGORITHM_ID_JSON);
                    byte[] party_u_info = concat.getBinary (PARTY_U_INFO_JSON);
                    byte[] party_v_info = concat.getBinary (PARTY_V_INFO_JSON);
                    raw_aes_key = Z;  // For now...since WebCrypto does not (yet) implement CONCAT
                  }
                Cipher cipher = Cipher.getInstance (sym_alg.getJCEName ());
                SecretKeySpec sk = new SecretKeySpec (raw_aes_key, "AES");
                cipher.init (Cipher.DECRYPT_MODE, sk, new IvParameterSpec (encrypted_auth_data.getBinary (IV_JSON)));
                auth_data = JSONParser.parse (cipher.doFinal (encrypted_auth_data.getBinary (CIPHER_TEXT_JSON)));
                logger.info ("Decrypted \"" + AUTH_DATA_JSON + "\":\n" + new String (new JSONObjectWriter (auth_data).serializeJSONObject (JSONOutputFormats.PRETTY_PRINT), "UTF-8"));
                VerifierInterface verifier = new KeyStoreVerifier (PaymentDemoService.client_root);
                auth_data.getSignature ().verify (new JSONX509Verifier (verifier));
              }
            else
              {
                auth_data = JSONParser.parse (encrypted_auth_data.getBinary (CIPHER_TEXT_JSON));
              }
            auth_data.getString (DOMAIN_NAME_JSON);  // We have no DB...
            auth_data.getDateTime (DATE_TIME_JSON);  //     "-"
            JSONObjectReader payee = auth_data.getObject (PAYMENT_REQUEST_JSON);
            PaymentRequest.parseJSONData (payee);  // No DB to store in...
            JSONObjectReader request_hash = trans_req.getObject(REQUEST_HASH_JSON);
            HashAlgorithms hash_alg = HashAlgorithms.getAlgorithmFromID (request_hash.getString (ALGORITHM_JSON)); 
            if (hash_alg != HashAlgorithms.SHA256)
              {
                throw new IOException ("Unexpected hash algorithm: " + hash_alg.getURI ());
              }
            if (!ArrayUtil.compare (request_hash.getBinary (VALUE_JSON),
                                    HashAlgorithms.SHA256.digest (new JSONObjectWriter (payee).serializeJSONObject (JSONOutputFormats.NORMALIZED))))
              {
                throw new IOException ("\"" + REQUEST_HASH_JSON + "\" mismatch");
              }
            if (!verifyMerchantSignature (payee).equals (verifyMerchantSignature (trans_req)))
              {
                throw new IOException ("Non-matching outer/inner signer");
              }
            result.setObject (HTML.PAYMENT_REQUEST_JSON, payee);
            String pan = auth_data.getString (PAN_JSON);
            StringBuffer payee_pan = new StringBuffer ();
            for (int i = 0; i < pan.length (); i++)
              {
                if (i != 0 && ((i % 4) == 0))
                  {
                    payee_pan.append (' ');
                  }
                payee_pan.append (i < 12 ? '*' : pan.charAt (i));
              }
            result.setString (CARD_TYPE_JSON, auth_data.getString (CARD_TYPE_JSON));
            byte[] payment_token = new byte[32];  // There must surely be a better way
            new SecureRandom ().nextBytes (payment_token);
            result.setBinary (PAYMENT_TOKEN_JSON, payment_token);
            result.setString (REFERENCE_PAN_JSON, payee_pan.toString ());
            result.setString (TRANSACTION_ID_JSON, "#" + transaction_id++);
            result.setDateTime (DATE_TIME_JSON, new Date (), true);
            KeyStoreSigner signer = new KeyStoreSigner (PaymentDemoService.bank_eecert_key, null);
            signer.setExtendedCertPath (true);
            signer.setKey (null, PaymentDemoService.key_password);
            result.setSignature (new JSONX509Signer (signer).setSignatureCertificateAttributes (true));
            auth_data.checkForUnread ();
            trans_req.checkForUnread ();
          }
        catch (Exception e)
          {
            result = Messages.createBaseMessage (Messages.TRANSACTION_RESPONSE);
            result.setString (ERROR_JSON, e.getMessage ());
            logger.log (Level.SEVERE, e.getMessage ());
          }
        response.setContentType ("application/json; charset=utf-8");
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", 0);
        response.getOutputStream ().write (result.serializeJSONObject (JSONOutputFormats.NORMALIZED));
      }
  }
