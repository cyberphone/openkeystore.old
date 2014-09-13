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
package org.webpki.json.test;

import java.io.IOException;

import java.math.BigDecimal;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import java.util.Date;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyStoreSigner;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.SymKeySignerInterface;
import org.webpki.crypto.SymKeyVerifierInterface;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONSymKeySigner;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONX509Signer;

import org.webpki.util.ArrayUtil;

/**
 * Simple signature test generator
 */
public class Sign
  {
    static enum ACTION {SYM, EC, RSA, X509};
    
    static final String ID = "ID";
    
    public static final String SYMMETRIC_KEY_NAME = "mykey";
    
    public static final byte[] SYMMETRIC_KEY = {(byte)0xF4, (byte)0xC7, (byte)0x4F, (byte)0x33, (byte)0x98, (byte)0xC4, (byte)0x9C, (byte)0xF4,
                                                (byte)0x6D, (byte)0x93, (byte)0xEC, (byte)0x98, (byte)0x18, (byte)0x83, (byte)0x26, (byte)0x61,
                                                (byte)0xA4, (byte)0x0B, (byte)0xAE, (byte)0x4D, (byte)0x20, (byte)0x4D, (byte)0x75, (byte)0x50,
                                                (byte)0x36, (byte)0x14, (byte)0x10, (byte)0x20, (byte)0x74, (byte)0x34, (byte)0x69, (byte)0x09};

    public static class SymmetricOperations implements SymKeySignerInterface, SymKeyVerifierInterface
      {
        @Override
        public byte[] signData (byte[] data) throws IOException
          {
            return getMACAlgorithm ().digest (SYMMETRIC_KEY, data);
          }
  
        @Override
        public MACAlgorithms getMACAlgorithm () throws IOException
          {
            return MACAlgorithms.HMAC_SHA256;
          }

        @Override
        public boolean verifyData (byte[] data, byte[] digest, MACAlgorithms algorithm, String key_id) throws IOException
          {
            if (key_id.equals (SYMMETRIC_KEY_NAME))
              {
                return ArrayUtil.compare (digest, getMACAlgorithm ().digest (SYMMETRIC_KEY, data));
              }
            throw new IOException ("Unknown key id: " + key_id);
          }
      }
    
    static class AsymSigner implements AsymKeySignerInterface
      {
        PrivateKey priv_key;
        PublicKey pub_key;
  
        AsymSigner (PrivateKey priv_key, PublicKey pub_key)
          {
            this.priv_key = priv_key;
            this.pub_key = pub_key;
          }
  
        public byte[] signData (byte[] data, AsymSignatureAlgorithms sign_alg) throws IOException
          {
            try
              {
                Signature s = Signature.getInstance (sign_alg.getJCEName ());
                s.initSign (priv_key);
                s.update (data);
                return s.sign ();
              }
            catch (GeneralSecurityException e)
              {
                throw new IOException (e);
              }
          }
  
        public PublicKey getPublicKey () throws IOException
          {
            return pub_key;
          }
      }

    class OrderLine
      {
        public OrderLine (int units, String sku, String description, BigDecimal unit_price, JSONArrayWriter array_writer) throws IOException
          {
            JSONObjectWriter wr = array_writer.setObject ();
            wr.setInt ("Units", units);
            wr.setString ("Description", description);
            wr.setString ("SKU", sku);
            wr.setBigDecimal ("UnitPrice", unit_price);
          }
      }
    
    class SO
      {
        SO (int value, String instance, JSONArrayWriter array_writer) throws IOException
          {
            JSONObjectWriter wr = array_writer.setObject ();
            wr.setString (ID, instance);
            wr.setInt ("Data", value);
            createSymmetricKeySignature (wr);
          }
      }

    ACTION action;
    public Sign (ACTION action, boolean multiple)
      {
        this.action = action;
        this.multiple = multiple;
      }
    
    boolean multiple;

    public static void createX509Signature (JSONObjectWriter wr) throws IOException
      {
        KeyStoreSigner signer = new KeyStoreSigner (DemoKeyStore.getExampleDotComKeyStore (), null);
        signer.setExtendedCertPath (true);
        signer.setKey (null, DemoKeyStore.getSignerPassword ());
        wr.setSignature (new JSONX509Signer (signer).setSignatureCertificateAttributes (true));
      }
    
    public static void createAsymmetricKeySignature (JSONObjectWriter wr, boolean rsa) throws IOException
      {
        try
          {
            KeyStore ks = rsa ? DemoKeyStore.getMybankDotComKeyStore () : DemoKeyStore.getECDSAStore ();
            PrivateKey private_key = (PrivateKey)ks.getKey ("mykey", DemoKeyStore.getSignerPassword ().toCharArray ());
            PublicKey public_key = ks.getCertificate ("mykey").getPublicKey ();
            wr.setSignature (new JSONAsymKeySigner (new AsymSigner (private_key, public_key)));
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }
    
    public static void createSymmetricKeySignature (JSONObjectWriter wr) throws IOException
      {
        wr.setSignature (new JSONSymKeySigner (new SymmetricOperations ()).setKeyID (SYMMETRIC_KEY_NAME));
      }
    
    
    public void writeJSONData (JSONObjectWriter wr) throws IOException
      {
        wr.setDateTime ("Now", new Date (), false);
        JSONObjectWriter payment_request = wr.setObject ("PaymentRequest");
        payment_request.setString ("Currency", "USD");
        payment_request.setBigDecimal ("VAT", new BigDecimal ("1.45"));
        JSONArrayWriter array_writer = payment_request.setArray ("Specification");
        new OrderLine (3, "TR-46565666", "USB cable", new BigDecimal ("4.50"), array_writer);
        new OrderLine (1, "JK-56566655", "4G Router", new BigDecimal ("39.99"), array_writer);
        if (multiple)
          {
            array_writer = wr.setArray ("SignedObjects").setArray ();
            new SO (35, "this", array_writer);
            new SO (-90, "that", array_writer);
          }
        wr.setString ("EscapeMe", "\u000F\nA'\u0042\\\"/" );
        if (action == ACTION.X509)
          {
            createX509Signature (wr);
          }
        else if (action == ACTION.SYM)
          {
            createSymmetricKeySignature (wr);
          }
        else
          {
            createAsymmetricKeySignature (wr, action == ACTION.RSA);
          }
      }
    
    static void show ()
      {
        System.out.println (ACTION.SYM.toString () + "|" + ACTION.EC.toString () + "|" + ACTION.RSA.toString () + "|" + ACTION.X509.toString () + " multiple(true|false) output-file\n");
        System.exit (0);
      }

    static StringBuffer info_string;
    
    static int info_lengthp2;
    
    static void printHeader ()
      {
        for (int i = 0; i < info_lengthp2; i++)
          {
            info_string.append ('=');
          }
        info_string.append ('\n');
      }
    
    static void printInfo (String info)
      {
        info_string = new StringBuffer ("\n\n");
        info_lengthp2 = info.length () + 4;
        printHeader ();
        info_string.append ("= ").append (info).append (" =\n");
        printHeader ();
        System.out.println (info_string.toString ());
      }

    public static void main (String[] argc)
      {
        if (argc.length != 3)
          {
            show ();
          }
        for (ACTION action : ACTION.values ())
          {
            if (action.toString ().equalsIgnoreCase (argc[0]))
              {
                try
                  {
                    CustomCryptoProvider.conditionalLoad ();
                    JSONObjectWriter wr = new JSONObjectWriter ();
                    new Sign (action, new Boolean (argc[1])).writeJSONData (wr);
                    ArrayUtil.writeFile (argc[2], wr.serializeJSONObject (JSONOutputFormats.PRETTY_PRINT));
                  }
                catch (Exception e)
                  {
                    e.printStackTrace ();
                  }
                return;
              }
          }
        show ();
      }
  }
