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
package org.webpki.json.test;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

import java.util.Date;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyStoreSigner;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;
import org.webpki.crypto.SymKeyVerifierInterface;
import org.webpki.crypto.URLFriendlyRandom;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONEnvelopedSignatureEncoder;
import org.webpki.json.JSONObject;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONSymKeySigner;
import org.webpki.json.JSONWriter;
import org.webpki.json.JSONX509Signer;
import org.webpki.util.ArrayUtil;

/**
 * Simple test program
 */
public class Sign extends JSONEncoder
  {
    static enum ACTION {SYM, ASYM, X509};
    
    static final String VERSION = "http://example.com/signature";
    static final String ROOT_PROPERTY = "MyLittleSignature";
    static final String ID = "ID";
    
    static class SymmetricOperations implements SymKeySignerInterface, SymKeyVerifierInterface
      {
        static final byte[] KEY = {(byte)0xF4, (byte)0xC7, (byte)0x4F, (byte)0x33, (byte)0x98, (byte)0xC4, (byte)0x9C, (byte)0xF4,
                                   (byte)0x6D, (byte)0x93, (byte)0xEC, (byte)0x98, (byte)0x18, (byte)0x83, (byte)0x26, (byte)0x61,
                                   (byte)0xA4, (byte)0x0B, (byte)0xAE, (byte)0x4D, (byte)0x20, (byte)0x4D, (byte)0x75, (byte)0x50,
                                   (byte)0x36, (byte)0x14, (byte)0x10, (byte)0x20, (byte)0x74, (byte)0x34, (byte)0x69, (byte)0x09};

        @Override
        public byte[] signData (byte[] data) throws IOException
          {
            return getMACAlgorithm ().digest (KEY, data);
          }
  
        @Override
        public MACAlgorithms getMACAlgorithm () throws IOException
          {
            return MACAlgorithms.HMAC_SHA256;
          }

        @Override
        public boolean verifyData (byte[] data, byte[] digest, MACAlgorithms algorithm) throws IOException
          {
            return ArrayUtil.compare (digest, getMACAlgorithm ().digest (KEY, data));
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

    class HT implements JSONObject
      {
        boolean fantastic;

        HT (boolean fantastic)
          {
            this.fantastic = fantastic;
          }

        @Override
        public void writeObject (JSONWriter wr) throws IOException
          {
            wr.setString ("HTL", "656756#");
            wr.setInt ("INTEGER", -689);
            wr.setBoolean ("Fantastic", fantastic);
          }
      }
    
    class RT implements JSONObject
      {
        @Override
        public void writeObject (JSONWriter wr) throws IOException
          {
            wr.setString ("RTl", "67");
            wr.setObject ("YT", new HT (false));
            wr.setString ("er","33");
          }
      }

    ACTION action;
    public Sign (ACTION action)
      {
        this.action = action;
      }

    JSONEnvelopedSignatureEncoder signature;
    
    @Override
    protected byte[] getJSONData () throws IOException
      {
        String instant = URLFriendlyRandom.generate (20);
        JSONWriter wr = new JSONWriter (ROOT_PROPERTY, VERSION);
        wr.setDateTime ("Now", new Date ());
        wr.setObject ("HRT", new RT ());
        wr.setObjectArray ("ARR", new JSONObject[]{});
        wr.setObjectArray ("BARR", new JSONObject[]{new HT (true), new HT (false)});
        wr.setString (ID, instant);
        wr.setStringArray ("STRINGS", new String[]{"One", "Two", "Three"});
        wr.setString ("EscapeMe", "A\\\n\"" );
        wr.setInt ("Intra", 78);
        if (action == ACTION.X509)
          {
            KeyStoreSigner signer = new KeyStoreSigner (DemoKeyStore.getExampleDotComKeyStore (), null);
            signer.setKey (null, DemoKeyStore.getSignerPassword ());
            signature = new JSONEnvelopedSignatureEncoder (new JSONX509Signer (signer));
          }
        else if (action == ACTION.ASYM)
          {
            try
              {
                PrivateKey private_key = (PrivateKey)DemoKeyStore.getECDSAStore ().getKey ("mykey", DemoKeyStore.getSignerPassword ().toCharArray ());
                PublicKey public_key = DemoKeyStore.getECDSAStore ().getCertificate ("mykey").getPublicKey ();
                signature = new JSONEnvelopedSignatureEncoder (new JSONAsymKeySigner (new AsymSigner (private_key, public_key)));
              }
            catch (GeneralSecurityException e)
              {
                throw new IOException (e);
              }
          }
        else
          {
            signature = new JSONEnvelopedSignatureEncoder (new JSONSymKeySigner (new SymmetricOperations ()));
          }
        signature.sign (wr, ID, instant);
        wr.setString ("Additional", "Not signed since it comes after the EnvelopedSignature");
        return wr.serializeJSONStructure ();
      }
    
    static void show ()
      {
        System.out.println (ACTION.SYM.toString () + "|" + ACTION.ASYM.toString () + "|" + ACTION.X509.toString () + " output-file\n");
        System.exit (0);
      }

    public static void main (String[] argc)
      {
        if (argc.length != 2)
          {
            show ();
          }
        for (ACTION action : ACTION.values ())
          {
            if (action.toString ().equalsIgnoreCase (argc[0]))
              {
                try
                  {
                    Security.insertProviderAt (new BouncyCastleProvider(), 1);
                    ArrayUtil.writeFile (argc[1], new Sign (action).getJSONData ());
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
