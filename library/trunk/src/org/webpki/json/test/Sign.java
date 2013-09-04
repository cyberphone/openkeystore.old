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
import java.security.Provider;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;

import java.util.Date;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyStoreSigner;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SymKeySignerInterface;
import org.webpki.crypto.SymKeyVerifierInterface;
import org.webpki.crypto.URLFriendlyRandom;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONSignatureEncoder;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONEncoder;
import org.webpki.json.JSONSymKeySigner;
import org.webpki.json.JSONWriter;
import org.webpki.json.JSONX509Signer;

import org.webpki.util.ArrayUtil;

/**
 * Simple signature test generator
 */
public class Sign extends JSONEncoder
  {
    static enum ACTION {SYM, ASYM, X509};
    
    static final String CONTEXT = "http://example.com/signature";
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

    class HT implements JSONObjectWriter
      {
        boolean fantastic;

        HT (boolean fantastic)
          {
            this.fantastic = fantastic;
          }

        @Override
        public void writeObject (JSONWriter wr) throws IOException
          {
            wr.setInt ("Value", -689);
            wr.setString ("String", "656756#");
            wr.setBoolean ("Fantastic", fantastic);
          }
      }
    
    class RT implements JSONObjectWriter
      {
        @Override
        public void writeObject (JSONWriter wr) throws IOException
          {
            wr.setString ("rt", "67");
            wr.setObject ("YT", new HT (false));
            wr.setString ("er","33");
          }
      }

    class SO implements JSONObjectWriter
      {
        int value;
        String instance;
        
        SO (int value, String instance)
          {
            this.value = value;
            this.instance = instance;
          }

        @Override
        public void writeObject (JSONWriter wr) throws IOException
          {
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

    JSONSignatureEncoder signature;
    
    void createX509Signature (JSONWriter wr) throws IOException
      {
        KeyStoreSigner signer = new KeyStoreSigner (DemoKeyStore.getExampleDotComKeyStore (), null);
        signer.setKey (null, DemoKeyStore.getSignerPassword ());
        wr.setEnvelopedSignature (new JSONX509Signer (signer));
      }
    
    void createAsymmetricKeySignature (JSONWriter wr) throws IOException
      {
        try
          {
            PrivateKey private_key = (PrivateKey)DemoKeyStore.getECDSAStore ().getKey ("mykey", DemoKeyStore.getSignerPassword ().toCharArray ());
            PublicKey public_key = DemoKeyStore.getECDSAStore ().getCertificate ("mykey").getPublicKey ();
            wr.setEnvelopedSignature (new JSONAsymKeySigner (new AsymSigner (private_key, public_key)));
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e);
          }
      }
    
    void createSymmetricKeySignature (JSONWriter wr) throws IOException
      {
        wr.setEnvelopedSignature (new JSONSymKeySigner (new SymmetricOperations ()));
      }
    
    
    @Override
    public byte[] getJSONData () throws IOException
      {
        String instant = URLFriendlyRandom.generate (20);
        JSONWriter wr = new JSONWriter (CONTEXT);
        wr.setDateTime ("Now", new Date ());
        wr.setObject ("RT", new RT ());
        wr.setObjectArray ("Array", new JSONObjectWriter[]{});
        wr.setObjectArray ("Barray", new JSONObjectWriter[]{new HT (true), new HT (false)});
        if (multiple)
          {
            wr.setObjectArray ("SignedObjects", new JSONObjectWriter[]{new SO (35, "this"), new SO (-90, "that")});
          }
        wr.setString (ID, instant);
        wr.setStringArray ("Strings", new String[]{"One", "Two", "Three"});
        wr.setString ("EscapeMe", "A\\\n\"" );
        wr.setInt ("Int", 78);
        if (action == ACTION.X509)
          {
            createX509Signature (wr);
          }
        else if (action == ACTION.ASYM)
          {
            createAsymmetricKeySignature (wr);
          }
        else
          {
            createSymmetricKeySignature (wr);
          }
        return wr.serializeJSONStructure ();
      }
    
    static void show ()
      {
        System.out.println (ACTION.SYM.toString () + "|" + ACTION.ASYM.toString () + "|" + ACTION.X509.toString () + " multiple(true|false) output-file\n");
        System.exit (0);
      }

    static void installOptionalBCProvider ()
      {
        @SuppressWarnings("rawtypes")
        Class bc = null;
        try
          {
            bc = Class.forName ("org.bouncycastle.jce.provider.BouncyCastleProvider");
          }
        catch (ClassNotFoundException e)
          {
            System.out.println ("\nBouncyCastle provider not in path - Using the platform provider\n");
            return;
          }
        try
          {
            Security.insertProviderAt ((Provider) bc.newInstance (), 1);
            System.out.println ("\nInstalled BouncyCastle as first provider\n");
          }
        catch (Exception e)
          {
            System.out.println ("\nFailed to install BouncyCastle!\n");
          }
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
                    installOptionalBCProvider ();
                    ArrayUtil.writeFile (argc[2], new Sign (action, new Boolean (argc[1])).getJSONData ());
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
