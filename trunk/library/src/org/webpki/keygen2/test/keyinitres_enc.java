package org.webpki.keygen2.test;

import java.io.IOException;

import java.math.BigInteger;

import java.util.Date;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Security;

import java.security.Signature;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.DOMReaderHelper;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.keygen2.KeyInitializationResponseEncoder;

public class keyinitres_enc
  {
    static final String UNFORMATTED_RSA  = "RSA/ECB/NoPadding";

    static int key_count;
    
    static byte[] key_attestation = new byte[]{0,5,7,};

    private static void show ()
      {
        System.out.println ("keyinitres_enc out_file\n");
        System.exit (3);
      }


    static class rsaKey implements AsymKeySignerInterface
    {
      PrivateKey priv_key;
      PublicKey pub_key;

      rsaKey (int size) throws Exception
        {
          KeyPairGenerator kpg = KeyPairGenerator.getInstance ("RSA");
          kpg.initialize (size);
          KeyPair key_pair = kpg.generateKeyPair ();
          priv_key = key_pair.getPrivate ();
          pub_key = key_pair.getPublic ();
        }

      rsaKey (int size, int exponent) throws Exception
        {
          KeyPairGenerator kpg = KeyPairGenerator.getInstance ("RSA");
          kpg.initialize (new RSAKeyGenParameterSpec (size, BigInteger.valueOf (exponent)));
          KeyPair key_pair = kpg.generateKeyPair ();
          priv_key = key_pair.getPrivate ();
          pub_key = key_pair.getPublic ();
        }

      public byte[] signData (byte[] data, SignatureAlgorithms sign_alg) throws IOException, GeneralSecurityException
        {
          Signature s = Signature.getInstance (sign_alg.getJCEName ());
          s.initSign (priv_key);
          s.update (data);
          return s.sign ();
        }

      public PublicKey getPublicKey () throws IOException, GeneralSecurityException
      {
        return pub_key;
      }
      }

    static class ecKey implements AsymKeySignerInterface
    {
      PrivateKey priv_key;
      PublicKey pub_key;

      ecKey () throws Exception
        {
          KeyPairGenerator kpg = KeyPairGenerator.getInstance ("EC");
          ECGenParameterSpec eccgen = new ECGenParameterSpec ("P-256");
          kpg.initialize(eccgen);
          KeyPair key_pair = kpg.generateKeyPair ();
          priv_key = key_pair.getPrivate ();
          pub_key = key_pair.getPublic ();
        }

      public byte[] signData (byte[] data, SignatureAlgorithms sign_alg) throws IOException, GeneralSecurityException
        {
          Signature s = Signature.getInstance (sign_alg.getJCEName ());
          s.initSign (priv_key);
          s.update (data);
          return s.sign ();
        }
      public PublicKey getPublicKey () throws IOException, GeneralSecurityException
      {
        return pub_key;
      }
      
    }

     
    static PublicKey nonceGen(PublicKey k) throws Exception
      {
        return k;
      }

    static PublicKey rsaAttestedKey (int size) throws Exception
    {
      return nonceGen (new rsaKey (size).getPublicKey ());
    }
    static PublicKey ecAttestedKey () throws Exception
    {
      return nonceGen (new ecKey ().getPublicKey ());
    }
    static PublicKey rsaAttestedKey (int size, int exponent) throws Exception
      {
        return nonceGen (new rsaKey (size, exponent).getPublicKey ());
      }

    static String getKey ()
      {
        key_count++;
        return "Key." + key_count;
      }

    public static void main (String args[]) throws Exception
      {
        if (args.length != 1) show ();
        Date client_time = DOMReaderHelper.parseDateTime (Constants.CLIENT_TIME).getTime ();
        Date server_time = DOMReaderHelper.parseDateTime (Constants.SERVER_TIME).getTime ();
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());

        KeyInitializationResponseEncoder kre = 
              new KeyInitializationResponseEncoder (Constants.SESSION_ID,
                                                    Constants.REQUEST_ID,
                                                    server_time,
                                                    client_time);

        kre.addPublicKey (rsaAttestedKey (1024), key_attestation, getKey (), null);

        kre.addPublicKey (rsaAttestedKey (1024, 3), key_attestation, getKey (), null);

        kre.addPublicKey (rsaAttestedKey (2048), key_attestation, getKey (), new byte[]{3,6,8,9,9});

        kre.addPublicKey (ecAttestedKey (), key_attestation, getKey (), null);

        ArrayUtil.writeFile (args[0], kre.writeXML());
      }
  }
