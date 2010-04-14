package org.webpki.keygen2.test;

import java.io.IOException;

import java.math.BigInteger;

import javax.crypto.Cipher;

import java.util.Date;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;

import java.security.Signature;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import java.security.interfaces.RSAKey;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.DOMReaderHelper;

import org.webpki.crypto.JKSSignCertStore;
import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.keygen2.KeyInitializationResponseEncoder;
import org.webpki.keygen2.KeyAttestationUtil;
import org.webpki.keygen2.KeyGen2KeyUsage;

public class keyinitres_enc
  {
    static final String UNFORMATTED_RSA  = "RSA/ECB/NoPadding";

    static int key_count;
    static byte[] last_signature;

    static String last_key;
    private static void show ()
      {
        System.out.println ("keyinitres_enc out_file [-selfsigned]\n");
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
        last_key = getKey ();
        byte[] nonce = KeyAttestationUtil.createKA1Nonce (last_key, Constants.SESSION_ID, Constants.REQUEST_ID);
        KeyStore ks = TPMKeyStore.getTPMKeyStore ();
        String signpassword = TPMKeyStore.getSignerPassword ();
        String key_alias = "mykey";
        Cipher cipher = Cipher.getInstance (UNFORMATTED_RSA);
        PrivateKey priv = (PrivateKey) ks.getKey (key_alias, signpassword.toCharArray ());
        cipher.init (Cipher.DECRYPT_MODE, priv);
        last_signature = cipher.doFinal (KeyAttestationUtil.createKA1Package ((RSAKey)priv,
                                                                              k,
                                                                              false,
                                                                              KeyGen2KeyUsage.AUTHENTICATION,
                                                                              nonce,
                                                                              null));
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
        if (args.length < 1 || args.length > 2 || (args.length == 2 && !args[1].equals ("-selfsigned"))) show ();
        Date client_time = DOMReaderHelper.parseDateTime (Constants.CLIENT_TIME).getTime ();
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());



        KeyInitializationResponseEncoder kre = 
              new KeyInitializationResponseEncoder (Constants.SESSION_ID,
                                               Constants.REQUEST_ID,
                                               "https://example.com/keygenres",
                                               "https://example.com/keygenreq",
                                               Constants.SERVER_TIME,
                                               client_time,
                                               (X509Certificate)DemoKeyStore.getExampleDotComKeyStore ().getCertificate ("mykey"));

        if (args.length == 2)
          {
            kre.addSelfSignedKey (new rsaKey (1024), getKey ());

            kre.addSelfSignedKey (new rsaKey (1024, 3), getKey ());

            kre.addSelfSignedKey (new rsaKey (2048), getKey ());

            kre.addSelfSignedKey (new rsaKey (1024), getKey ());
          }
        else
          {
            kre.addAttestedKey (rsaAttestedKey (1024), last_signature, last_key, null);

            kre.addAttestedKey (rsaAttestedKey (1024, 3), last_signature, last_key, null);

            kre.addAttestedKey (rsaAttestedKey (2048), last_signature, last_key, null);

            kre.addAttestedKey (ecAttestedKey (), last_signature, last_key, null);
          }

        KeyStore ks = TPMKeyStore.getTPMKeyStore ();
        String signpassword = TPMKeyStore.getSignerPassword ();
        String key_alias = "mykey";
        JKSSignCertStore signer = new JKSSignCertStore (ks, null);
        signer.setKey (key_alias, signpassword);

        kre.createEndorsementKeySignature (signer);

        ArrayUtil.writeFile (args[0], kre.writeXML());
      }
  }
