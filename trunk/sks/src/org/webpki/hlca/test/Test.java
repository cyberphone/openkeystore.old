package org.webpki.hlca.test;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;

import java.util.EnumSet;
import java.util.Enumeration;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.KeyStoreReader;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.hlca.JCEKeyStore;
import org.webpki.hlca.JCEProvider;
import org.webpki.keygen2.KeyUsage;
import org.webpki.keygen2.PINGrouping;
import org.webpki.keygen2.PassphraseFormat;
import org.webpki.keygen2.PatternRestriction;

import org.webpki.sks.SecureKeyStore;

import org.webpki.sks.test.Device;
import org.webpki.sks.test.GenKey;
import org.webpki.sks.test.PINPol;
import org.webpki.sks.test.ProvSess;

public class Test
  {
    static byte[] TEST = {0,2,7,3,2,9,3,57};
    public static void main (String[] argc) throws GeneralSecurityException, IOException
      {
        if (argc.length == 0)
          {
            System.out.println ("i keystore storepass                      // Init keystore");
            System.out.println ("e keystore storepass [keypass]            // Enumerate or Enumerate + Sign");
            System.out.println ("a keystore storepass p12/jks-file keypass // Add key");
            System.exit (3);
          }
        Security.addProvider (new JCEProvider ());
        Security.addProvider(new BouncyCastleProvider());
        KeyStore ks = KeyStore.getInstance ("SKS");
        switch (argc[0].charAt (0))
          {
            case 'i':
              ks.load (null, null);
              ks.store (new FileOutputStream (argc[1]), argc[2].toCharArray ());
              break;
            case 'e':
              ks.load (new FileInputStream (argc[1]), argc[2].toCharArray ());
              Enumeration<String> aliases = ks.aliases ();
              while (aliases.hasMoreElements ())
                {
                  String alias = aliases.nextElement ();
                  System.out.println ("Key:" + alias + "\n" + new CertificateInfo ((X509Certificate) ks.getCertificate (alias)));
                  if (argc.length == 4)
                    {
                      Signature signer = Signature.getInstance ("SHA256withRSA", "SKS");
                      signer.initSign ((PrivateKey) ks.getKey (alias, argc[3].toCharArray ()));
                      signer.update (TEST);
                      byte[] result = signer.sign ();
                      Signature verify = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName (), "BC");
                      verify.initVerify (ks.getCertificate (alias));
                      verify.update (TEST);
                      if (verify.verify (result))
                        {
                          System.out.println ("Signature worked fine");
                        }
                      else
                        {
                          throw new IOException ("Bad signature");
                        }
                    }
                }
              break;
            case 'a':
              ks = KeyStoreReader.loadKeyStore (argc[3], argc[4]);
              aliases = ks.aliases ();
              String key_entry = null;
              while (aliases.hasMoreElements ())
                {
                  String alias = aliases.nextElement ();
                  if (ks.isKeyEntry (alias))
                    {
                      key_entry = alias;
                      break;
                    }
                }
              if (key_entry == null)
                {
                  throw new IOException ("No key found in keystore");
                }
              SecureKeyStore sks = JCEKeyStore.loadKeyStore (new FileInputStream (argc[1]), argc[2].toCharArray ());
              ProvSess sess = new ProvSess (new Device (sks));
              PINPol pin_policy = sess.createPINPolicy ("PIN",
                                                        PassphraseFormat.STRING,
                                                        EnumSet.noneOf (PatternRestriction.class),
                                                        PINGrouping.SHARED,
                                                        4 /* min_length */, 
                                                        8 /* max_length */,
                                                        (short) 3 /* retry_limit*/, 
                                                        null /* puk_policy */);
              GenKey key = sess.createECKey ("Key.1",
                                             argc[4] /* pin_value */,
                                             pin_policy,
                                             KeyUsage.UNIVERSAL);
              key.setCertificate (new X509Certificate[]{(X509Certificate)ks.getCertificate (key_entry)});
              sess.restorePrivateKey (key, (PrivateKey)ks.getKey (key_entry, argc[4].toCharArray ()));
              sess.closeSession ();
              JCEKeyStore.storeSoftToken (sks, new FileOutputStream (argc[1]), argc[2].toCharArray ());
          }
      }
  }
