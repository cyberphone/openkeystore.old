package org.webpki.crypto.test;

import java.security.PublicKey;
import java.security.Signature;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;

import java.security.interfaces.ECPublicKey;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import org.webpki.asn1.DerDecoder;
import org.webpki.asn1.ParseUtil;
import org.webpki.asn1.BaseASN1Object;
import org.webpki.asn1.ASN1Sequence;
import org.webpki.asn1.ASN1ObjectID;
import org.webpki.asn1.ASN1BitString;

import org.webpki.util.ArrayUtil;

public class ECDSATest
  {


    private ECDSATest ()
      {
      }

    public static void main (String[] argv) throws Exception
      {
        KeyPairGenerator generator = KeyPairGenerator.getInstance ("EC");
        ECGenParameterSpec eccgen = new ECGenParameterSpec ("P-256");
        generator.initialize(eccgen);
        KeyPair keypair = generator.generateKeyPair();
System.out.println ("ALG=" + ((ECPublicKey)keypair.getPublic ()).getAlgorithm () +
" FMT=" + ((ECPublicKey)keypair.getPublic ()).getFormat ());
        BaseASN1Object subjectPublicKeyInfo = DerDecoder.decode (keypair.getPublic ().getEncoded ());
System.out.println (subjectPublicKeyInfo.toString ());
        ASN1Sequence seqo = ParseUtil.sequence(subjectPublicKeyInfo, 2);
String oid;
byte[] pub;
System.out.println ("1=" + (oid = ParseUtil.oid (ParseUtil.sequence(seqo.get(0), 2).get(1)).oid()));
System.out.println ("2=" + org.webpki.util.DebugFormatter.getHexDebugData (pub = ParseUtil.bitstring(seqo.get(1))));
PublicKey rpk = KeyFactory.getInstance ("EC").generatePublic (new X509EncodedKeySpec (new ASN1Sequence (new BaseASN1Object[] {
    new ASN1Sequence (new BaseASN1Object[] {new ASN1ObjectID ("1.2.840.10045.2.1"),
                                            new ASN1ObjectID (oid)
                                           }),
    new ASN1BitString (pub)
                                       }).encode ()));

System.out.println ("KEQ=" + ArrayUtil.compare (rpk.getEncoded (), keypair.getPublic ().getEncoded ()));
        Signature signer = Signature.getInstance ("SHA256WithECDSA");
        signer.initSign (keypair.getPrivate ());
        byte[] data = "Hej".getBytes ("UTF-8");
        signer.update (data);
        byte[] result = signer.sign ();
System.out.println (org.webpki.util.DebugFormatter.getHexDebugData (result));
        signer = Signature.getInstance ("SHA256WithECDSA");
        signer.initSign (keypair.getPrivate ());
        signer.update (data);
        result = signer.sign ();
System.out.println (org.webpki.util.DebugFormatter.getHexDebugData (result));
        Signature verifier = Signature.getInstance ("SHA256WithECDSA");
        verifier.initVerify (keypair.getPublic ());
        verifier.update (data);
        System.out.println ("Signature OK=" + verifier.verify (result));

      }

  }
