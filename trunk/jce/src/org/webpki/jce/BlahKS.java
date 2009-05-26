package org.webpki.jce;

import java.io.IOException;

import java.util.Vector;
import java.util.GregorianCalendar;
import java.util.Date;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.math.BigInteger;

import java.security.PrivateKey;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.security.PublicKey;
import java.security.Signature;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyPairGenerator;

import org.webpki.asn1.cert.DistinguishedName;

import org.webpki.util.DebugFormatter;
import org.webpki.util.ImageData;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.MacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.keygen2.PassphraseFormats;
import org.webpki.keygen2.PINGrouping;
import org.webpki.keygen2.InputMethods;
import org.webpki.keygen2.KeyGen2KeyUsage;

import org.webpki.ca.CertSpec;
import org.webpki.ca.CA;

import org.webpki.wasp.test.BankLogo;

import org.webpki.crypto.JKSSignCertStore;

import org.webpki.infocard.InfoCardWriter;
import org.webpki.infocard.TokenType;
import org.webpki.infocard.ClaimType;

import org.webpki.jce.crypto.CryptoDriver;

import org.webpki.crypto.test.DemoKeyStore;

public class BlahKS
  {
    static final String COMMON_HOTP_DEMO_SECRET = "3132333435363738393031323334353637383930";

    static final String SYM_KEY = "A0F35533E578DDCCA0F35533E578DDCC";

    static byte[] getSymKey () throws IOException
      {
        return DebugFormatter.getByteArrayFromHex (SYM_KEY);
      }

    static final int PIN_RETRIES = 3;

    static class CASignature implements AsymKeySignerInterface
      {
        KeyStore ks;

        CASignature () throws IOException
          {
            this.ks = DemoKeyStore.getSubCAKeyStore ();
          }

        public byte[] signData (byte[] data, SignatureAlgorithms sign_alg) throws IOException, GeneralSecurityException
          {
            Signature s = Signature.getInstance (sign_alg.getJCEName ());
            s.initSign ((PrivateKey)ks.getKey ("mykey", DemoKeyStore.getSignerPassword ().toCharArray ()));
            s.update (data);
            return s.sign ();
          }

        public PublicKey getPublicKey () throws IOException, GeneralSecurityException
          {
            return ks.getCertificate ("mykey").getPublicKey ();
          }
      }



    static class Property
      {
        private Property () {}

        String name;

        String value;

        boolean writable;


        public boolean isWritable ()
          {
            return writable;
          }


        public String getName ()
          {
            return name;
          }


        public String getValue ()
          {
            return value;
          }
      }


    static class PropertyBag
      {
        private PropertyBag () {}

        String type;

        Vector<Property> properties = new Vector<Property> ();


        public Property[] getProperties ()
          {
            return properties.toArray (new Property[0]);
          }


        public String getType ()
          {
            return type;
          }
      }


    static class Extension
      {
        private Extension () {}

        String type;

        byte[] data;


        public byte[] getData ()
          {
            return data;
          }


        public String getType ()
          {
            return type;
          }

      }


    @SuppressWarnings("serial")
    static class Logotype extends ImageData
      {
        String type_uri;

        Logotype (byte[] data, String mime_type, String type_uri)
          {
            super (data, mime_type);
            this.type_uri = type_uri;
          }

        public String getType ()
          {
            return type_uri;
          }
      }


    static void updateUserKey (int key_id, int pin_policy_id, int symmetric) throws IOException, SQLException, GeneralSecurityException
      {
        String sql = "UPDATE USERKEYS SET PINPolicyID=?, PINValue=?, PINTryCount=?, SecretKey=?" +
                 ((symmetric==1 || symmetric==2) ? ", PrivateKey=NULL, SuppAlgs=NULL" :
                  symmetric==3 ? ", PrivateKey=NULL, SuppAlgs='" + MacAlgorithms.HMAC_SHA1.getURI () + "'" : "") +
                     " WHERE KeyID=?";
        Connection conn = KeyUtil.getDatabaseConnection ();
        PreparedStatement pstmt = conn.prepareStatement (sql);
        pstmt.setInt (1, pin_policy_id);
        pstmt.setBytes (2, KeyUtil.getEncryptedPassphrase ("1234", PassphraseFormats.NUMERIC));
        pstmt.setInt (3, PIN_RETRIES);
        byte[] symkey = null;
        if (symmetric > 0)
          {
            symkey = CryptoDriver.sealSecretKey (DebugFormatter.getByteArrayFromHex (symmetric == 2 ? SYM_KEY + SYM_KEY : symmetric == 3 ?
                     COMMON_HOTP_DEMO_SECRET : SYM_KEY), false, new String[0]);
          }
        pstmt.setBytes (4, symkey);
        pstmt.setInt (5, key_id);
        pstmt.executeUpdate ();
        pstmt.close ();
        conn.close ();
      }


    static void addInformationCard (int user_id, int key_id) throws IOException, SQLException, GeneralSecurityException
      {
        KeyDescriptor kd = new KeyMetadataProvider (user_id).getKeyDescriptor (key_id);
        InfoCardWriter icw = new InfoCardWriter (kd.getCertificatePath ()[0],
                                                 TokenType.SAML_1_0,
                                                 "http://infocard.example.com/1234567",
                                                 "http://example.com",
                                                 "https://sts.example.com/tokenservice",
                                                 "https://sts.example.com/metadata");
        icw.addClaim (ClaimType.EMAIL_ADDRESS, "boss@fire.hell")
           .addClaim (ClaimType.COUNTRY)
           .setCardName ("WebPKI.org")
           .setCardImage (new ImageData (BankLogo.getGIFImage (), "image/gif"))
  //         .setTimeExpires (DOMReaderHelper.parseDateTime ("2017-11-12T21:03:24Z").getTime ())
           .setRequireAppliesTo (true)
           .setOutputSTSIdentity (true)
           .setPrivacyNotice ("http://example.com/priv")
           .addTokenType (TokenType.SAML_2_0);

        JKSSignCertStore signer = new JKSSignCertStore (DemoKeyStore.getExampleDotComKeyStore (), null);
        signer.setKey (null, DemoKeyStore.getSignerPassword ());
        Extension ic = new Extension ();
        ic.data = icw.getInfoCard (signer);
        ic.type = "http://schemas.xmlsoap.org/ws/2005/05/identity";
 //       Provisioning.deployExtension (ic, kd);
      }


    public static void createBlahData (int user_id) throws IOException, SQLException, GeneralSecurityException
      {
        createUserKey (user_id, "No PIN PKI key", false);
        int key_id = createUserKey (user_id, "John Doe", true);
        Provisioning prov = new Provisioning (user_id);
        int dev_puk_id = prov.getDevicePUKPolicyID ();
        int pin_policy_id = prov.createPINPolicy (PIN_RETRIES, // int retry_limit,
                                                          4, 8, // int min_length, int max_length,
                                                          PassphraseFormats.NUMERIC,
                                                          PINGrouping.SHARED,
                                                          null,  // PatternRestrictions[] May be null
                                                          InputMethods.ANY,
                                                          false, //boolean caching_support,
                                                          dev_puk_id);
        int key_id_sym = createUserKey (user_id, "Symmetric Key", false);
        int key_id_sym256 = createUserKey (user_id, "Symmetric Key 256", false);
        int key_id_sym20b = createUserKey (user_id, "Symmetric Key 20 bytes", false);
        int key_id_ic = createUserKey (user_id, "John's Dual-use", false);

        PropertyBag pb = new PropertyBag ();
        pb.type = org.webpki.keygen2.KeyGen2URIs.OTPPROVIDERS.IETF_HOTP;
        Property prop = new Property ();
        prop.name = "Counter";
        prop.value = "0";
        prop.writable = true;
        pb.properties.add (prop);
        prop = new Property ();
        prop.name = "Digits";
        prop.value = "8";
        pb.properties.add (prop);
        prop = new Property ();
        prop.name = "LoginID";
        prop.value = "johndoe";
        pb.properties.add (prop);
  //      Provisioning.deployPropertyBag (pb, key_id_sym20b);

        pb = new PropertyBag ();
        pb.type = org.webpki.keygen2.KeyGen2URIs.OTPPROVIDERS.IETF_TOTP;
        prop = new Property ();
        prop.name = "Cycle";
        prop.value = "30";
        pb.properties.add (prop);
        prop = new Property ();
        prop.name = "Digits";
        prop.value = "6";
        pb.properties.add (prop);
        prop = new Property ();
        prop.name = "LoginID";
        prop.value = "johndoe";
        pb.properties.add (prop);
    //    Provisioning.deployPropertyBag (pb, key_id_sym20b);

        pb = new PropertyBag ();
        pb.type = org.webpki.keygen2.KeyGen2URIs.OTPPROVIDERS.IETF_OCRA;
        prop = new Property ();
        prop.name = "CLength";
        prop.value = "6";
        pb.properties.add (prop);
        prop = new Property ();
        prop.name = "Digits";
        prop.value = "6";
        pb.properties.add (prop);
        prop = new Property ();
        prop.name = "LoginID";
        prop.value = "johndoe";
        pb.properties.add (prop);
  //      Provisioning.deployPropertyBag (pb, key_id_sym20b);

 //       Provisioning.deployLogotype (userLogo (user_id), key_id_sym20b);

        updateUserKey (key_id, pin_policy_id, 0);
        updateUserKey (key_id_sym, pin_policy_id, 1);
        updateUserKey (key_id_sym20b, pin_policy_id, 3);
        int puk_policy_id = prov.createPUKPolicy (3, PassphraseFormats.NUMERIC);
        prov.updatePUKPolicy (puk_policy_id, "0123456789");
        pin_policy_id = prov.createPINPolicy (PIN_RETRIES, // int retry_limit,
                                                      4, 8, // int min_length, int max_length,
                                                      PassphraseFormats.NUMERIC,
                                                      PINGrouping.SHARED,
                                                      null,  // PatternRestrictions[] May be null
                                                      InputMethods.ANY,
                                                      false, //boolean caching_support,
                                                      puk_policy_id);
        updateUserKey (key_id_sym256, pin_policy_id, 2);
        updateUserKey (key_id_ic, pin_policy_id, 0);
        addInformationCard (user_id, key_id_ic);
      }


    static int createUserKey (int user_id, String name, boolean add_ca_cert) throws IOException, SQLException, GeneralSecurityException
      {
        CertSpec cert_spec = new CertSpec ();
        cert_spec.setEndEntityConstraint ();
        cert_spec.setSubject ("CN=" + name + ",dc=webpki,dc=org");

        GregorianCalendar start = new GregorianCalendar ();
        GregorianCalendar end = (GregorianCalendar) start.clone ();
        end.set (GregorianCalendar.YEAR, end.get (GregorianCalendar.YEAR) + 25);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance ("RSA");
        kpg.initialize (1024);
        KeyPair key_pair = kpg.generateKeyPair ();
        Vector<X509Certificate> cert_path = new Vector<X509Certificate> ();

        cert_path.add ( 
            new CA ().createCert (cert_spec,
                                  DistinguishedName.subjectDN ((X509Certificate) DemoKeyStore.getSubCAKeyStore ().getCertificate ("mykey")),
                                  new BigInteger (String.valueOf (new Date ().getTime ())),
                                  start.getTime (), end.getTime (), 
                                  SignatureAlgorithms.RSA_SHA1,
                                  new CASignature (),
                                  key_pair.getPublic ()));
        if (add_ca_cert)
          {
            cert_path.add ((X509Certificate) DemoKeyStore.getSubCAKeyStore ().getCertificate ("mykey"));
          }
        Connection conn = KeyUtil.getDatabaseConnection ();
        PreparedStatement pstmt = conn.prepareStatement ("INSERT INTO USERKEYS (UserID, CertPath, PrivateKey, FriendlyName) " +
                                                         "VALUES (?,?,?,?)",
                                                         PreparedStatement.RETURN_GENERATED_KEYS);
        pstmt.setInt (1, user_id);
        pstmt.setBytes (2, KeyUtil.createDBCertificatePath (cert_path.toArray (new X509Certificate[0])));
        pstmt.setBytes (3, CryptoDriver.sealPrivateKey (key_pair.getPrivate (), false, KeyGen2KeyUsage.UNIVERSAL));
        pstmt.setString (4, name);
        pstmt.executeUpdate ();
        int key_id = 0;
        ResultSet rs = pstmt.getGeneratedKeys ();
        if (rs.next ())
          {
            key_id = rs.getInt (1);
          }
        rs.close ();
        pstmt.close ();
        conn.close ();
        if (key_id == 0)
          {
            throw new IOException ("Couldn't get KeyID!");
          }
        return key_id;
      }

  }
