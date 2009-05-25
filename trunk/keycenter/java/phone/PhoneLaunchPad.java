package phone;

import java.io.IOException;

import java.util.GregorianCalendar;
import java.util.Date;

import java.sql.SQLException;

import java.math.BigInteger;

import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;
import java.security.Signature;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyPairGenerator;

import javax.servlet.ServletException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.asn1.cert.DistinguishedName;

import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.CertificateFilter;
import org.webpki.crypto.MacAlgorithms;

import org.webpki.ca.CertSpec;
import org.webpki.ca.CA;

import org.webpki.webutil.ServletUtil;

import org.webpki.util.WrappedException;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;

import org.webpki.jce.SignatureProvider;
import org.webpki.jce.SymKeyEncryptionProvider;
import org.webpki.jce.AsymKeyEncryptionProvider;
import org.webpki.jce.HmacProvider;
import org.webpki.jce.KeyDescriptor;
import org.webpki.jce.KeyMetadataProvider;
import org.webpki.jce.InformationCardProvider;
import org.webpki.jce.SelectedCertificate;
import org.webpki.jce.PropertyBag;
import org.webpki.jce.Provisioning;

import org.webpki.jce.crypto.CryptoDriver;


@SuppressWarnings("serial")
public class PhoneLaunchPad extends ProtectedServlet
  {
    class CASignature implements AsymKeySignerInterface
      {
        KeyStore ks;
        ServletContext context;

        CASignature (ServletContext context) throws IOException
          {
            this.context = context;
            this.ks = getDeviceCAKeyStore (context);
          }

        public byte[] signData (byte[] data, SignatureAlgorithms sign_alg) throws IOException, GeneralSecurityException
          {
            Signature s = Signature.getInstance (sign_alg.getJCEName ());
            s.initSign ((PrivateKey)ks.getKey ("mykey", context.getInitParameter ("devicecakeypass").toCharArray ()));
            s.update (data);
            return s.sign ();
          }

        public PublicKey getPublicKey () throws IOException, GeneralSecurityException
          {
            return ks.getCertificate ("mykey").getPublicKey ();
          }
      }


    private String getCertificateInfo (X509Certificate certificate) throws IOException
      {
        return new CertificateInfo (certificate).toString ();
      }


    String createDeviceCertificate (int user_id) throws SQLException, IOException, GeneralSecurityException
      {
        ServletContext context = getServletContext ();
        CertSpec cert_spec = new CertSpec ();
        cert_spec.setEndEntityConstraint ();
        cert_spec.setSubject ("CN=Device Type 1AK4,serialNumber=" + user_id + ",dc=webpki,dc=org");

        GregorianCalendar start = new GregorianCalendar ();
        GregorianCalendar end = (GregorianCalendar) start.clone ();
        end.set (GregorianCalendar.YEAR, end.get (GregorianCalendar.YEAR) + 25);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance ("RSA");
        kpg.initialize (2048);
        KeyPair key_pair = kpg.generateKeyPair ();

        X509Certificate device_cert = 
            new CA ().createCert (cert_spec,
                                  DistinguishedName.subjectDN ((X509Certificate) getDeviceCAKeyStore (context).getCertificate ("mykey")),
                                  new BigInteger (String.valueOf (new Date ().getTime ())),
                                  start.getTime (), end.getTime (), 
                                  SignatureAlgorithms.RSA_SHA1,
                                  new CASignature (context),
                                  key_pair.getPublic ());

        Provisioning.storeDeviceCertificatePathAndKey (new X509Certificate[] {device_cert}, key_pair.getPrivate (), user_id);

        return "\n" + getCertificateInfo (device_cert) + "\n";
      }

    void signTest (SignatureProvider uc, KeyDescriptor[] kds, SignatureAlgorithms algorithm, HttpSession session) throws IOException, GeneralSecurityException, SQLException
      {
        if (uc.open (kds[1].getKeyID (), "1234"))
          {
            byte[] raw_data = new byte[]{6,7};
            byte[] sign_data = uc.signData (raw_data, algorithm);
            PhoneDebugWin.setDebugEvent (session, "Succeed signing l=" + sign_data.length + " Alg=" + algorithm.toString ());
            java.security.Signature verifier = Signature.getInstance (algorithm.getJCEName ());
            verifier.initVerify (kds[1].getCertificatePath ()[0].getPublicKey ());
            verifier.update (raw_data);
            PhoneDebugWin.setDebugEvent (session, verifier.verify (sign_data) ? "Successful verify" : "Bad verify");
          }
        else
          {
            PhoneDebugWin.setDebugEvent (session, "Bad password");
          }
      }

    void testRound (int user_id, HttpSession session) throws IOException, GeneralSecurityException, SQLException
      {
        org.webpki.jce.BlahKS.createBlahData (user_id);

        SignatureProvider uc = new SignatureProvider (user_id);
        for (SelectedCertificate cert : uc.getCertificateSelection (new CertificateFilter[]{new CertificateFilter ().setSubjectRegEx (".*CN=John Doe(,.*|$)")}, null))
          {
            KeyDescriptor kd = cert.getKeyDescriptor ();
            PhoneDebugWin.setDebugEvent (session, "Matching cert: " + kd.getKeyID () + " PIN=" + kd.isPINProtected () +
                                   "\n" + getCertificateInfo (cert.getCertificate ()).toString ());
          }
        KeyMetadataProvider md = new KeyMetadataProvider (user_id);
        KeyDescriptor[] kds = md.getKeyDescriptors ();
        for (KeyDescriptor kd : kds)
          {
            PhoneDebugWin.setDebugEvent (session, kd.toString ());
          }
        
        uc.open (kds[1].getKeyID (), "0000");  // One bad attempt
        uc.open (kds[1].getKeyID (), "0000");  // One bad attempt
        uc.open (kds[1].getKeyID (), "0000");  // One bad attempt
        PhoneDebugWin.setDebugEvent (session, (kds[1] = md.getKeyDescriptor (kds[1].getKeyID ())).toString ());
        kds[1].unlockKey ("01234567890123456");
        PhoneDebugWin.setDebugEvent (session, kds[1].toString ());
        kds[1].unlockKey ("01234567890123456789");
        PhoneDebugWin.setDebugEvent (session, kds[1].toString ());
        signTest (uc, kds, SignatureAlgorithms.RSA_SHA1, session);
        signTest (uc, kds, SignatureAlgorithms.RSA_SHA256, session);
        signTest (uc, kds, SignatureAlgorithms.RSA_SHA512, session);
        HmacProvider hmac = new HmacProvider (user_id);
        if (hmac.open (kds[2].getKeyID (), "1234"))
          {
            PhoneDebugWin.setDebugEvent (session, "Succeed opening sym key ");
            hmac.mac (new byte[]{6,7}, MacAlgorithms.HMAC_SHA1);
          }
        else
          {
            PhoneDebugWin.setDebugEvent (session, "Bad password");
          }
        SymKeyEncryptionProvider sk = new SymKeyEncryptionProvider (user_id);
        if (sk.open (kds[2].getKeyID (), "1234"))
          {
            String s = "The quick brown fox jumped over the lazy bear";
            byte[] res = sk.encrypt (s.getBytes ("UTF-8"), SymEncryptionAlgorithms.AES128_CBC);
            sk.open (kds[2].getKeyID (), "1234");
            PhoneDebugWin.setDebugEvent (session, new String (sk.decrypt (res, SymEncryptionAlgorithms.AES128_CBC), "UTF-8") + " [AES128_CBC]");
            sk.open (kds[2].getKeyID (), "1234");
            res = sk.encrypt (s.getBytes ("UTF-8"), SymEncryptionAlgorithms.AES_ECB_P5);
            sk.open (kds[2].getKeyID (), "1234");
            PhoneDebugWin.setDebugEvent (session, new String (sk.decrypt (res, SymEncryptionAlgorithms.AES_ECB_P5), "UTF-8") + " [AES128_ECB_P5]");
            if (wantStrongCrypto (getServletContext ()))
              {
                sk.open (kds[3].getKeyID (), "1234");
                res = sk.encrypt (s.getBytes ("UTF-8"), SymEncryptionAlgorithms.AES_ECB_P5);
                sk.open (kds[3].getKeyID (), "1234");
                PhoneDebugWin.setDebugEvent (session, new String (sk.decrypt (res, SymEncryptionAlgorithms.AES_ECB_P5), "UTF-8") + " [AES256_ECB_P5]");
                sk.open (kds[3].getKeyID (), "1234");
                res = sk.encrypt (s.getBytes ("UTF-8"), SymEncryptionAlgorithms.AES256_CBC);
                sk.open (kds[3].getKeyID (), "1234");
                PhoneDebugWin.setDebugEvent (session, new String (sk.decrypt (res, SymEncryptionAlgorithms.AES256_CBC), "UTF-8") + " [AES256_CBC]");
              }
            PropertyBag prop_bag = kds[4].getPropertyBag (org.webpki.keygen2.KeyGen2URIs.OTPPROVIDERS.IETF_HOTP);
            if (prop_bag == null)
              {
                PhoneDebugWin.setDebugEvent (session, "MISSING PROPERTYBAG!");
              }
            else
              {
                PhoneDebugWin.setDebugEvent (session, "HAS PROPERTYBAG! Counter=" + prop_bag.getString ("Counter") + " LoginID.w=" + prop_bag.isWritable ("LoginID"));
//                prop_bag.setInteger ("Counter", prop_bag.getInteger ("Counter") + 1);
              }
            sk.open (kds[2].getKeyID (), "1234");
            s = "01234567";
            res = sk.encrypt (s.getBytes ("UTF-8"), SymEncryptionAlgorithms.KW_AES128);
            sk.open (kds[2].getKeyID (), "1234");
            PhoneDebugWin.setDebugEvent (session, new String (sk.decrypt (res, SymEncryptionAlgorithms.KW_AES128), "UTF-8") + " [KW-128]");
          }
        else
          {
            PhoneDebugWin.setDebugEvent (session, "Bad password");
          }
        AsymKeyEncryptionProvider asye = new AsymKeyEncryptionProvider (user_id);
        if (asye.open (kds[1].getKeyID (), "1234"))
          {
            String s = "The quick brown fox jumped over the lazy bear [PKI]";
            byte[] res = asye.encrypt (s.getBytes ("UTF-8"), kds[1].getKeyID (), AsymEncryptionAlgorithms.RSA_PKCS_1);
            PhoneDebugWin.setDebugEvent (session, new String (asye.decrypt (res, AsymEncryptionAlgorithms.RSA_PKCS_1), "UTF-8"));
          }
        else
          {
            PhoneDebugWin.setDebugEvent (session, "Bad password");
          }
        InformationCardProvider.InformationCard[] ics = InformationCardProvider.getInformationCards (user_id);
        PhoneDebugWin.setDebugEvent (session, "InfoCards=" + (ics == null ? 0 : ics.length));
      }

    void initPhone (HttpSession session) throws IOException
      {
        int user_id = getUserID (session);
        try
          {
            X509Certificate[] device_cert_path = null;
            try
              {
                device_cert_path = new CryptoDriver (user_id).getDeviceCertificatePath ();
              }
            catch (IOException iox)
              {
System.out.println (iox.getMessage ());
              }
            if (device_cert_path == null)
              {
                PhoneDebugWin.setDebugEvent (session, "Device certificate creation begin...");
                PhoneDebugWin.setDebugEvent (session, createDeviceCertificate (user_id));
                PhoneDebugWin.setDebugEvent (session, "Device certificate creation finished!");
                testRound (user_id, session);
              }
            else
              {
                PhoneDebugWin.setDebugEvent (session, "Device certificate:\n" + getCertificateInfo (device_cert_path[0]));
              }
          }
        catch (SQLException iox)
          {
            throw new WrappedException (iox);
          }
        catch (GeneralSecurityException gse)
          {
            throw new WrappedException (gse);
          }
      }


    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.PHONE_LAUNCH;
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        if (PhoneDebugWin.initDebugWin (session))
          {
            PhoneDebugWin.setDebugEvent (session, "Virtual phone '" + getEmailAddress (request) + "' initialized");
            initPhone (session);
          }

        StringBuffer s = createHeader (request,
                  "function launchphone (url)\n" +
                  "{\n" +
                  "  window.open (url,'debugger" +
                  getUserID (session) +
                  "','resizable=yes,scrollbars=yes,toolbar=no,menubar=no,location=no,status=no,height=540,width=1000');\n" +
                  "}\n").
          append ("<table width=\"450\"><tr><td align=\"center\" class=\"headline\">Mobile Phone Emulator<br>&nbsp;</td></tr>" +
                  "<tr><td align=\"left\">The mobile phone emulator is a web-application that works like a " +
                  "virtual mobile phone on the Internet.&nbsp; Each registered user get their own private instance of a " +
                  "mobile phone and can with this " +
                  "tool provision and test credentials.&nbsp; The " +
                  "purpose of the mobile phone emulator is to make it possible to &quot;play&quot; with KeyGen2 without doing any " +
                  "downloads or similar.&nbsp; In addition to supporting demonstrations, the mobile phone emulator serves as a reference implementation." +
                  "&nbsp;<br>&nbsp;<br>" +
                  "Tip: Try the &quot;Quick Run&quot; command in the emulator.</td></tr>" +
                  "<tr><td>&nbsp;</td></tr>" +
                  "<tr><td align=\"center\"><input type=\"button\" onclick=\"launchphone ('").
          append (ServletUtil.getContextURL (request)).
          append ("/phonemain')\" value=\"Launch Mobile Phone Emulator\"></td></tr></table>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
