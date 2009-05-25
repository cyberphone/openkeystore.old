package keygen;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.ByteArrayOutputStream;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.CallableStatement;

import javax.servlet.ServletException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.KeyStore;
import java.security.KeyFactory;
import java.security.Signature;

import java.security.spec.PKCS8EncodedKeySpec;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.webpki.util.ArrayUtil;
import org.webpki.util.WrappedException;import org.webpki.util.HTMLHeader;
import org.webpki.util.DebugFormatter;

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.JKSCAVerifier;

import org.webpki.keygen2.KeyOperationResponseDecoder;import misc.Init;

@SuppressWarnings("serial")
public class CredentialDeploymentRequestServlet extends KeyGenServlet
  {
    static final byte[] KEY_BACKUP_TEST_STRING = new byte[]{'T', 'h', 'i', 's', ' ', 'i','s',' ', 'i', 't'};


    private String convert (String input) throws IOException      {
        return DebugFormatter.getHexString (input.getBytes ("UTF-8"));      }
    public void protectedPost (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        try
          {
            ServletContext context = getServletContext ();

            ProvisioningState prov_state = getProvisioningState (session);
            prov_state.key_op_res_dec = (KeyOperationResponseDecoder) getXMLObject (request);            JKSCAVerifier verifier = new JKSCAVerifier (getDeviceCAKeyStore (context));
            verifier.setTrustedRequired (false);
            prov_state.key_op_res_dec.verifyEndorsementKeySignature (verifier, prov_state.key_op_req_enc);

            if (httpsMode (context))
              {
                KeyStore ks = getTLSCertificateKeyStore (context);
                if (!ArrayUtil.compare (prov_state.key_op_res_dec.getServerCertificateFingerprint (),
                                        CertificateUtil.getCertificateSHA256 ((X509Certificate) ks.getCertificate (ks.aliases ().nextElement ()))))
                  {
                    bad ("Non-matching server cert hash");
                  }
              }            // Key ecsrow code
            for (KeyOperationResponseDecoder.GeneratedPublicKey key : prov_state.key_op_res_dec.getGeneratedPublicKeys ())
              {
                if (key.getKeyArchivalData () != null)
                  {
                    KeyOperationResponseDecoder.KeyArchivalData key_archival_data = key.getKeyArchivalData ();                    Cipher crypt = Cipher.getInstance (key_archival_data.getKeyWrapAlgorithm ().getJCEName ());
                    crypt.init (Cipher.DECRYPT_MODE, getKeyArchivalPrivateKey (context));
                    byte[] encryption_key = crypt.doFinal (key_archival_data.getWrappedEncryptionKey ());
                    byte[] encrypted_private_key = key_archival_data.getEncryptedPrivateKey ();
                    crypt = Cipher.getInstance (key_archival_data.getEncryptionAlgorithm ().getJCEName ());
                    crypt.init (Cipher.DECRYPT_MODE,                                new SecretKeySpec (encryption_key, "AES"),                                new IvParameterSpec (encrypted_private_key, 0, 16));
                    byte[] private_key_blob = crypt.doFinal (encrypted_private_key, 16, encrypted_private_key.length - 16);                    // Verification of key
                    PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec (private_key_blob);                    boolean rsa = key.getPublicKey () instanceof RSAPublicKey;
                    PrivateKey private_key = KeyFactory.getInstance (rsa ? "RSA" : "EC").generatePrivate (key_spec);
                    Signature sign = Signature.getInstance ((rsa ? SignatureAlgorithms.RSA_SHA1 : SignatureAlgorithms.ECDSA_SHA1).getJCEName ());
                    sign.initSign (private_key);                    sign.update (KEY_BACKUP_TEST_STRING);
                    byte[] key_archival_verify = sign.sign ();
                    Signature verify = Signature.getInstance ((rsa ? SignatureAlgorithms.RSA_SHA1 : SignatureAlgorithms.ECDSA_SHA1).getJCEName ());
                    verify.initVerify (key.getPublicKey ());                    verify.update (KEY_BACKUP_TEST_STRING);
                    if (!verify.verify (key_archival_verify))                      {
                        bad ("Archived private key validation failed");                      }
                  }              }            if (wantDeferredCertification (context))              {                ByteArrayOutputStream baos = new ByteArrayOutputStream ();
                new ObjectOutputStream (baos).writeObject (prov_state);                Connection conn = getDatabaseConnection ();
                CallableStatement stmt = conn.prepareCall ("{call SetRequestSP(?, ?, ?, ?)}");
                stmt.setInt (1, getUserID (session));
                stmt.setString (2, prov_state.key_op_res_dec.getServerSessionID ());
                stmt.setString (3, prov_state.key_op_res_dec.getClientSessionID ());
                stmt.setBytes (4, baos.toByteArray ());
                stmt.execute ();
                stmt.close ();
                conn.close ();
                String url = new StringBuffer (genApplicationURL (request, "delayed_kg2_deploy")).                  append ("?uid=").append (getUserID (session)).                  append ("&sid=").                  append (convert (prov_state.key_op_res_dec.getServerSessionID ())).                  append ("&cid=").
                  append (convert (prov_state.key_op_res_dec.getClientSessionID ())).toString ();
                StringBuffer s = HTMLHeader.createHTMLHeader (true, true, "Success", null).
                  append ("<body><table width=\"100%\" height=\"100%\"><tr><td align=\"center\" valign=\"middle\">" +
                          "<table><tr><td align=\"center\"><b>Step #1 Completed</b></td></tr>" +
                          "<tr><td height=\"10\"></td></tr>" +
                          "<tr><td align=\"center\"><img src=\"images/mini_banklogo.gif\"></td></tr>" +
                          "<tr><td height=\"20\"></td></tr>" +
                          "<tr><td align=\"left\">");                if (request.getHeader ("User-Agent").equals ("WebPKI.org Phone Emulator"))
                  {
                    Init.sendPhoneMail (getEmailAddress (request),
                                        "MyBank CA",
                                        "<script type=\"text/javascript\">var once=true;function oneTimeOnly (href){if (once){" +                                        "once=false; href.disabled = true; return true;}return false;}</script>" +                                        "Click on <a href=\"" + url +
                                        "\" onclick=\"return oneTimeOnly (this)\"> get&nbsp;credentials</a> to complete enrollment");
                    s.append ("You will in 10 seconds or so receive an e-mail (<i>in the phone...</i>) telling how to complete " +
                               "the enrollment process.&nbsp;<br>&nbsp;<br>PLEASE WAIT for the e-mail!");
                  }
                else
                  {                    s.append ("In order to complete the process you should " +                              "(after you and your device have been verified by MyBank), click on " +                              "<a href=\"" + url + "\"> get&nbsp;credentials</a>");
                  }                s.append ("<br>&nbsp;<br>/MyBank team</td></tr>" +
                          "</table></td></tr></table></body></html>");

                session.invalidate ();
                setHTMLMode (response);
                response.getOutputStream ().print (s.toString ());
              }            else              {
                deployCredentials (context, prov_state, getUserID (session), request, response);              }
          }
        catch (SQLException sqle)
          {
            throw new WrappedException (sqle);
          }
        catch (GeneralSecurityException gse)
          {
            throw new WrappedException (gse);
          }
      }
  }
