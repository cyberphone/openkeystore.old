package phone;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Signature;
import java.security.PrivateKey;

import javax.crypto.Mac;

import java.util.Enumeration;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.util.WrappedException;

import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.MacAlgorithms;


@SuppressWarnings("serial")
public class PhoneWinJCETest extends PhoneWinServlet
  {
    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        Enumeration<String> aliases = null;
        KeyStore ks = null;
        try
          {
            ks = KeyStore.getInstance ("WebPKI");
            ks.load (null, String.valueOf (getUserID (session)).toCharArray ());
            aliases = ks.aliases ();
          }
        catch (GeneralSecurityException gse)
          {
            bad (gse.getMessage ());
          }
        StringBuffer s = createHeader ("JCE Tests").
          append (divSection ());
        String sym = null;
        String asym = null;
        while (aliases.hasMoreElements ())
          {
            asym = sym;
            s.append (sym = aliases.nextElement ()).append ("<br>");
          }
        try
          {
            Signature sign = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName (), ks.getProvider ());
            sign.initSign ((PrivateKey)ks.getKey (asym, "1345".toCharArray ()));
            byte[] data = new byte[]{1,2,3,6};
            sign.update (data);
            byte[] sign_data = sign.sign ();
            Signature verifier = Signature.getInstance (SignatureAlgorithms.RSA_SHA256.getJCEName ());
            verifier.initVerify (ks.getCertificate (asym));
            verifier.update (data);
            s.append (verifier.verify (sign_data)? "SIGN_OK": "****").append ("<br>");
            Mac mac = Mac.getInstance (MacAlgorithms.HMAC_SHA1.getJCEName (), ks.getProvider ());
            mac.init (ks.getKey (sym, "1345".toCharArray ()));
            s.append (mac.doFinal (data).length);
          }
        catch (GeneralSecurityException gse)
          {
            throw new WrappedException (gse);
          }
        s.append ("</div>").
          append (createFooter ("phonewinsecurity"));

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
