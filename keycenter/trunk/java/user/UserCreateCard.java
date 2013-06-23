package user;

import java.io.IOException;

import java.util.Date;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.security.cert.X509Certificate;

import org.webpki.infocard.TokenType;
import org.webpki.infocard.ClaimType;
import org.webpki.infocard.InfoCardWriter;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;


@SuppressWarnings("serial")
public class UserCreateCard extends ProtectedServlet
  {
    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.SETUP_CREDENTIALS;
      }

    private void printPage (HttpServletRequest request, HttpServletResponse response, boolean error) throws IOException, ServletException
      {
        StringBuffer s = createHeader (request).
          append ("<table><tr><td align=\"center\" class=\"headline\">Setup Credentials for Provisioning<br>&nbsp;</td></tr>");
        s.append ("<tr><td align=\"center\">To be implemented...</td></tr>");
        s.append ("</table>").
          append (createFooter ());
/*
        append ("<table><form method=\"POST\" action=\"").append (request.getRequestURL().toString ()).append ("\">" +
                "<tr><td align=\"center\" colspan=\"2\" class=\"headline\">2. Add Claims</td></tr>" +
                "<tr><td align=\"center\" colspan=\"2\" height=\"7\"></td></tr>");
        if (error)
          {
            s.append ("<tr><td align=\"center\" colspan=\"2\"><font color=\"red\"><b>Please specify at least one claim!</b><br>&nbsp;</font/></td></tr>");
          }
        for (ClaimType ct : ClaimType.values ())
          {
            s.append ("<tr align=\"left\"><td>").append (ct.getDisplayTag ()).
              append ("</td><td><input type=\"text\" name=\"").
              append (ct.toString ()).append ("\"></td></tr>");
          }
        s.append ("<tr><td align=\"center\" colspan=\"2\" height=\"7\"></td></tr>" +
                  "<tr><td align=\"center\" colspan=\"2\"><input type=\"submit\" value=\"Create and Download InfoCard\">" +
                  "</td></tr></form></table>").
          append (createFooter ());
*/
        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }

    public void protectedPost (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        InfoCardWriter icw = new InfoCardWriter ((X509Certificate) session.getAttribute (ProtectedServlet.CERTIFICATE),
                                                 TokenType.SAML_1_0,
                                                 "http://arport2/1234567",
                                                 "http://arport2",
                                                 "https://arport2/webpki/infocard/tokenservice",
                                                 "https://arport2/webpki/infocard/metadata");
        boolean empty = true;
        for (ClaimType ct : ClaimType.values ())
          {
            String claim = request.getParameter (ct.toString ());
            if (claim != null && (claim = claim.trim ()).length () > 0)
              {
                icw.addClaim (ct, claim);
                empty = false;
              }
          }
        if (empty)
          {
            printPage (request, response, true);
            return;
          }
        icw.setDisplayCredentialHint ("Insert smart card")
           .setCardName ("WebPKI.org")
           .setCardImage (getFile ("images/logo.gif"))
           .setTimeIssued (new Date ())
//           .setRequireAppliesTo (false)
           .setOutputSTSIdentity (false)
//           .setPrivacyNotice ("http://example.com/priv")
;

        byte[] data = icw.getInfoCard (getTLSCertificateSignatureKey (getServletContext ()));
        response.setContentType ("application/x-mscardfile");
        response.setHeader ("Content-Disposition", "inline; filename=infocard.crd");
        response.getOutputStream ().write (data);
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        printPage (request, response, false);
      }
  }
