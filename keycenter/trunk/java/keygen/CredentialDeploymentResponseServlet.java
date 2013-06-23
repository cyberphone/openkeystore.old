package keygen;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.util.HTMLHeader;

import org.webpki.keygen2.CredentialDeploymentResponseDecoder;


@SuppressWarnings("serial")
public class CredentialDeploymentResponseServlet extends KeyGenServlet
  {

    public void protectedPost (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        CredentialDeploymentResponseDecoder decoder = (CredentialDeploymentResponseDecoder) getXMLObject (request);
        decoder.getServerSessionID();  // Just to do something...

        session.invalidate ();

        StringBuffer s = HTMLHeader.createHTMLHeader (true, true, "Success", null).
          append ("<body><table width=\"100%\" height=\"100%\"><tr><td align=\"center\" valign=\"middle\">" +
                  "<table><tr><td align=\"center\"><b>Successful Deployment</b></td></tr>" +
                  "<tr><td height=\"10\"></td></tr>" +
                  "<tr><td align=\"center\"><img src=\"images/mini_banklogo.gif\"></td></tr>" +
                  "<tr><td height=\"20\"></td></tr>" +
                  "<tr><td align=\"left\">Congratulations!&nbsp;  You now have a set of " +
                  "keys in your phone for usage with our on-line services.<br>&nbsp;<br>/MyBank team</td></tr>" +
                  "</table></td></tr></table></body></html>");

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
