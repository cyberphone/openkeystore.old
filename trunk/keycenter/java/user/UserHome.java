package user;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;


@SuppressWarnings("serial")
public class UserHome extends ProtectedServlet
  {
    public static final String ATTENTION = "ATT";

    protected KeyCenterCommands getCommand ()
      {
        return null;
      }

    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        StringBuffer s = createHeader (request).
          append ("<table><tr><td align=\"center\" class=\"headline\">Welcome to Universal Provisioning!<br>&nbsp;</td></tr>");
        String err = request.getParameter (ATTENTION);
        if (err != null)
          {
            s.append ("<tr><td align=\"center\">").
              append (errorMessage (err)).
              append ("</td></tr>");
          }
        else
          {
            s.append ("<tr><td align=\"center\"><table width=\"500\"><tr><td align=\"left\">The purpose of this site is providing developers and other "+
                      "interested parties with documentation, source code, binaries, and on-line test facilities for a standards proposal called KeyGen2, also known " +
                      "as &quot;Universal Provisioning&quot;.&nbsp; What is that?&nbsp; " +
                      "Well, quoting a typical marketing department the message would probably go something like: " +
                      "<i>&quot;The ability to securely and conveniently, provision and managing all the authentication, " +                      "signature and encryption keys a consumer, " +
                      "citizen, or employee may ever need - Any organization, any technology&quot;</i> " +
                      "which BTW is almost true ;-)</td></tr>" +
                      "<tr><td height=\"10\"></td></tr>" +
                      "<tr><td align=\"center\" class=\"headline\">Why select when you can have it all?</td></tr>" +
                      "<tr><td height=\"10\"></td></tr>" +
                      "<tr><td align=\"center\"><img title=\"and always use the authentication method most suited for the actual application...\" " +
                      "src=\"images/credentials.gif\" width=\"350\" height=\"56\"></td></tr>" +
                      "<tr><td height=\"10\"></td></tr>" +
                      "<tr><td align=\"left\">For you die-hard engineers it may be more appropriate " +
                      "just listing the core ingredients in this soup: XML, PKI, OTP, PIN, PUK, InformationCards, TPM, MIME, HTTP, and SQL :-)<p>" +
                      "Now, for the real information, please take a peek in the &quot;").
              append (KeyCenterCommands.RESOURCES.getButtonText ()).
              append ("&quot; section.&nbsp; Enjoy!<p>/The WebPKI.org team</td></tr></table></td></tr>");
          }
        s.append ("</table>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());

      }
  }
