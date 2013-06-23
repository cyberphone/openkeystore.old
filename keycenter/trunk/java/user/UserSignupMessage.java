package user;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;


@SuppressWarnings("serial")
public class UserSignupMessage extends ProtectedServlet
  {
    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.REGISTER;
      }


    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        String email = request.getParameter ("email");
        StringBuffer s = createHeader (request).
          append ("<table width=\"450\">" +
                  "<tr><td align=\"center\" class=\"headline\">Account Verification<br>&nbsp;</td></tr>" +
                  "<tr><td align=\"center\">").
          append (infoMessage ("In order to verify the <nobr>e-mail</nobr> address <b>" + email +
                                  "</b> a message has been sent to you which contains an URL that " +
                                 "if clicked on will activate the account.&nbsp; The account must " +
                                 "be activated within " + SIGNUP_MAX_DAYS + " days.")).
          append ("</td></tr></table>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }

  }
