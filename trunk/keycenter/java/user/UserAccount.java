package user;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;


@SuppressWarnings("serial")
public class UserAccount extends ProtectedServlet
  {
    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.USER_ACCOUNT;
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        StringBuffer s = createHeader (request).
          append ("<table><tr><td align=\"center\" class=\"headline\">User Account<br>&nbsp;</td></tr>");
        String adm_message = (String) session.getAttribute (SESS_ADMIN_MESSAGE);
        if (adm_message != null)
          {
            s.append ("<tr><td align=\"center\">").
              append (infoMessage (adm_message)).
              append ("</td></tr><tr><td>&nbsp;</td></tr>");
            session.setAttribute (SESS_ADMIN_MESSAGE, null);
          }
        s.append ("<tr><td align=\"center\"><table>" +
                  "<tr><td><a href=\"changepwd\">Change Password...</a></td></tr>" +
                  "<tr><td><a href=\"resetacc\">Reset Account Detail...</a></td></tr>" +
                  "<tr><td><a href=\"kg2_init\">Start KeyGen2!</a></td></tr>" +
                  "</table></td></tr></table>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
