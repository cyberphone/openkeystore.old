package admin;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;


@SuppressWarnings("serial")
public class AdminMain extends ProtectedServlet
  {
    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.ADMINISTRATION;
      }


    protected boolean adminPriviledgesRequired ()
      {
        return true;
      }


    void alink (StringBuffer s, String url, String description)
      {
        s.append ("<tr><td align=\"center\"><a href=\"").append (url).append ("\">").append (description).append ("</a></td></tr>");
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        StringBuffer s = createHeader (request).
          append ("<table><tr><td align=\"center\" class=\"headline\">Administration<br>&nbsp;</td></tr>");
        String adm_message = (String) session.getAttribute (SESS_ADMIN_MESSAGE);
        if (adm_message != null)
          {
            s.append ("<tr><td align=\"center\">").
              append (infoMessage (adm_message)).
              append ("</td></tr><tr><td>&nbsp;</td></tr>");
            session.setAttribute (SESS_ADMIN_MESSAGE, null);
          }
        alink (s, "adm_impersonate_user", "Impersonate User");
        alink (s, "adm_delete_user", "Delete User");
        alink (s, "adm_create_user", "Create User");
        alink (s, "adm_reset_user_pwd", "Reset User Password");
        alink (s, "adm_list_users", "List Users");
        alink (s, "adm_set_availability", "Set System Availability");
        s.append ("</table>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
