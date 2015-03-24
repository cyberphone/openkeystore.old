package user;

import java.io.IOException;

import java.sql.SQLException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;
import admin.AdminDeleteUser;


@SuppressWarnings("serial")
public class UserUnregister extends ProtectedServlet
  {
    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.REGISTER;
      }


    public void protectedPost (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        try
          {
            if (AdminDeleteUser.delete (getEmailAddress (request)))
              {
                session.invalidate ();
                response.sendRedirect (getHomeURL (request));
                return;
              }
            bad ("Unregister failed for unknown reasons!");
          }
        catch (SQLException e)
          {
            bad (e.getMessage ());
          }
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        StringBuffer s = createHeader (request).
          append ("<form method=\"POST\" action=\"").
          append (request.getRequestURL ().toString ()).append ("\">" +
                  "<table width=\"450\"><tr><td align=\"center\" class=\"headline\">Unregister Logged In User<br>&nbsp;</td></tr>" +
                  "<tr><td align=\"center\">").
          append (infoMessage ("This operation will remove <i>all</i> data associated with this login.&nbsp; " +
                  "If you do not want to procede, just click on any of the menu buttons to the left.")).
          append ("</td></tr><tr><td>&nbsp;</td></tr>" +
                  "<tr><td align=\"center\"><input type=\"submit\" title=\"Goodbye, we hoped that you liked KeyGen2!\" value=\"Delete Me Now!\"></td></tr>" +
                  "</table></form>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }

  }
