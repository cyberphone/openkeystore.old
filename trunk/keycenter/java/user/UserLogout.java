package user;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;


@SuppressWarnings("serial")
public class UserLogout extends ProtectedServlet
  {
    protected KeyCenterCommands getCommand ()
      {
        return null;
      }

    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {

        String user = getEmailAddress (request);
        if (user == null)
          {
            response.sendRedirect (getHomeURL (request));
            return;  // Session already dead...
          }

        request.getSession ().invalidate ();  // Just forget it all

        StringBuffer s = createHeader (request).
          append ("<table cellpadding=\"0\" cellspacing=\"0\" border=\"0\">" +
                  "<tr><td align=\"center\">Welcome back<b> ").
          append (user).
          append ("!</b></td></tr></table>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
