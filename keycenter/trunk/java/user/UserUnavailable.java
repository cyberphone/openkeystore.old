package user;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;
import admin.AdminSetAvailability;


@SuppressWarnings("serial")
public class UserUnavailable extends ProtectedServlet
  {
    protected KeyCenterCommands getCommand ()
      {
        return null;
      }


    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        StringBuffer s = createHeader (request);
        if (AdminSetAvailability.availability != null)
          {
            s.append ("<table width=\"450\">" +
                      "<tr><td align=\"center\" class=\"headline\">System Unavailable!<br>&nbsp;</td></tr>" +
                      "<tr><td align=\"center\">").
              append (errorMessage (AdminSetAvailability.availability)).
              append ("</td></tr></table>");
          }
        s.append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }

  }
