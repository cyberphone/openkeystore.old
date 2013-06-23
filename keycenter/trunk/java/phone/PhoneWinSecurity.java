package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@SuppressWarnings("serial")
public class PhoneWinSecurity extends PhoneWinServlet
  {
    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {

        StringBuffer s = createHeader ("Security").
          append (divSection ()).
          append ("<table cellpadding=\"2\" cellspacing=\"0\">" +
                  "<tr><td><a href=\"phonewinkeyexplorer\">Key Explorer</a></td></tr>" +
                  "<tr><td><a href=\"phonewininfocards\">Information Cards</a></td></tr>" +
                  "<tr><td><a href=\"phonewinseproperties\">Security Element</a></td></tr>");
        if (internalApps (getServletContext ()))
          {
            s.append ("<tr><td><a href=\"phonewincardsel\">Card Selector</a> NOT READY!</td></tr>");
            s.append ("<tr><td><a href=\"phonewinjcetest\">JCE TEST</a> NOT READY!</td></tr>");
          }
        s.append ("</table></div>").append (createFooter ("phonewinhome"));

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
