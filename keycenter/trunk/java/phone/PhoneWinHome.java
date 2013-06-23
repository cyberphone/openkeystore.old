package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@SuppressWarnings("serial")
public class PhoneWinHome extends PhoneWinServlet
  {
    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {

        StringBuffer s = createHeader ("Home").
          append (divSection ()).
          append ("<table cellpadding=\"2\" cellspacing=\"0\">" +
                  "<tr><td><a href=\"phonewinapps\">Demo Applications</a></td></tr>" +
                  "<tr><td><a href=\"phonewinsecurity\">Security</a></td></tr>" +
/*
                  "<tr><td><a href=\"phonewindemoapps\">Demo/Test Applications</a></td></tr>" +
                  "<tr><td><a href=\"phonewinsignreq\">Signature Request</a></td></tr>" +
*/
                  "<tr><td><a href=\"phonewinquickrun\">QuickRun!</a></td></tr>" +
                  "<tr><td height=\"10\"></td></tr>" +
                  "<tr><td>This is a mobile phone emulator that is pre-programmed for testing and demonstrating WASP, WebAuth, OTP, PKI, Information Cards, and most of all, KeyGen2.</td></tr>" +
                  "</table></div>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
