package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@SuppressWarnings("serial")
public class PhoneWinInformationCards extends PhoneWinServlet
  {
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {

        StringBuffer s = createHeader ("Information Cards").
          append (divSection ()).
          append ("<table cellpadding=\"2\" cellspacing=\"0\">" +
                  "<tr><td>Not yet implemented...</td></tr>" +
                  "<tr><td height=\"10\"></td></tr>" +
                  "<tr><td align=\"center\"><img src=\"images/infocard_60x42.gif\"></td></tr>" +
                  "</table></div>").
          append (createFooter ("phonewinsecurity"));

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
