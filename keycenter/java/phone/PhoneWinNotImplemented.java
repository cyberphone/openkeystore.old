package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@SuppressWarnings("serial")
public class PhoneWinNotImplemented extends PhoneWinServlet
  {
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {

        StringBuffer s = createHeader ("Not Implemented").
          append (divSection ()).
          append ("<table><tr><td>").
          append (request.getParameter ("what")).
          append ("</td></tr>" +
                  "</table></div>").
          append (createFooter (request.getParameter ("back")));

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
