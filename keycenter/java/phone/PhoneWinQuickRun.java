package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@SuppressWarnings("serial")
public class PhoneWinQuickRun extends PhoneWinServlet
  {
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {

        StringBuffer s = createHeader ("QuickRun - Step #1").
          append ("<form name=\"shoot\" method=\"GET\" action=\"phonewinauthentication\">" +
                  "<input type=\"hidden\" name=\"staged\" value=\"true\">").
          append (divSection (50, 300)).
          append ("<table cellpadding=\"2\" cellspacing=\"0\">" +
                  "<tr><td align=\"center\"><img src=\"images/keygen2.gif\"></td></tr>" +
                  "<tr><td height=\"10\"></td></tr>" +
                  "<tr><td>Welcome!<br>&nbsp;<br>This is a demo tour using the actual KeyGen2 protocol but slightly \"staged\" to " +
                  "eliminiate menu choices, logins etc.</td></tr>" +
                  "<tr><td height=\"10\"></td></tr>" +
                  "<tr><td align=\"center\"><input type=\"button\" name=\"ok\" value=\"Run!\" onclick=\"this.disabled=true;document.forms.shoot.submit()\"></td></tr>" +
                  "</table></div></form>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
