package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import misc.Init;


@SuppressWarnings("serial")
public class PhoneWinSendMail extends PhoneWinServlet
  {
    public void protectedPost (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        request.setCharacterEncoding ("UTF-8");

        Init.sendPhoneMail (request.getParameter ("email"),
                            getEmailAddress (request),
                            request.getParameter ("msg"));

        StringBuffer s = createHeader ("Message Sent").
          append (divSection ()).
          append ("Note: the validity of the e-mail address is not checked but " +
                  "the if it was correct the message should pop up in the recepient's "+
                  "phone.<p>Please wait 10-20 seconds for a message to be delivered!</div>").
          append (createFooter ("phonewinapps"));

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }

    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        String msg = request.getParameter ("msg");
        if (msg == null)
          {
            msg = "";
          }
        StringBuffer s = createHeader ("Send Mail Message").
          append ("<form method=\"POST\" action=\"").
          append (request.getRequestURL ().toString ()).
          append ("\">").
          append (divSection ()).
          append ("<table cellpadding=\"0\" cellspacing=\"0\">" +
                  "<tr><td>Recepient:</td></tr>" +
                  "<tr><td height=\"2\"></td></tr>" +
                  "<tr><td><input type=\"text\" size=\"30\" name=\"email\"></td></tr>" +
                  "<tr><td height=\"10\"></td></tr>" +
                  "<tr><td>Message:</td></tr>" +
                  "<tr><td height=\"2\"></td></tr>" +
                  "<tr><td><textarea style=\"word-wrap:break-word;overflow:hidden;margin:0px;width:" + 
                      (SCREEN_WIDTH - 14) + "px;height:100px;font-weight:normal;font-size:8pt\" name=\"msg\">").
          append (msg).
          append ("</textarea></td></tr>" +
                  "<tr><td height=\"10\"></td></tr>" +
                  "<tr><td align=\"center\"><input type=\"submit\" value=\"Send!\"></td></tr>" +
                  "</table></div></form>").
          append (createFooter ("phonewinapps"));

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
