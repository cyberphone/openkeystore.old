package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webutil.ServletUtil;


@SuppressWarnings("serial")
public class PhoneWinApplications extends PhoneWinServlet
  {
    void notImplemented (StringBuffer s, String app)
      {
        s.append ("<tr><td><a href=\"phonewinnotimpl?back=phonewinapps&what=In+this+emulator+only+authentication+related+applications+have+been+implemented!\">").
          append (app).
          append ("</a></tr></td>");
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        setQuickRunFlag (session, null);
        StringBuffer s = createHeader ("Demo Applications", PhoneWinOTP.LAUNCH_BANK_OTP_JS).
          append (divSection ()).
          append ("<table cellpadding=\"2\" cellspacing=\"0\">" +
                  "<tr><td><a href=\"phonewinotp?init=true\">OTP (One Time Password)</a></td></tr>" +
                  "<tr><td><a href=\"javascript:").
          append (PhoneWinOTP.getLaunchBankOTPLoginURL (request, session)).
          append ("\">Login to a Bank with OTP</a></td></tr>" +
                  "<tr><td><a href=\"phonewinauthentication\">Autologin to KeyGen2</a></td></tr>" +
                  "<tr><td><a href=\"").
          append (PhoneWinProxy.createProxyURL (request, ServletUtil.getContextURL (request) + "/kg2_login")).
          append ("\">Manual Login to KeyGen2</a></td></tr>" +
                  "<tr><td><a href=\"phonewinsendmail\">Send Mail</a></td></tr>");
        notImplemented (s, "Calendar");
        notImplemented (s, "IM");
        notImplemented (s, "Games");
        s.append ("</table></div>").
          append (createFooter ("phonewinhome"));

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
