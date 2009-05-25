package phone;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@SuppressWarnings("serial")
public class PhoneWinDemoApplications extends PhoneWinServlet
  {
    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        StringBuffer s = createHeader ("Demo/Test Apps", PhoneWinOTP.LAUNCH_BANK_OTP_JS).
          append (divSection ()).
          append ("<table cellpadding=\"2\" cellspacing=\"0\">" +
                  "<tr><td><a href=\"javascript:").
          append (PhoneWinOTP.getLaunchBankOTPLoginURL (request, session)).
          append ("\">Login with OTP</a></td></tr>" +
                  "</table></div>").
          append (createFooter ("phonewinhome"));

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
