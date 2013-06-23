package phone;

import java.io.IOException;

import java.text.NumberFormat;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.keygen2.KeyGen2URIs;

import org.webpki.webutil.ServletUtil;

import org.webpki.sks.OTPProvider;
import org.webpki.sks.KeyDescriptor;
import org.webpki.sks.Logotype;

import misc.ProtectedServlet;


@SuppressWarnings("serial")
public class PhoneWinOTP extends PhoneWinServlet
  {
    static final String LAUNCH_BANK_OTP_JS = 
                  "function launchotp (url)\n" +
                  "{\n" +
                  "  window.open (url,'otp','top=0,left=0,width=400,height=250,resizable=yes,scrollbars=no,toolbar=no,menubar=no,location=no,status=no');\n" +
                  "  location.href='phonewinotp?init=true';\n" +
                  "}\n";

    static String getLaunchBankOTPLoginURL (HttpServletRequest request, HttpSession session) throws IOException
      {
        NumberFormat nf = NumberFormat.getInstance ();
        nf.setMinimumIntegerDigits (6);
        nf.setGroupingUsed (false);
        return "launchotp ('" + ServletUtil.getContextURL (request) + "/misc_otpauth?init=C" + nf.format (ProtectedServlet.getUserID (session)) + "')";
      }


    static OTPProvider getOTPProvider (HttpSession session) throws IOException
      {
        OTPProvider[] otps = OTPProvider.getOTPProviders (getSKS (session), null, OTPProvider.OTP_TYPES.EVENT);
        return otps == null ? null : otps[0];
      }

    static final String OTP_PIN = "OTP_PIN";


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        StringBuffer s = createHeader ("One Time Password");        OTPProvider otp_prov = getOTPProvider (session);        if (otp_prov == null)          {            s.append (divSection (100, SCREEN_HEIGHT)).              append ("You have not provisioned any OTP keys yet.&nbsp; Try QuickRun!</div>");
          }        else          {
            KeyDescriptor kd = otp_prov.getKeyDescriptor ();

            /*======================================================*/
            /* An issuer application logotype is nice but optional. */
            /*======================================================*/
            Logotype logotype = kd.getLogotype (KeyGen2URIs.LOGOTYPES.APPLICATION);
            if (logotype == null)
              {
                logotype = Logotype.getDefaultLogotype (KeyGen2URIs.LOGOTYPES.APPLICATION);
              }
            PhoneWinResource.clearResourceList (session);
            String url = PhoneWinResource.addResource (session, logotype.getData (), logotype.getMimeType ());

            /*======================================================*/
            /* Since this is a web-application the built-in PIN GUI */
            /* is not applicable.  The following is an "emulation"  */
            /* of "the real thing".  Note that this implementation  */
            /* assumes that it is OK to cache PINs for a limited    */
            /* time which ultmately should be specified by a        */
            /* provisioning property and NOT hardcoded into the OTP */
            /* application!                                         */
            /*======================================================*/

            /*======================================================*/
            /* This implementation uses a single FORM for state-    */
            /* keeping and navigation.                              */
            /*======================================================*/
            s.append ("<form name=\"shoot\" method=\"GET\" action=\"").
              append (request.getRequestURL ().toString ()).
              append ("\">");

            /*======================================================*/
            /* The first time the OTP application is called, any    */
            /* stored PIN must be cleared.                          */
            /*======================================================*/
            if (request.getParameter ("init") != null)
              {
                session.setAttribute (OTP_PIN, null);
              }

            /*======================================================*/
            /* If there was a session PIN or supplied PIN we assume */
            /* that we are in OTP generate/display mode.            */
            /*======================================================*/
            String pin = null;
            boolean pin_failure = false;
            if ((pin = request.getParameter ("pin")) != null ||
                (pin = (String) session.getAttribute (OTP_PIN)) != null)
              {
                pin = pin.trim ();
                session.setAttribute (OTP_PIN, pin);
              }
            else
              {
                kd = otp_prov.getKeyDescriptor ();
                pin_failure = true;
              }
// TODO not ready all, open removed...

            /*======================================================*/
            /* If there was no PIN or it didn't work we present a   */
            /* PIN dialog to the user, else we are in OTP mode.     */
            /*======================================================*/
            if (pin == null)
              {
                addPINDialog (s, kd, pin_failure);
              }
            else
              {
                String otp_value = otp_prov.generate ();
                s.append (divSection (190, SCREEN_HEIGHT)).
                  append ("<table align=\"center\" cellpadding=\"0\" cellspacing=\"0\">" +
                          "<tr><td align=\"center\"><img src=\"phonewinotpdisplay?value=").
                  append (otp_value).
                  append ("\" width=\"").
                  append (PhoneWinOTPDisplay.getWidth (otp_value)).
                  append ("\" height=\"" + 
                          (PhoneWinOTPDisplay.BACK_IMAGE_HEIGHT + PhoneWinOTPDisplay.PASSWORD_HEIGHT) +
                          "\" title=\"This is it!\"></td></tr>" +
                          "<tr><td height=\"15\"></td></tr>" +
                          "<tr><td align=\"center\"><input type=\"submit\" value=\"" +
                          "Next Password\" title=\"Please get me a new cool password!\"></td></tr></table></div>");
              }

            /*======================================================*/
            /* In the OTP aplication we always show a logotype.     */
            /*======================================================*/
            s.append (divSection (60, 100)).
              append ("<table align=\"center\" cellpadding=\"0\" cellspacing=\"0\">" +
                      "<tr><td align=\"center\"><img src=\"").
              append (url).
              append ("\" title=\"Issuer logotype\"></td></tr></table></div></form>");          }
        s.append (createFooter ("phonewinapps"));
        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
