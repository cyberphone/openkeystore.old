package misc;

import java.io.IOException;

import java.security.GeneralSecurityException;

import javax.crypto.Mac;

import javax.crypto.spec.SecretKeySpec;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.CallableStatement;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.util.HTMLHeader;
import org.webpki.util.HTMLEncoder;

import org.webpki.util.DebugFormatter;

import org.webpki.crypto.MacAlgorithms;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;


@SuppressWarnings("serial")
public class MiscOTPAuth extends ProtectedServlet
  {
    public static final String COMMON_HOTP_DEMO_SECRET = "3132333435363738393031323334353637383930";

    class HOTP
      {
        String information;

        private String getHOTPValue (long input) throws IOException, GeneralSecurityException
          {
            byte[] data = new byte[8];
            for (int i = 7; i >= 0; i--)
              {
                data[i] = (byte) (input & 0xff);
                input >>= 8;
              }
            Mac mac = Mac.getInstance (MacAlgorithms.HMAC_SHA1.getJCEName ());
            mac.init (new SecretKeySpec (DebugFormatter.getByteArrayFromHex (COMMON_HOTP_DEMO_SECRET), "RAW"));  // Note: any length is OK in HMAC
            byte[] hash = mac.doFinal (data);
            int offset = hash[hash.length - 1] & 0xf;
            int binary = ((hash[offset]     & 0x7f) << 24)
                       | ((hash[offset + 1] & 0xff) << 16)
                       | ((hash[offset + 2] & 0xff) <<  8)
                       |  (hash[offset + 3] & 0xff);
            String result = String.valueOf (binary % 100000000);
            while (result.length () < 8)
              {
                result = "0" + result;
              }
            return result;
          }

        boolean validate (String login_id, String otp) throws IOException
          {
            information = null;
            boolean success = false;
            login_id = login_id.trim ().toUpperCase ();
            if (login_id.length () != 7 || login_id.indexOf ('C') != 0)
              {
                return false;
              }
            login_id = login_id.substring (1);
            for (int i = 0; i < login_id.length (); i++)
              {
                if (login_id.charAt (i) > '9' || login_id.charAt (i) < '0')
                  {
                    return false;
                  }
              }
            if (otp == null)
              {
                ProtectedServlet.bad ("OTP is \"null\"");
              }
            otp = otp.trim ();
            try
              {
                Connection conn = getDatabaseConnection ();
                CallableStatement stmt = conn.prepareCall ("{call GetOTPCounterSP(?, ?)}");
                stmt.setString (1, login_id);
                stmt.registerOutParameter (2, java.sql.Types.INTEGER);
                stmt.execute ();
                int counter = stmt.getInt (2);
                stmt.close ();
                if (counter >= 0)
                  {
                    for (int i = -1; i < 20; i++)
                      {
                        if (getHOTPValue (counter + i).equals (otp))
                          {
                            if (i < 0)
                              {
                                information = " Already used OTP";
                              }
                            else
                              {
                                if (i > 0)
                                  {
                                    information = " Stepped " + i + " postions";
                                  }
                                stmt = conn.prepareCall ("{call SetOTPCounterSP(?, ?)}");
                                stmt.setString (1, login_id);
                                stmt.setInt (2, counter + i + 1);
                                stmt.execute ();
                                stmt.close ();
                                success = true;
                              }
                            break;
                          }
                      }
                  }
                conn.close ();
              }
            catch (SQLException sqle)
              {
                ProtectedServlet.bad (sqle.getMessage ());
              }
            catch (GeneralSecurityException gse)
              {
                ProtectedServlet.bad (gse.getMessage ());
              }
            return success;
          }
        

        public String getInformation (String original)
          {
            return information == null ? original : original + information;
          }

      }


    protected KeyCenterCommands getCommand ()
      {
        return null;
      }


    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        String login_id = request.getParameter ("init");
        String error = null;
        String success = null;
        if (login_id == null)
          {
            if (login_id == null)
              {
                login_id = "";
              }
            login_id = request.getParameter ("login_id");
            HOTP otp = new HOTP ();
            if (otp.validate (login_id, request.getParameter ("pwd")))
              {
                success = otp.getInformation ("Authentication Successful.");
              }
            else
              {
                error = otp.getInformation ("Failed to authenticate!");
              }
          }
        StringBuffer s = HTMLHeader.createHTMLHeader (true, true, "OTP Authentication", null);
        s.append ("<body><img src=\"images/mini_banklogo.gif\" style=\"position:absolute;top:10px;left:10px\"><table width=\"100%\" height=\"100%\" cellpadding=\"0\" cellspacing=\"0\" border=\"0\" style=\"position:absolute;z-index:5\">" +
                  "<tr><td align=\"center\" valign=\"middle\"><form method=\"GET\" action=\"").
          append (request.getRequestURL ().toString ()).
          append ("\"><table><tr><td align=\"center\" colspan=\"2\"><b>Test App: Login with OTP</b><br>&nbsp;</td></tr>");
        if (error != null)
          {
            s.append ("<tr><td align=\"center\" colspan=\"2\">").
              append (errorMessage (error)).
              append ("</td></tr><tr><td colspan=\"2\" height=\"5\"></td></tr>");
          }
        if (success != null)
          {
            s.append ("<tr><td align=\"center\" colspan=\"2\">").
              append (infoMessage (success)).
              append ("</td></tr><tr><td colspan=\"2\" height=\"5\"></td></tr>");
          }
        s.append ("<tr><td align=\"right\">Login ID&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"text\" tabindex=\"1\" name=\"login_id\" size=\"10\" value=\"").
          append (HTMLEncoder.encode (login_id)).
          append ("\" style=\"background-color:" + COLOR_INACTIVE + "\"");
        s.append ("></td></tr>" +
                  "<tr><td align=\"right\">Password&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"text\" tabindex=\"2\" name=\"pwd\" size=\"10\" " +
                  "style=\"background-color:" +
                  COLOR_INACTIVE + "\"");
        s.append ("></td></tr>" +
                  "<tr><td colspan=\"2\" height=\"10\"></td></tr>" +
                  "<tr><td align=\"center\" colspan=\"2\" height=\"10\"><input type=\"submit\" value=\"Login\"></td></tr>" +
                  "</table></form></td></tr></table></body></html>");

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
