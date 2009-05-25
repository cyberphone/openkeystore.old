package user;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.CallableStatement;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webutil.ServletUtil;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;
import phone.PhoneDebugWin;


@SuppressWarnings("serial")
public class UserResetAccount extends ProtectedServlet
  {
    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.USER_ACCOUNT;
      }


    private static void resetObject (HttpSession session, String stored_procedure) throws IOException
      {
        try
          {
            Connection conn = getDatabaseConnection ();
            CallableStatement stmt = conn.prepareCall ("{call " + stored_procedure + "(?)}");
            stmt.setInt (1, getUserID (session));
            stmt.execute ();
            conn.close ();
          }
        catch (SQLException e)
          {
            bad (e.getMessage ());
          }
      }

    public static void clearOTPCounters (HttpSession session) throws IOException
      {
        resetObject (session, "DeleteIssuedCredentialsSP");
      }

    public void protectedPost (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        String what = request.getParameter ("what");
        String message = "Phone user keys were successfully reset";
        if (what == null)
          {
            bad ("Missing radio button!");
          }
        if (what.equals ("user"))
          {
            resetObject (session, "DeleteUserKeysSP");
          }
        else if (what.equals ("device"))
          {
            message = "Device master clear";
            resetObject (session, "DeletePhoneKeysSP");
          }
        else
          {
            message = "OTP counters were successfully reset";
            clearOTPCounters (session);
          }
        PhoneDebugWin.clearDebugWin (session);
        session.setAttribute (SESS_ADMIN_MESSAGE, message);
        response.sendRedirect (ServletUtil.getContextURL (request) + "/" + KeyCenterCommands.USER_ACCOUNT.getServletName ());
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        StringBuffer s = createHeader (request);

        s.append ("<form method=\"POST\" action=\"").
          append (request.getRequestURL ().toString ()).
          append ("\"><table width=\"450\">" +
                  "<tr><td align=\"center\" class=\"headline\">Reset Account Detail<br>&nbsp;</td></tr>" +
                  "<tr><td align=\"center\"><table>" +
                  "<tr align=\"left\"><td><input type=\"radio\" checked name=\"what\" value=\"user\" " +
                  "tabindex=\"1\"></td><td>&nbsp;Phone Emulator User Keys</td></tr>" +
                  "<tr align=\"left\"><td><input type=\"radio\" name=\"what\" value=\"issued\" " +
                  "tabindex=\"2\"></td><td>&nbsp;OTP Counters</td></tr>" +
                  "<tr align=\"left\"><td><input type=\"radio\" name=\"what\" value=\"device\" " +
                  "tabindex=\"3\"></td><td>&nbsp;Entire Device</td></tr>" +
                  "</table></td></tr>" +
                  "<tr><td>&nbsp;</td></tr>" +
                  "<tr><td align=\"center\"><input title=\"Reset (Clear) Selected Account Details\" type=\"submit\" " +
                  "value=\"Reset\"></td></tr></table></form>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }

  }
