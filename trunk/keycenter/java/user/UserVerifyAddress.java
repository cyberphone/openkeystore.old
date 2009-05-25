package user;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.CallableStatement;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webutil.ServletUtil;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;


@SuppressWarnings("serial")
public class UserVerifyAddress extends ProtectedServlet
  {
    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.REGISTER;
      }


    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        String inst = request.getParameter ("ID");
        String email = request.getParameter ("USER");
        String mac = request.getParameter ("HMAC");
        if (inst != null && email != null && mac != null && mac.equals (getSignupMac (inst, email)))
          {
            try
              {
                Connection conn = getDatabaseConnection ();
                CallableStatement stmt = conn.prepareCall ("{call ActivateAccountSP(?, ?, ?)}");
                stmt.registerOutParameter (1, java.sql.Types.BOOLEAN);
                stmt.setString (2, email);
                stmt.setInt (3, Integer.parseInt (inst));
                stmt.execute ();
                boolean found = stmt.getBoolean (1);            
                stmt.close ();
                conn.close ();
                if (found)
                  {
                    response.sendRedirect (ServletUtil.getContextURL (request) + "/login?email=" + email);
                    return;
                  }
              }
            catch (SQLException e)
              {
                bad (e.getMessage ());
              }
          }
        StringBuffer s = createHeader (request).
          append ("<table width=\"450\">" +
                  "<tr><td align=\"center\" class=\"headline\">Account Verification Failed!<br>&nbsp;</td></tr>" +
                  "<tr><td align=\"center\">").
          append (errorMessage ("Presumably your sign-up request has expired, or you "+
                  "have already succeed creating an account using this or another sign-up message instance.")).
          append ("</td></tr></table>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }

  }
