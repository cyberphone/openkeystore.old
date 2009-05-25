package user;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webutil.ServletUtil;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;


@SuppressWarnings("serial")
public class UserChangePassword extends ProtectedServlet
  {
    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.USER_ACCOUNT;
      }


    protected String onLoadArgument ()
      {
        return "fixme ()";
      }


    public void protectedPost (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        ParseUserData parser = new ParseUserData (request);
        String pwd = parser.getDoublePassword ();
        if (parser.success ())
          {
            try
              {
                Connection conn = getDatabaseConnection ();
                PreparedStatement pstmt = conn.prepareStatement ("UPDATE USERS SET Password=? WHERE UserID=?");
                pstmt.setString (1, pwd);
                pstmt.setInt (2, getUserID (session));
                pstmt.executeUpdate ();
                pstmt.close ();
                conn.close ();
                session.setAttribute (SESS_ADMIN_MESSAGE, "Password was successfully changed");
                response.sendRedirect (ServletUtil.getContextURL (request) + "/" + KeyCenterCommands.USER_ACCOUNT.getServletName ());
                return;
              }
            catch (SQLException e)
              {
                bad (e.getMessage ());
              }
          }
        print (request, response, parser.getError ());
      }


    public void print (HttpServletRequest request, HttpServletResponse response, String error) throws IOException, ServletException
      {
        StringBuffer s = createHeader (request,
                "function fixme ()\n" +
                "{\n" +
                "  if (document.all == null) // FF, Opera, etc\n" +
                "    {\n" +
                "      if (document.getElementById ('pwd1') != null) document.getElementById ('pwd1').focus ();\n" +
                "    }\n" +
                "  else // MSIE 6+\n" +
                "    {\n" +
                "      if (document.all.pwd1 != null) document.all.pwd1.focus ();\n" +
                "     }\n" +
                "}\n");

        s.append ("<form method=\"POST\" action=\"").
          append (request.getRequestURL ().toString ()).
          append ("\"><table width=\"450\">" +
                  "<tr><td colspan=\"2\" align=\"center\" class=\"headline\">Change Password<br>&nbsp;</td></tr>");

        if (error != null)
          {
            s.append ("<tr><td align=\"center\" colspan=\"2\">").
              append (errorMessage (error)).
              append ("</td></tr><td>&nbsp;</td></tr>");
          }

        s.append ("<tr><td align=\"right\">Password&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"password\" id=\"pwd1\" name=\"pwd1\" size=\"20\" " +
                  "tabindex=\"1\" style=\"background-color:" + COLOR_INACTIVE + "\"></td></tr>" +
                  "<tr><td align=\"right\">Repeat password&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"password\" name=\"pwd2\" size=\"20\" " +
                  "tabindex=\"2\" style=\"background-color:" + COLOR_INACTIVE + "\"></td></tr>" +
                  "<tr><td colspan=\"2\">&nbsp;</td></tr>" +
                  "<tr><td colspan=\"2\" align=\"center\"><input title=\"Change Password!\" type=\"submit\" " +
                  "value=\"Update\"></td></tr></table></form>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        print (request, response, null);
      }

  }
