package admin;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webutil.ServletUtil;

import org.webpki.util.HTMLEncoder;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;


@SuppressWarnings("serial")
public class AdminResetUserPassword extends ProtectedServlet
  {
    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.ADMINISTRATION;
      }


    protected boolean adminPriviledgesRequired ()
      {
        return true;
      }


    protected String onLoadArgument ()
      {
        return "fixme ()";
      }


    public void protectedPost (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        ParseUserData parser = new ParseUserData (request);
        String email = parser.getLoginID ();
        String pwd = parser.getDoublePassword ();
        if (parser.success ())
          {
            try
              {
                Connection conn = getDatabaseConnection ();
                PreparedStatement pstmt = conn.prepareStatement ("SELECT UserID FROM USERS WHERE Email=?");
                pstmt.setString(1, email);
                ResultSet rs = pstmt.executeQuery ();
                boolean found = rs.next ();
                rs.close ();
                pstmt.close ();
                if (found)
                  {
                    pstmt = conn.prepareStatement ("UPDATE USERS SET Password=? WHERE Email=?");
                    pstmt.setString (1, pwd);
                    pstmt.setString (2, email);
                    pstmt.executeUpdate ();
                    pstmt.close ();
                    conn.close ();
                    session.setAttribute (SESS_ADMIN_MESSAGE, "Password for user <b>" + email + "</b> was set");
                    response.sendRedirect (ServletUtil.getContextURL (request) + "/" + KeyCenterCommands.ADMINISTRATION.getServletName ());
                    return;
                  }
                parser.setError ("No such user");
                conn.close ();
              }
            catch (SQLException e)
              {
                bad (e.getMessage ());
              }
          }
        print (request, response, email, parser.getError ());
      }


    public void print (HttpServletRequest request, HttpServletResponse response, String email, String error) throws IOException, ServletException
      {
        StringBuffer s = createHeader (request,
                "function fixme ()\n" +
                "{\n" +
                "  if (document.all == null) // FF, Opera, etc\n" +
                "    {\n" +
                "      if (document.getElementById ('uidfield') != null) document.getElementById ('uidfield').focus ();\n" +
                "    }\n" +
                "  else // MSIE 6+\n" +
                "    {\n" +
                "      if (document.all.uidfield != null) document.all.uidfield.focus ();\n" +
                "     }\n" +
                "}\n").
          append ("<form method=\"POST\" action=\"").
          append (request.getRequestURL ().toString ()).append ("\">" +
                  "<table><tr><td colspan=\"2\" align=\"center\" class=\"headline\">Reset User Password<br>&nbsp;</td></tr>");

        if (error != null)
          {
            s.append ("<tr><td align=\"center\" colspan=\"2\">").
              append (errorMessage (error)).
              append ("</td></tr><tr><td colspan=\"2\">&nbsp;</td></tr>");
          }

        s.append ("<tr><td align=\"right\">Email address&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"text\" id=\"uidfield\" name=\"email\" size=\"30\" " +
                  "tabindex=\"1\" value=\"").
          append (HTMLEncoder.encode (email)).
          append ("\" style=\"background-color:" + COLOR_INACTIVE + "\">" +
                  "</td></tr><tr><td align=\"right\">Password&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"password\" name=\"pwd1\" size=\"20\" " +
                  "tabindex=\"2\" style=\"background-color:" + COLOR_INACTIVE + "\">" +
                  "</td></tr><tr><td align=\"right\">Repeat password&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"password\" name=\"pwd2\" size=\"20\" " +
                  "tabindex=\"3\" style=\"background-color:" + COLOR_INACTIVE + "\"></td></tr>" +
                  "<tr><td colspan=\"2\">&nbsp;</td></tr>" +
                  "<tr><td colspan=\"2\" align=\"center\"><input type=\"submit\" value=\"Reset!\"></td></tr>" +
                  "</table></form>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        String email = "";
        print (request, response, email, null);
      }

  }
