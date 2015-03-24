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
public class AdminCreateUser extends ProtectedServlet
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
        String name = parser.getUserName ();
        String email = parser.getLoginID ();
        String pwd = parser.getDoublePassword ();
        if (parser.success ())
          {
            try
              {
                Connection conn = getDatabaseConnection ();
                PreparedStatement pstmt = conn.prepareStatement ("SELECT UserID FROM USERS WHERE Email=?");
                pstmt.setString (1, email);
                ResultSet rs = pstmt.executeQuery ();
                boolean found = rs.next ();
                rs.close ();
                pstmt.close ();
                if (found)
                  {
                    parser.setError ("User already exists");
                    conn.close ();
                  }
                else
                  {
                    pstmt = conn.prepareStatement ("INSERT INTO USERS (Password, Email, Name) VALUES (?, ?, ?)");
                    session.setAttribute (SESS_ADMIN_MESSAGE, "User <b>" + email + "</b> was created");
                    pstmt.setString(1, pwd);
                    pstmt.setString(2, email);
                    pstmt.setString(3, name);
                    pstmt.executeUpdate ();
                    pstmt.close ();
                    conn.close ();
                    response.sendRedirect (ServletUtil.getContextURL (request) + "/" + KeyCenterCommands.ADMINISTRATION.getServletName ());
                    return;
                  }
              }
            catch (SQLException e)
              {
                bad (e.getMessage ());
              }
          }
        print (request, response, name, email, parser.getError ());
      }


    public void print (HttpServletRequest request, HttpServletResponse response, String name, String email, String error) throws IOException, ServletException
      {
        StringBuffer s = createHeader (request,
                "function fixme ()\n" +
                "{\n" +
                "  if (document.all == null) // FF, Opera, etc\n" +
                "    {\n" +
                "      if (document.getElementById ('namefield') != null) document.getElementById ('namefield').focus ();\n" +
                "    }\n" +
                "  else // MSIE 6+\n" +
                "    {\n" +
                "      if (document.all.namefield != null) document.all.namefield.focus ();\n" +
                "     }\n" +
                "}\n").
          append ("<form method=\"POST\" action=\"").
          append (request.getRequestURL ().toString ()).append ("\">" +
                  "<table><tr><td colspan=\"2\" align=\"center\" class=\"headline\">Create User<br>&nbsp;</td></tr>");

        if (error != null)
          {
            s.append ("<tr><td align=\"center\" colspan=\"2\">").
              append (errorMessage (error)).
              append ("</td></tr><tr><td colspan=\"2\">&nbsp;</td></tr>");
          }

        s.append ("<tr><td align=\"right\">User name&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"text\" id=\"namefield\" name=\"name\" size=\"30\" " +
                  "tabindex=\"1\" value=\"").
          append (HTMLEncoder.encode (name)).
          append ("\" style=\"background-color:" + COLOR_INACTIVE + "\">" +
                  "</td></tr><tr><td align=\"right\">Email address&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"text\" name=\"email\" size=\"30\" " +
                  "tabindex=\"2\" value=\"").
          append (HTMLEncoder.encode (email)).
          append ("\" style=\"background-color:" + COLOR_INACTIVE + "\">" +
                  "</td></tr><tr><td align=\"right\">Password&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"password\" name=\"pwd1\" size=\"20\" " +
                  "tabindex=\"3\" style=\"background-color:" + COLOR_INACTIVE + "\"></td></tr>" +
                  "<tr><td align=\"right\">Repeat password&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"password\" name=\"pwd2\" size=\"20\" " +
                  "tabindex=\"4\" style=\"background-color:" + COLOR_INACTIVE + "\"></td></tr>" +
                  "<tr><td colspan=\"2\">&nbsp;</td></tr>" +
                  "<tr><td colspan=\"2\" align=\"center\"><input type=\"submit\" value=\"Create!\"></td></tr>" +
                  "</table></form>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        String email = "";
        String name = "";
        print (request, response, name, email, null);
      }

  }
