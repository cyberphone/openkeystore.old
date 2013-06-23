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

import user.UserLogin;


@SuppressWarnings("serial")
public class AdminImpersonateUser extends ProtectedServlet
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
        if (parser.success ())
          {
            try
              {
                boolean is_admin = false;
                int userid = 0;
                String name = null;
                Connection conn = getDatabaseConnection ();
                PreparedStatement pstmt = conn.prepareStatement ("SELECT UserID, Name, IsAdmin FROM USERS WHERE Email=?");
                pstmt.setString (1, email);
                ResultSet rs = pstmt.executeQuery ();
                boolean found = rs.next ();
                if (found)
                  {
                    userid = rs.getInt (1);
                    name = rs.getString (2);
                    is_admin = rs.getBoolean (3);
                  }
                else
                  {
                    parser.setError ("No such user!");
                  }
                rs.close ();
                pstmt.close ();
                conn.close ();
                if (found)
                  {
                    setLoginSession (request, userid, name, email, is_admin);
                    response.sendRedirect (ServletUtil.getContextURL (request) + "/" + UserLogin.DEFAULT_LOGIN_APP);
                    return;
                  }
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
                "function submitenter(myfield,e)\n" +
                "{\n" +
                "  var keycode;\n" +
                "  if (window.event) keycode = window.event.keyCode;\n" +
                "  else if (e) keycode = e.which;\n" +
                "  else return true;\n" +
                "  if (keycode == 13)\n" +
                "    {\n" +
                "      myfield.form.submit();\n" +
                "      return false;\n" +
                "    }\n" +
                "  else return true;\n" +
                "}\n" +
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
                  "<table><tr><td colspan=\"2\" align=\"center\" class=\"headline\">Impersonate User<br>&nbsp;</td></tr>");

        if (error != null)
          {
            s.append ("<tr><td align=\"center\" colspan=\"2\">").
              append (errorMessage (error)).
              append ("</td></tr><tr><td colspan=\"2\">&nbsp;</td></tr>");
          }

        s.append ("<tr><td align=\"right\">Email address&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"text\" id=\"uidfield\" name=\"email\" size=\"30\" " +
                  "tabindex=\"2\" onKeyPress=\"return submitenter(this,event)\" value=\"").
          append (HTMLEncoder.encode (email)).
          append ("\" style=\"background-color:" + COLOR_INACTIVE + "\"></td></tr>" +
                  "<tr><td colspan=\"2\">&nbsp;</td></tr>" +
                  "<tr><td colspan=\"2\" align=\"center\"><input type=\"submit\" value=\"Impersonate!\"></td></tr>" +
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
