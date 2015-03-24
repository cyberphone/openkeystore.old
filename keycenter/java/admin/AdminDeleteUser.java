package admin;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.CallableStatement;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webutil.ServletUtil;

import org.webpki.util.HTMLEncoder;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;


@SuppressWarnings("serial")
public class AdminDeleteUser extends ProtectedServlet
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


    public static boolean delete (String email) throws SQLException
      {
        Connection conn = ProtectedServlet.getDatabaseConnection ();
        CallableStatement stmt = conn.prepareCall ("{call DeleteUserSP(?, ?)}");
        stmt.registerOutParameter (1, java.sql.Types.BOOLEAN);
        stmt.setString (2, email);
        stmt.execute ();
        boolean success = stmt.getBoolean (1);
        stmt.close ();
        conn.close ();
        return success;
      }


    public void protectedPost (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        ParseUserData parser = new ParseUserData (request);
        String email = parser.getLoginID ();
        if (parser.success ())
          {
            try
              {
                if (delete (email))
                  {
                    session.setAttribute (SESS_ADMIN_MESSAGE, "User <b>" + email + "</b> was deleted");
                    response.sendRedirect (ServletUtil.getContextURL (request) + "/" + KeyCenterCommands.ADMINISTRATION.getServletName ());
                    return;
                  }
                parser.setError ("No such user!");
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
                  "<table><tr><td colspan=\"2\" align=\"center\" class=\"headline\">Delete User<br>&nbsp;</td></tr>");

        if (error != null)
          {
            s.append ("<tr><td align=\"center\" colspan=\"2\">").
              append (errorMessage (error)).
              append ("</td></tr><tr><td colspan=\"2\">&nbsp;</td></tr>");
          }

        s.append ("<tr><td align=\"right\">Email address&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"text\" id=\"uidfield\" name=\"email\" size=\"30\" " +
                  "tabindex=\"1\" onKeyPress=\"return submitenter(this,event)\" value=\"").
          append (HTMLEncoder.encode (email)).
          append ("\" style=\"background-color:" + COLOR_INACTIVE + "\"></td></tr>" +
                  "<tr><td colspan=\"2\">&nbsp;</td></tr>" +
                  "<tr><td colspan=\"2\" align=\"center\"><input type=\"submit\" value=\"Delete!\"></td></tr>" +
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
