package user;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.CallableStatement;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.Cookie;

import org.webpki.webutil.ServletUtil;

import org.webpki.util.HTMLEncoder;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;
import admin.AdminSetAvailability;


@SuppressWarnings("serial")
public class UserLogin extends ProtectedServlet
  {
    static final String USER_COOKIE = "USER";

    public static final String DEFAULT_LOGIN_APP = KeyCenterCommands.RESOURCES.getServletName ();

    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.LOGIN;
      }

    protected String onLoadArgument ()
      {
        return "fixme ()";
      }


    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        ParseUserData parser = new ParseUserData (request);
        String email = parser.getLoginID ();
        String pwd = parser.getPassword ();
        if (parser.success ())
          {
            try
              {
                int userid = 0;
                String name = null;
                boolean is_admin = false;
                Connection conn = getDatabaseConnection ();
                CallableStatement stmt = conn.prepareCall ("{call LoginSP(?, ?, ?, ?, ?, ?)}");
                stmt.registerOutParameter (1, java.sql.Types.BOOLEAN);
                stmt.registerOutParameter (2, java.sql.Types.BOOLEAN);
                stmt.registerOutParameter (3, java.sql.Types.VARCHAR);
                stmt.registerOutParameter (4, java.sql.Types.INTEGER);
                stmt.setString (5, email);
                stmt.setString (6, pwd);
                stmt.execute ();
                boolean success = stmt.getBoolean (1);            
                if (success)
                  {
                    is_admin = stmt.getBoolean (2);
                    name = stmt.getString (3);
                    userid = stmt.getInt (4);
                  }
                stmt.close ();
                conn.close ();
                if (success && !is_admin && failedDueToUnavailable (request, response))
                  {
                    return;
                  }
                if (success)
                  {
                    Cookie c = new Cookie (USER_COOKIE, email);
                    c.setMaxAge (60 * 60 * 24 * 100); // 100 days
                    c.setPath (request.getContextPath () + "/" + KeyCenterCommands.LOGIN.getServletName ());
                    response.addCookie (c);
                    setLoginSession (request, userid, name, email, is_admin);
                    String target_url = request.getParameter ("url");
                    response.sendRedirect (ServletUtil.getContextURL (request) + "/" + 
                       (target_url == null ?
                           (is_admin ? KeyCenterCommands.ADMINISTRATION.getServletName () : DEFAULT_LOGIN_APP)
                                           :
                            target_url));
                    return;
                  }
                parser.setError ("Unknown user ID or password");
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
        String target_url = request.getParameter ("url");
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
                "      if (document.getElementById ('activefield') != null) document.getElementById ('activefield').focus ();\n" +
                "    }\n" +
                "  else // MSIE 6+\n" +
                "    {\n" +
                "      if (document.all.activefield != null) document.all.activefield.focus ();\n" +
                "    }\n" +
                "}\n").
          append ("<form method=\"POST\" action=\"").
          append (request.getRequestURL ().toString ()).append ("\">");

        if (target_url != null)
          {
            s.append ("<input type=\"hidden\" name=\"url\" value=\"").
              append (target_url).
              append ("\">");
          }

        s.append ("<table>");

        if (error == null)
          {
            if (AdminSetAvailability.availability != null)
              {
                s.append ("<tr><td align=\"left\" colspan=\"2\">").
                  append (errorMessage ("Only administrators may currently login")).
                  append ("</td></tr><tr><td colspan=\"2\">&nbsp;</td></tr>");
              }
            else if (target_url != null)
              {
                s.append ("<tr><td align=\"left\" colspan=\"2\">").
                  append (infoMessage ("This resource requires you to login...")).
                  append ("</td></tr><tr><td colspan=\"2\">&nbsp;</td></tr>");
              }
          }
        else
          {
            s.append ("<tr><td align=\"left\" colspan=\"2\">").
              append (errorMessage (error)).
              append ("</td></tr><tr><td colspan=\"2\">&nbsp;</td></tr>");
          }

        s.append ("<tr><td align=\"right\">Email address&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"text\" tabindex=\"1\" name=\"email\" size=\"30\" value=\"").
          append (HTMLEncoder.encode (email)).
          append ("\" style=\"background-color:" + COLOR_INACTIVE + "\"");
        if (email.length () == 0)
          {
            s.append (" id=\"activefield\"");
          }
        s.append ("></td></tr>" +
                  "<tr><td align=\"right\">Password&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"password\" tabindex=\"2\" name=\"pwd\" size=\"20\" " +
                  "onKeyPress=\"return submitenter(this,event)\" style=\"background-color:" +
                  COLOR_INACTIVE + "\"");
        if (email.length () != 0)
          {
            s.append (" id=\"activefield\"");
          }
        s.append ("></td></tr>" +
                  "<tr><td colspan=\"2\">&nbsp;</td></tr>" +
                  "<tr><td colspan=\"2\" align=\"center\"><input type=\"submit\" value=\"Login\"></td></tr>" +
                  "<tr><td colspan=\"2\">&nbsp;</td></tr>" +
                  "<tr><td colspan=\"2\" align=\"center\"><i>JavaScript and session cookies must be enabled.</i></td></tr>");

        s.append ("</table></form>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }


    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        if (steppedUpSecurity (request, response))
          {
            return;
          }
        String email = request.getParameter ("email");
        if (email == null)
          {
            email = "";
            Cookie[] cookies = request.getCookies ();
            if (cookies != null)
              {
                for (int i = 0; i < cookies.length; i++)
                  {
                    Cookie cookie = cookies[i];
                    if (cookie.getName ().equals (USER_COOKIE))
                      {
                        email = cookie.getValue ();
                        break;
                      }
                  }
              }
          }
        print (request, response, email, null);
      }

  }
