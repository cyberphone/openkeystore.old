package keygen;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.CallableStatement;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webutil.ServletUtil;

import org.webpki.util.HTMLEncoder;
import org.webpki.util.HTMLHeader;


@SuppressWarnings("serial")
public class PasswordLogin extends KeyGenServlet
  {

    public void print (HttpServletRequest request, HttpServletResponse response, String email, String error) throws IOException, ServletException
      {
        StringBuffer s = HTMLHeader.createHTMLHeader (true, true, "Login to Key Provisioning", null).
          append ("<body><table width=\"100%\" height=\"100%\"><tr><td align=\"center\" valign=\"middle\">" +
                  "<table><form method=\"POST\" action=\"").
          append (request.getRequestURL ().toString ()).
          append ("\"><input type=\"hidden\" name=\"interactive\" value=\"true\">" +
                  "<tr><td align=\"center\"><b>Login to Key Provisioning</b></td></tr>" +
                  "<tr><td height=\"10\"></td></tr>" +
                  "<tr><td align=\"center\">");
        if (error == null)
          {
            s.append ("Login as any registered user");
          }
        else
          {
            s.append ("<font color=\"red\"><b>").
              append (error).
              append ("</b></font");
          }
        s.append ("</td></tr>" +
                  "<tr><td height=\"10\"></td></tr>" +
                  "<tr><td align=\"center\">Email address</td></tr>" +
                  "<tr><td align=\"center\"><input type=\"text\" size=\"25\" value=\"").
          append (HTMLEncoder.encode (email)).
          append ("\" name=\"email\"></td></tr>" +
                  "<tr><td height=\"10\"></td></tr>" +
                  "<tr><td align=\"center\">Password</td></tr>" +
                  "<tr><td align=\"center\"><input type=\"password\" size=\"16\" name=\"pwd\"></td></tr>" +
                  "<tr><td height=\"10\"></td></tr>" +
                  "<tr><td align=\"center\"><input type=\"submit\" value=\"Login\"></td></tr>" +
                  "</table></td></tr></table></form></body></html>");

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }

    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        if (request.getParameter ("email") == null)
          {
            print (request, response, "", null);
          }
        else
          {
            doPost (request, response);
          }   
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
                    stmt.getBoolean (2);  // just ignore
                    name = stmt.getString (3);
                    userid = stmt.getInt (4);
                  }
                stmt.close ();
                conn.close ();
                if (success)
                  {
                    setLoginSession (request, userid, name, email, false);
                    response.sendRedirect (ServletUtil.getContextURL (request) + "/kg2_init");
                    return;
                  }
                parser.setError ("Unknown user ID or password");
              }
            catch (SQLException e)
              {
                bad (e.getMessage ());
              }
          }
        if (request.getParameter ("interactive") == null)
          {
            response.sendError (HttpServletResponse.SC_UNAUTHORIZED);
          }
        else
          {
            print (request, response, email, parser.getError ());
          }
      }
  }
