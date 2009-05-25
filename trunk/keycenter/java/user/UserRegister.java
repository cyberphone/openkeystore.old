package user;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import javax.servlet.ServletException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webutil.ServletUtil;

import org.webpki.util.HTMLEncoder;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;
import misc.RestrictedMode;


@SuppressWarnings("serial")
public class UserRegister extends ProtectedServlet
  {
    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.REGISTER;
      }


    protected String onLoadArgument ()
      {
        return "fixme ()";
      }


    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        if (!isAdministrator (request) && failedDueToUnavailable (request, response))
          {
            return;
          }
        ParseUserData parser = new ParseUserData (request);
        String name = parser.getUserName ();
        String email = parser.getLoginID ();
        String pwd = parser.getDoublePassword ();
        if (parser.success ())
          {
            try
              {
                Connection conn = getDatabaseConnection ();
                PreparedStatement pstmt = conn.prepareStatement ("INSERT INTO SIGNUPS (Password, Email, Name) VALUES (?, ?, ?)",
                                                                 PreparedStatement.RETURN_GENERATED_KEYS);
                pstmt.setString (1, pwd);
                pstmt.setString (2, email);
                pstmt.setString (3, name);
                pstmt.executeUpdate ();
                String inst = null;
                ResultSet rs = pstmt.getGeneratedKeys ();
                if (rs.next ())
                  {
                    inst = rs.getString (1);
                  }
                rs.close ();
                pstmt.close ();
                conn.close ();
                if (inst == null)
                  {
                    bad ("Couldn't get SignupID!");
                  }
                ServletContext context = getServletContext ();
                String fromaddress = context.getInitParameter ("fromaddress");
                sendMail (context, email, fromaddress, "Message from " + fromaddress.toUpperCase (),
                          name +
                          ",\nThank you for signing up with the KeyGen2 test-server.\n" + 
                          "To activate your account click on the following URL:\n" +
                          ServletUtil.getContextURL (request) + "/verify?ID=" + inst +
                          "&USER=" + email + "&HMAC=" + getSignupMac (inst, email) + 
                          "\n\nNote that the account must be activated within " + SIGNUP_MAX_DAYS + " days!\n\n" + 
                          "/The registry");

                response.sendRedirect (ServletUtil.getContextURL (request) + "/signupmsg?email=" + email);
                return;
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
                "}\n");

        boolean restricted = RestrictedMode.isRestricted (request, response, getServletContext ());
        if (!restricted)
          {
            s.append ("<form method=\"POST\" action=\"").
              append (request.getRequestURL ().toString ()).
              append ("\">");
          }

        s.append ("<table width=\"450\">" +
                  "<tr><td colspan=\"2\" align=\"center\" class=\"headline\">Register an Account<br>&nbsp;</td></tr>" +
                  "<tr><td colspan=\"2\" align=\"left\">In order to use this test-server you must have an account with a " +
                  "<i>verified</i> <nobr>e-mail</nobr> address.&nbsp; The \"User name\" does not have to be real, " +
                  "it will only be used in CN fields of created X.509 certificates.<br>&nbsp;</td></tr>");

        if (error != null)
          {
            s.append ("<tr><td align=\"center\" colspan=\"2\">").
              append (errorMessage (error)).
              append ("</td></tr><td>&nbsp;</td></tr>");
          }

        if (restricted)
          {
            s.append ("<tr><td align=\"center\" colspan=\"2\">").
              append (errorMessage ("This site is currently running in &quot;restricted mode&quot; and does not allow self-signup, you must be <i>invited</i>.")).
              append ("</td></tr><td>&nbsp;</td></tr>");
          }

        s.append ("<tr><td align=\"right\">User name&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"text\" id=\"namefield\" name=\"name\" size=\"30\" " +
                  "tabindex=\"1\" value=\"").
          append (HTMLEncoder.encode (name)).
          append ("\" style=\"background-color:" + COLOR_INACTIVE + "\"></td></tr>" +
                  "<tr><td align=\"right\">Email address&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"text\" name=\"email\" size=\"30\" " +
                  "tabindex=\"2\" value=\"").
          append (HTMLEncoder.encode (email)).
          append ("\" style=\"background-color:" + COLOR_INACTIVE + "\"></td></tr>" +
                  "<tr><td align=\"right\">Password&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"password\" name=\"pwd1\" size=\"20\" " +
                  "tabindex=\"3\" style=\"background-color:" + COLOR_INACTIVE + "\"></td></tr>" +
                  "<tr><td align=\"right\">Repeat password&nbsp;</td>" +
                  "<td align=\"left\"><input type=\"password\" name=\"pwd2\" size=\"20\" " +
                  "tabindex=\"4\" style=\"background-color:" + COLOR_INACTIVE + "\"></td></tr>" +
                  "<tr><td colspan=\"2\">&nbsp;</td></tr>" +
                  "<tr><td colspan=\"2\" align=\"center\"><input  title=\"Welcome to KeyGen2!\" type=\"submit\" value=\"").
          append (restricted ? "Disabled Button" : "Register").
          append ("\"></td></tr>" +
                  "<tr><td colspan=\"2\">&nbsp;</td></tr>" +
                  "<tr><td colspan=\"2\" align=\"center\">").
          append (infoMessage ("Privacy notice: The owner of this site honors user privacy and promises " +
                      "to never sell, reveal, or transfer any data regarding<br> registered users to another party.")).
          append ("</td></tr><tr><td colspan=\"2\">&nbsp;</td></tr>" +
                  "<tr><td align=\"center\" colspan=\"2\"><input type=\"button\" title=\"You may leave us whenever you want\" value=\"Unregister Account...\" onclick=\"location.href='");
                  if (getEmailAddress (request) == null)
                    {
                      s.append (KeyCenterCommands.LOGIN.getServletName ()).
                        append ("?URL=");
                    }
        s.append ("unregister'\"></td></tr>" +
                  "</table></form>").
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
        String email = "";
        String name = "";
        print (request, response, name, email, null);
      }

  }
