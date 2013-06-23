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

import misc.ProtectedServlet;
import misc.KeyCenterCommands;


@SuppressWarnings("serial")
public class AdminSetAvailability extends ProtectedServlet
  {
    public static String availability;

    static boolean on_at_server_restart;

    public static String resetServer () throws SQLException
      {
        Connection conn = ProtectedServlet.getDatabaseConnection ();
        CallableStatement stmt = conn.prepareCall ("{call ResetServerSP(?,?,?)}");
        stmt.registerOutParameter (1, java.sql.Types.DATE);
        stmt.registerOutParameter (2, java.sql.Types.VARCHAR);
        stmt.registerOutParameter (3, java.sql.Types.BOOLEAN);
        stmt.execute ();
        String date_string = stmt.getDate (1).toString ();
        availability = stmt.getString (2);
        on_at_server_restart = stmt.getBoolean (3);
        stmt.close ();
        conn.close ();
        return date_string;
      }


    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.ADMINISTRATION;
      }


    protected boolean adminPriviledgesRequired ()
      {
        return true;
      }


    public void protectedPost (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        request.setCharacterEncoding ("UTF-8");
        String message = "Server was set to AVAILABLE";
        try
          {
            availability = request.getParameter ("message");
            on_at_server_restart = request.getParameter ("resetatrestart") != null;
            if (availability.length () == 0)
              {
                availability = null;
              }
            else
              {
                message = "Server declared UNAVAILABLE!";
              }
            Connection conn = ProtectedServlet.getDatabaseConnection ();
            CallableStatement stmt = conn.prepareCall ("{call SetServerAvailabilitySP(?,?)}");
            stmt.setString (1, availability);
            stmt.setBoolean (2, on_at_server_restart);
            stmt.execute ();
            stmt.close ();
            conn.close ();
          }
        catch (SQLException e)
          {
            bad (e.getMessage ());
          }
        session.setAttribute (SESS_ADMIN_MESSAGE, message);
        response.sendRedirect (ServletUtil.getContextURL (request) + "/" + KeyCenterCommands.ADMINISTRATION.getServletName ());
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        StringBuffer s = createHeader (request).
          append ("<form method=\"POST\" action=\"").
          append (request.getRequestURL ().toString ()).append ("\">" +
                  "<table><tr><td align=\"center\" class=\"headline\">Set Server Availability<br>&nbsp;</td></tr>" +
                  "<tr><td align=\"left\">Unavailable message:</td></tr>" +
                  "<tr><td align=\"left\"><textarea name=\"message\" " +
                  "rows=\"4\" cols=\"40\" style=\"background-color:" + COLOR_INACTIVE + "\">").
          append (availability == null ? "" : availability).
          append ("</textarea></td></tr>" +
                  "<tr><td>&nbsp;</td></tr>" +
                  "<tr><td align=\"center\"><table><tr><td><input type=\"checkbox\" ");
        if (on_at_server_restart)
          {
            s.append ("checked ");
          }
        s.append ("name=\"resetatrestart\"></td><td>&nbsp;Set available after restart</td></tr></table></td></tr>" +
                  "<tr><td>&nbsp;</td></tr>" +
                  "<tr><td align=\"center\"><input type=\"submit\" value=\"Set Availability\"></td></tr>" +
                  "</table></form>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }

  }
