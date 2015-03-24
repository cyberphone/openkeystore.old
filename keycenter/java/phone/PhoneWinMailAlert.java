package phone;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.CallableStatement;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import misc.ProtectedServlet;


@SuppressWarnings("serial")
public class PhoneWinMailAlert extends PhoneWinServlet
  {
    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        String sender = null;
        String message = null;
        try
          {
            Connection conn = ProtectedServlet.getDatabaseConnection ();
            CallableStatement stmt = conn.prepareCall ("{call GetEmailMessageSP(?, ?, ?)}");
            stmt.setInt (1, getUserID (session));
            stmt.registerOutParameter (2, java.sql.Types.VARCHAR);
            stmt.registerOutParameter (3, java.sql.Types.VARCHAR);
            stmt.execute ();
            sender = stmt.getString (2);
            message = stmt.getString (3);
            stmt.close ();
            conn.close ();
            if (message != null)
              {
                StringBuffer newmsg = new StringBuffer ();
                int i = 0;
                while ((i = message.indexOf ("href=\"")) > 0 )
                  {
                    int j = message.substring (i + 10).indexOf ('"');
                    if (j < 0)
                      {
                        break;
                      }
                    newmsg.append (message.substring (0, i + 6));
                    newmsg.append (PhoneWinProxy.createProxyURL (request, message.substring (i + 6, i + j + 10)));
                    message = message.substring (i + j + 10);
                  }
                message = newmsg.append (message).toString ();
                newmsg = new StringBuffer ();                
                for (char c : message.toCharArray ())
                  {
                    if (c == '\n')
                      {
                        newmsg.append ("<br>");
                      }
                    else
                      {
                        newmsg.append (c);
                      }
                  }
                message = newmsg.toString ();
              }
          }
        catch (SQLException sqle)
          {
            ProtectedServlet.bad (sqle.getMessage ());
          }
        StringBuffer s = createHeader ("Message Received").
          append (divSection (30, SCREEN_HEIGHT)).
          append ("<center><img src=\"images/email.png\"></center>" +
                  "<table cellpadding=\"0\" cellspacing=\"0\">" +
                  "<tr><td><b>From:</b> ").
          append (sender).
          append ("</td></tr><tr><td height=\"10\"></td></tr>" +
                  "<tr><td><b>Message:</b></td></tr>" +
                  "<tr><td height=\"2\"></td></tr>" +
                  "<tr><td>").
          append (message).
          append ("</td></tr></table></div>").
          append (createFooter ());

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
