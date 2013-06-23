package keygen;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ByteArrayInputStream;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.CallableStatement;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import java.security.GeneralSecurityException;

import org.webpki.util.WrappedException;
import org.webpki.util.DebugFormatter;
import org.webpki.util.HTMLHeader;

@SuppressWarnings("serial")
public class DelayedCredentialDeploymentRequestServlet extends KeyGenServlet
  {

    private String convert (String input) throws IOException      {
        return new String (DebugFormatter.getByteArrayFromHex (input), "UTF-8");      }
    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        try
          {            int user_id = Integer.parseInt (request.getParameter ("uid"));            Connection conn = getDatabaseConnection ();
            CallableStatement stmt = conn.prepareCall ("{call GetRequestSP(?, ?, ?, ?)}");
            stmt.setInt (1, user_id);
            stmt.setString (2, convert (request.getParameter ("sid")));
            stmt.setString (3, convert (request.getParameter ("cid")));
            stmt.registerOutParameter (4, java.sql.Types.BLOB);
            stmt.execute ();
            byte[] saved_state = stmt.getBytes (4);            
            stmt.close ();
            conn.close ();            if (saved_state == null)              {
                StringBuffer s = HTMLHeader.createHTMLHeader (true, true, "Provisioning Failed", null).
                  append ("<body><table width=\"100%\" height=\"100%\"><tr><td align=\"center\" valign=\"middle\">" +
                          "<table><tr><td align=\"center\"><b>Provisioning Failed!</b></td></tr>" +
                          "<tr><td height=\"10\"></td></tr>" +
                          "<tr><td align=\"center\"><img src=\"images/mini_banklogo.gif\"></td></tr>" +
                          "<tr><td height=\"20\"></td></tr>" +
                          "<tr><td align=\"left\">The request is unknown.<br>&nbsp;<br>/MyBank team</td></tr>" +
                          "</table></td></tr></table></body></html>");

                setHTMLMode (response);
                response.getOutputStream ().print (s.toString ());
              }            else              {
                deployCredentials (getServletContext (),
                                   (ProvisioningState) new ObjectInputStream (new ByteArrayInputStream (saved_state)).readObject (),
                                   user_id, request, response);              }
          }
        catch (ClassNotFoundException cnfe)
          {
            throw new WrappedException (cnfe);
          }
        catch (SQLException sqle)
          {
            throw new WrappedException (sqle);
          }
        catch (GeneralSecurityException gse)
          {
            throw new WrappedException (gse);
          }
      }
  }
