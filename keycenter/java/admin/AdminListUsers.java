package admin;

import java.io.IOException;

import java.util.Date;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.util.HTMLEncoder;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;


@SuppressWarnings("serial")
public class AdminListUsers extends ProtectedServlet
  {
    class UserTable extends HTMLTable
      {
        Connection conn;
        PreparedStatement pstmt;
        ResultSet rs;

        UserTable (HttpServletRequest request, HttpServletResponse response, String table_name) throws IOException
          {
            super (request, response, table_name);
          }


        public void initialize (String data_key, boolean ascending_mode, int row) throws IOException, SQLException
          {
            conn = getDatabaseConnection ();
            pstmt = conn.prepareStatement ("SELECT LastLogin AS c1, LoginCount AS c2, COUNT(REQUESTS.UserID)AS c3, Name AS c4, Email AS c5 " +
                                           "FROM USERS LEFT JOIN REQUESTS USING (UserID) GROUP BY UserID ORDER BY " + 
                                                 data_key + (ascending_mode ? " ASC" : " DESC") + 
                                                 (data_key.equals ("c5") ? "" : ", c5 ASC") +
                                                 " LIMIT " + row + "," + (LINES_PER_PAGE + 1));
            rs = pstmt.executeQuery ();
          }


        public String getCellData (int column) throws IOException, SQLException
          {
            switch (column)
              {
                case 0:
                  Date last_login = rs.getDate (1);
                  return last_login == null ? "&nbsp;" : last_login.toString ();

                case 1:
                case 2:
                  int value = rs.getInt (column + 1);
                  return value == 0 ? "&nbsp;" : String.valueOf (value);

                case 3:
                case 4:
                  return HTMLEncoder.encode (rs.getString (column + 1));
              }
            bad ("Missing case");
            return null;
          }


        public boolean hasMoreData () throws IOException, SQLException
          {
            return rs.next ();
          }


        public void terminate () throws IOException, SQLException
          {
            rs.close ();
            pstmt.close ();
            conn.close ();
          }
      }

    protected KeyCenterCommands getCommand ()
      {
        return KeyCenterCommands.ADMINISTRATION;
      }


    protected boolean adminPriviledgesRequired ()
      {
        return true;
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        try
          {
            UserTable t = new UserTable (request, response, "t1");
            t.addHeaderElement (false, "Last Login",    UserTable.ALIGNMENT.center, "c1");
            t.addHeaderElement (false, "Logins",        UserTable.ALIGNMENT.center, "c2");
            t.addHeaderElement (false, "CReqs",         UserTable.ALIGNMENT.center, "c3");
            t.addHeaderElement (true,  "User Name",     UserTable.ALIGNMENT.left,   "c4");
            t.addHeaderElement (true,  "Email Address", UserTable.ALIGNMENT.left,   "c5");
            StringBuffer s = createHeader (request).
              append ("<table><tr><td align=\"center\" class=\"headline\">User List<br>&nbsp;</td></tr><tr><td align=\"center\">").
              append (t.generate ()).
              append ("</td></tr></table>").
              append (createFooter ());

            setHTMLMode (response);
            response.getOutputStream ().print (s.toString ());
          }
        catch (SQLException e)
          {
            bad (e.getMessage ());
          }
     }

  }
