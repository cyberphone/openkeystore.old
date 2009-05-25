package misc;

import java.io.IOException;
import java.io.FileInputStream;

import javax.servlet.ServletException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServlet;

import java.util.Vector;
import java.util.Properties;

import java.net.URLEncoder;

import java.security.KeyStore;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;

import java.security.cert.X509Certificate;

import javax.crypto.spec.SecretKeySpec;

import javax.crypto.Mac;

import javax.naming.InitialContext;

import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.Message;
import javax.mail.PasswordAuthentication;
import javax.mail.Authenticator;

import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Connection;

import javax.sql.DataSource;

import org.webpki.webutil.ServletUtil;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;
import org.webpki.util.HTMLEncoder;
import org.webpki.util.MimeTypedObject;

import org.webpki.xml.XMLSchemaCache;

import org.webpki.crypto.SignerInterface;
import org.webpki.crypto.JKSSignCertStore;
import org.webpki.crypto.CertificateUtil;

import user.UserHome;
import admin.AdminSetAvailability;

@SuppressWarnings("serial")
public abstract class ProtectedServlet extends HttpServlet
  {

    public static final String CERTIFICATE = "CERTIFICATE";
    public static final String XMLDATA = "XMLDATA";

    public static final String SESS_USERID        = "USERID";
    public static final String SESS_NAME          = "NAME";
    public static final String SESS_EMAIL         = "EMAIL";
    public static final String SESS_ADMIN         = "ADMIN";
    public static final String SESS_ADMIN_MESSAGE = "ADMIN_MESSAGE";

    public static final int SIGNUP_MAX_DAYS = 7;

    public static final String APP_SCOPE = "APP_SCOPE";

    public static final String COLOR_INACTIVE = "#F4FFF1";
    public static final String COLOR_ACTIVE = "#FFF8DC";

    public static final String GENERIC_STYLE =
            "html, body {margin:0px;padding:0px;height:100%} " +
            "body {font-size:8pt;color:#000000;font-family:verdana,arial;background-color:white} " +
            "h2 {font-weight:bold;font-size:12pt;color:#000000;font-family:arial,verdana,helvetica} " +
            "h3 {font-weight:bold;font-size:11pt;color:#000000;font-family:arial,verdana,helvetica} " +
            "a:link {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana;text-decoration:none} " +
            "a:visited {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana;text-decoration:none} " +
            "a:active {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana} " +
            "input {font-weight:normal;font-size:8pt;font-family:verdana,arial} " +
            "td {font-size:8pt;font-family:verdana,arial} " +
            ".smalltext {font-size:6pt;font-family:verdana,arial} " +
            "button {font-weight:normal;font-size:8pt;font-family:verdana,arial;padding-top:2px;padding-bottom:2px} " +
            ".headline {font-weight:bolder;font-size:10pt;font-family:arial,verdana} ";

    public class ParseUserData
      {
        static final int MAX_EMAIL_LENGTH = 50;
        static final int MAX_USER_NAME_LENGTH = 50;
        static final int MAX_PASSWORD_LENGTH = 20;
        static final int MIN_PASSWORD_LENGTH = 4;

        HttpServletRequest request;
        String error;

        public ParseUserData (HttpServletRequest request) throws IOException
          {
            this.request = request;
            request.setCharacterEncoding ("UTF-8");
          }


        public void setError (String new_error)
          {
            if (error == null)
              {
                error = new_error;
              }
          }


        public boolean success ()
          {
            return error == null;
          }


        public String getError ()
          {
            return error;
          }


        private String getField (String param) throws IOException
          {
            String field = request.getParameter (param);
            if (field == null)
              {
                bad ("Missing \"" + param + "\" field");
              }
            return field;
          }


        private String chk (String field, String what, int max)
          {
            if (field.length () > max)
              {
                setError (what + " longer than " + max + " characters");
                return field.substring (0, max);
              }
            return field;
          }


        public String getUserName () throws IOException
          {
            String name = getField ("name").trim ();
            if (name.length () == 0)
              {
                setError ("Missing user name");
              }
            if (name.indexOf ('"') >= 0 || name.indexOf ('\\') >= 0 || name.indexOf ('\'') >= 0)
              {
                setError ("User names may not contain the characters: &quot;&nbsp;\\&nbsp;'");
              }
            return chk (name, "User name", MAX_USER_NAME_LENGTH);
          }


        public String getLoginID () throws IOException
          {        
            String email = getField ("email").trim ().toLowerCase ();
            if (email.length () == 0 || email.indexOf ('@') < 2)
              {
                setError ("Missing or malformed e-mail address");
              }
            return chk (email, "Email address", MAX_EMAIL_LENGTH);
          }


        private String getPassword (String param, boolean test) throws IOException
          {
            String pwd = getField (param);
            if (test && pwd.length () < MIN_PASSWORD_LENGTH)
              {
                setError ("Passwords must contain at least " + MIN_PASSWORD_LENGTH + " characters");
              }
            return chk (pwd, "Password", MAX_PASSWORD_LENGTH);
          }


        public String getPassword () throws IOException
          {
            return getPassword ("pwd", false);
          }


        public String getDoublePassword () throws IOException
          {
            String pwd1 = getPassword ("pwd1", true);
            String pwd2 = getPassword ("pwd2", true);
            if (!pwd1.equals (pwd2))
              {
                setError ("Non-matching passwords");
              }
            return pwd1;
          }
      }


    public static abstract class HTMLTable
      {

        public static enum ALIGNMENT {left, right, center};

        static enum DIRECTION {NEXT, PREVIOUS, SAME};

        public static final int LINES_PER_PAGE = 16;

        private class HTMLTableHeaderCell
          {
            boolean default_ascending;
            String header_text;
            String cell_attributes_options;
            ALIGNMENT table_cell_alignment;
            String data_key;
            int column_index;
          }

        HttpServletRequest request;

        HttpServletResponse response;

        String table_name;

        Vector<HTMLTableHeaderCell> header = new Vector<HTMLTableHeaderCell> ();

        boolean ascending;

        boolean eot;

        int column;

        int row;

        DIRECTION direction = DIRECTION.NEXT;

        boolean there_was_data;

        String srt_attr;

        boolean bad_parameters;


        public HTMLTable (HttpServletRequest request, HttpServletResponse response, String table_name) throws IOException
          {
            this.request = request;
            this.response = response;
            this.table_name = table_name;

            String row_attr = request.getParameter (table_name + "_row");
            there_was_data = row_attr != null;
            String dir_attr = request.getParameter (table_name + "_dir");
            srt_attr = request.getParameter (table_name + "_srt");
            String asc_attr = request.getParameter (table_name + "_asc");
            if (there_was_data == (dir_attr == null) ||
                (srt_attr == null) != (asc_attr == null) ||
                there_was_data == (asc_attr == null))
              {
                bad_parameters = true;
                there_was_data = false;
              }
            else if (there_was_data)
              {
                row = Integer.valueOf (row_attr);
                eot = request.getParameter (table_name + "_eot") != null;
                if (dir_attr.equals ("down"))
                  {
                    direction = DIRECTION.PREVIOUS;
                  }
                else if (dir_attr.equals ("stay"))
                  {
                    direction = DIRECTION.SAME;
                  }
                if (direction != DIRECTION.NEXT && !eot)
                  {
                    row -= LINES_PER_PAGE;
                  }
                if (direction == DIRECTION.PREVIOUS)
                  {
                    row -= LINES_PER_PAGE;
                  }    
                if (row < 0)
                  {
                    row = 0;
                  }
                ascending = new Boolean (asc_attr);
              }
          }


        public void addHeaderElement (boolean default_ascending, String header_text, ALIGNMENT table_cell_alignment, String data_key) throws IOException
          {
            addHeaderElement (default_ascending, header_text, table_cell_alignment, data_key, null);
          }


        public void addHeaderElement (boolean default_ascending, String header_text, ALIGNMENT table_cell_alignment, String data_key, String cell_attributes_options) throws IOException
          {
            HTMLTableHeaderCell hc = new HTMLTableHeaderCell ();
            hc.default_ascending = default_ascending;
            hc.header_text = header_text;
            hc.table_cell_alignment = table_cell_alignment;
            hc.data_key = data_key;
            hc.cell_attributes_options = cell_attributes_options;
            hc.column_index = header.size ();
            header.add (hc);
          }


        public abstract void initialize (String data_key, boolean ascending_mode, int row) throws IOException, SQLException;

        public abstract void terminate () throws IOException, SQLException;

        public abstract boolean hasMoreData () throws IOException, SQLException;

        public abstract String getCellData (int column) throws IOException, SQLException;


        public void setActiveColumnMode (int initial_column)
          {
            column = initial_column;
          }


        public String generate () throws IOException, SQLException
          {
            String curr_data_key = header.elementAt (column).data_key;
            if (there_was_data)
              {
                curr_data_key = null;
                for (HTMLTableHeaderCell th : header)
                  {
                    if (srt_attr.equals (th.data_key))
                      {
                        column = th.column_index;
                        curr_data_key = srt_attr;
                        break;
                      }
                  }
                if (curr_data_key == null)
                  {
                    bad_parameters = true;
                    curr_data_key = header.elementAt (column).data_key;
                  }
              }
            else
              {
                ascending = header.elementAt (column).default_ascending;
              }
            initialize (curr_data_key, ascending, row);

            String var_ref = table_name + "." + table_name + "_";
            StringBuffer s = new StringBuffer ("<tr align=\"center\">");
            for (HTMLTableHeaderCell th : header)
              {
                boolean acive_column = th.column_index == column;
                boolean normal_sort_order = ascending == th.default_ascending;
                s.append ("<td class=\"").
                  append (th.column_index == 0 ? "dbTL" : "dbTR").
                  append ("\" title=\"").
                  append (acive_column ? (normal_sort_order ? "Reverse sort order" : "Back to normal sort order") : "Select as primary").
                  append ("\" onclick=\"").
                  append (var_ref).
                  append ("srt.value='").
                  append (th.data_key).
                  append ("';").
                  append (var_ref).
                  append ("dir.value='stay';").
                  append (var_ref).
                  append ("asc.value='").
                  append (acive_column ? !ascending : th.default_ascending).
                  append ("';").
                  append (var_ref).
                  append ("row.value='0';");
                  if (!bad_parameters)
                    {
                      s.append (table_name).
                        append (".submit ()");
                    }
                s.append ("\" style=\"cursor:pointer;background-color:").
                  append (acive_column ? "#F0F0F0" : "#E0E0E0").
                  append ("\">");
                if (acive_column && !normal_sort_order)
                  {
                    s.append ("<i>").append (th.header_text).append ("</i></td>");
                  }
                else
                  {
                    s.append (th.header_text).append ("</td>");
                  }
              }

            int total_colums = header.size () + 1;
            s.append (verticalShaddow (1)).
              append ("</tr><tr>").
              append (horizontalShaddow (total_colums)).
              append ("</tr><tr><td colspan=\"").append (total_colums).append ("\" height=\"10\"></td></tr>");

            boolean first = true;
            int shaddow_insert_offset = 0;
            int start_row = row + 1;
            int lines = 0;
            while (!bad_parameters && hasMoreData ())
              {
                if (lines++ < LINES_PER_PAGE)
                  {
                    s.append ("<tr bgcolor=\"ivory\">");
                    String td_class = first ? "dbTL" : "dbNL";
                    for (HTMLTableHeaderCell th : header)
                      {
                        s.append ("<td align=\"").
                          append (th.table_cell_alignment).
                          append ('"');
                        if (th.cell_attributes_options != null)
                          {
                            s.append (' ').append (th.cell_attributes_options);
                          }
                        s.append (" class=\"").
                          append (td_class).
                          append ("\">").
                          append (getCellData (th.column_index)).
                          append ("</td>");
                        td_class = first ? "dbTR" : "dbNR";
                      }
                    s.append ("</tr>");
                  }
                if (first)
                  {
                    shaddow_insert_offset = s.length () - 5;
                    first = false;
                  }
              }
            if (lines > LINES_PER_PAGE)
              {
                row += LINES_PER_PAGE;
                eot = false;
                lines--;
              }
            else
              {
                eot = true;
              }
            if (first || bad_parameters)
              {
                s.append ("<tr bgcolor=\"ivory\"><td class=\"dbTL\" align=\"center\" colspan=\"").
                  append (total_colums - 1).
                  append ("\">").
                  append (bad_parameters ? "Bad table parameters!" : "Empty Table").
                  append ("</td>").
                  append (verticalShaddow (1)).
                  append ("</tr>");
              }
            else
              {
                s.insert (shaddow_insert_offset, verticalShaddow (lines));
              }
            s.append ("<tr>").
              append (horizontalShaddow (total_colums)).
              append ("</tr>");

            if (!bad_parameters && (!eot || row != 0))
              {
                s.append ("<tr><td colspan=\"").append (total_colums).append ("\">&nbsp;</td></tr>" +
                          "<tr><td colspan=\"").append (total_colums - 1).append ("\">" +
                          "<table cellpadding=\"0\" cellspacing=\"0\" width=\"100%\"><tr><td align=\"left\">" +
                          "<input type=\"button\" onclick=\"").
                  append (var_ref).
                  append ("dir.value='down';").
                  append (table_name).
                  append (".submit ()\" value=\"Previous\" style=\"width:60pt\"></td><td align=\"center\">Record ").
                  append (start_row).
                  append ('-').
                  append (start_row + lines - 1).
                  append ("</td><td align=\"right\">" +
                          "<input type=\"button\" onclick=\"").
                  append (table_name).
                  append (".submit ()\" value=\"Next\" style=\"width:60pt\"></td></tr></table></td><td></td></tr>");
              }

            terminate ();             StringBuffer table_def = new StringBuffer ().
              append ("<form name=\"").
              append (table_name).
              append ("\" method=\"GET\" action=\"").
              append (request.getRequestURL ().toString ()).append ("\">" +
                      "<input type=\"hidden\" name=\"target\" value=\"").
              append (table_name).
              append ("\">" +
                      "<input type=\"hidden\" name=\"").
              append (table_name).
              append ("_dir\" value=\"up\">" +
                      "<input type=\"hidden\" name=\"").
              append (table_name).
              append ("_row\" value=\"").
              append (row).
              append ("\"><input type=\"hidden\" name=\"").
              append (table_name).
              append ("_srt\" value=\"").
              append (curr_data_key).
              append ("\"><input type=\"hidden\" name=\"").
              append (table_name).
              append ("_asc\" value=\"").
              append (ascending).
              append ("\">");
            if (eot)
              {
                table_def.append ("<input type=\"hidden\" name=\"").
                          append (table_name).
                          append ("_eot\" value=\"true\">");
              }
            return table_def.append ("<table cellpadding=\"0\" cellspacing=\"0\">").append (s.toString ()).append ("</table></form>").toString ();
          }
      }


    public void setLoginSession (HttpServletRequest request, int userid, String name, String email, boolean is_admin) throws IOException
      {
        HttpSession session = request.getSession (false);
        if (session != null)
          {
            session.invalidate ();
          }
        session = request.getSession ();
        session.setAttribute (SESS_USERID, new Integer (userid));
        session.setAttribute (SESS_NAME, name);
        session.setAttribute (SESS_EMAIL, email);
        session.setAttribute (SESS_ADMIN, is_admin ? "true" : null);
      }


    public boolean httpsMode (ServletContext context) throws IOException
      {
        return new Boolean (context.getInitParameter ("httpslogin"));
      }


    public boolean steppedUpSecurity (HttpServletRequest request, HttpServletResponse response) throws IOException
      {
        if (!request.isSecure () && httpsMode (getServletContext ()))
          {
            StringBuffer url = request.getRequestURL ();
            url.insert (4, 's');
            String query = request.getQueryString ();
            if (query != null)
              {
                url.append ('?').append (query);
              }
            response.sendRedirect (url.toString ()); 
            return true;
          }
        return false;
      }


    public void setHTMLMode (HttpServletResponse response)
      {
        response.setContentType ("text/html; charset=utf-8");
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", 0);
      }


    public String getSignupMac (String inst, String email) throws IOException
      {
        try
          {
            Mac mac = Mac.getInstance ("HMACSHA1");
            mac.init (new SecretKeySpec (getServletContext ().getInitParameter ("signuphmackey").getBytes ("UTF-8"),
                                         "RAW"));  // Note: any length is OK in HMACSHA1
            return DebugFormatter.getHexString (mac.doFinal ((inst + email).getBytes ("UTF-8")));
          }
        catch (GeneralSecurityException gse)
          {
            bad (gse.getMessage ());
          }
        return null;
      }


    public static String getHomeURL (HttpServletRequest request)
      {
        return ServletUtil.getContextURL (request) + "/home";
      }


    public static XMLSchemaCache getSchemaCache (ServletContext context) 
      {
        return (XMLSchemaCache) context.getAttribute (APP_SCOPE);   
      }        


    public static String getEmailAddress (HttpServletRequest request)
      {
        HttpSession session = request.getSession (false);
        return session == null ? null : (String) session.getAttribute (SESS_EMAIL);
      }


    public static int getUserID (HttpSession session) throws IOException
      {
        return (Integer) session.getAttribute (SESS_USERID);
      }


    private class MTOFile implements MimeTypedObject
      {
        byte[] data;
        String mime_type;

        private MTOFile (byte[] data, String mime_type) throws IOException
          {
            this.data = data;
            this.mime_type = mime_type;
          }

        public byte[] getData () throws IOException
          {
            return data;
          }

        public String getMimeType () throws IOException
          {
            return mime_type;
          }

      }

    static DataSource dbhandle;

    static String jdbcurl;

    static String jdbcpassword;

    static String jdbcuser;

    static void initDatabaseParameters (ServletContext context) throws Exception
      {
        String jndiname = context.getInitParameter ("jndiname");
        if (jndiname == null)
          {
            Class.forName (context.getInitParameter ("jdbcdriver")).newInstance ();
            jdbcurl = context.getInitParameter ("jdbcurl");
            jdbcpassword = context.getInitParameter ("jdbcpassword");
            jdbcuser = context.getInitParameter ("jdbcuser");
          }
        else
          {
            InitialContext ctx = new InitialContext ();
            dbhandle = (DataSource) ctx.lookup (jndiname);
          }
      }


    public static Connection getDatabaseConnection () throws SQLException
      {
        return dbhandle == null ? DriverManager.getConnection (jdbcurl, jdbcuser, jdbcpassword) : dbhandle.getConnection ();
      }


    public boolean failedDueToUnavailable (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        if (AdminSetAvailability.availability != null)
          {
            response.sendRedirect (ServletUtil.getContextURL (request) + "/unavailable");
            return true;
          }
        return false;
      }


    public MimeTypedObject getFile (String partial_path) throws IOException
      {
        String fname = getServletContext ().getRealPath (partial_path);
        return new MTOFile (ArrayUtil.readFile (fname), getServletContext ().getMimeType (fname));
      }


    public StringBuffer createHeader (HttpServletRequest request) throws IOException
      {
        return createHeader (request, null);
      }


    protected String onLoadArgument ()
      {
        return null;
      }


    public static String horizontalShaddow (int colspan)
      {
        return new StringBuffer ("<td colspan=\"").append (colspan).append ("\" background=\"images/hshaddow.gif\" height=\"2\"></td>").toString ();
      }


    public static String verticalShaddow (int rowspan)
      {
        return new StringBuffer ("<td rowspan=\"").append (rowspan).append ("\" background=\"images/vshaddow.gif\" width=\"2\"></td>").toString ();
      }


    protected StringBuffer createHeader (HttpServletRequest request, String javascript) throws IOException
      {
        StringBuffer s = new StringBuffer ("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\">" +
            "<html><head><link rel=\"shortcut icon\" href=\"k2.ico\">" +
            "<title>Key Center - Universal Provisioning</title>" +
            "<style type=\"text/css\">html {overflow:auto} " +
            GENERIC_STYLE +
            ".dbTR {border-width:1px 1px 1px 0;border-style:solid;border-color:black;padding:4px} " +
            ".dbTL {border-width:1px 1px 1px 1px;border-style:solid;border-color:black;padding:4px} " +
            ".dbNL {border-width:0 1px 1px 1px;border-style:solid;border-color:black;padding:4px} " +
            ".dbNR {border-width:0 1px 1px 0;border-style:solid;border-color:black;padding:4px} " +
            "</style>");
        if (javascript != null)
          {
            s.append ("<script type=\"text/javascript\">\n").
              append (javascript).
              append ("</script>");
          }
        s.append ("</head>");
        String onload_arg = onLoadArgument ();
        if (onload_arg == null)
          {
            s.append ("<body>");
          }
        else
          {
            s.append ("<body onload=\"").append (onload_arg).append ("\">");
          }
        String user = getEmailAddress (request);
        boolean is_admin = false;
        if (user != null)
          {
            s.append ("<table cellpadding=\"0\" cellspacing=\"0\" style=\"position:absolute;top:10px;right:15px;z-index:5;visibility:visible\">" +
                      "<tr><td title=\"Also known as &quot;").
              append (HTMLEncoder.encode ((String) request.getSession ().getAttribute (SESS_NAME))).
              append ("&quot;\" style=\"padding-bottom:2px;padding-top:1px;background-color:#F4FFF1;border-width:1px;border-color:black;border-style:solid\">&nbsp;&nbsp;").
              append (user).
              append ("&nbsp;&nbsp;</td>").
              append (verticalShaddow (1)).
              append ("<td>&nbsp;&nbsp;</td><td title=\"Logout from this service\" onmouseover=\"this.style.backgroundColor='#FFFFFF'\" onmouseout=\"this.style.backgroundColor='#FFF8DC'\"" +
                      " onclick=\"location.href='logout'\" style=\"cursor:pointer;padding-bottom:2px;padding-top:1px;background-color:#FFF8DC;border-width:1px;border-color:black;border-style:solid\">&nbsp;&nbsp;" +
                      "Logout&nbsp;&nbsp;</td>").
              append (verticalShaddow (1)).
              append ("</tr><tr>").
              append (horizontalShaddow (2)).
              append ("<td></td>").
              append (horizontalShaddow (2)).
              append ("</tr></table>");
            is_admin = request.getSession ().getAttribute (SESS_ADMIN) != null;
          }
        s.append ("<table width=\"100%\" height=\"100%\"><tr><td align=\"center\" valign=\"top\">" +
                  "<a href=\"").append (getHomeURL (request)).
          append ("\" title=\"Home of Universal Provisioning\">" +
                  "<img vspace=\"5\" hspace=\"5\" src=\"images/keygen2.gif\" width=\"140\" height=\"90\" border=\"0\"></a>" +
                  "<table cellpadding=\"0\" cellspacing=\"0\">" +
                  "<tr><td colspan=\"2\" height=\"30\"></td></tr>");
        boolean next = false;
        for (KeyCenterCommands command : KeyCenterCommands.values ())
          {
            if (command.needsAdmin () && !is_admin)
              {
                continue;
              }
            if (command == KeyCenterCommands.SETUP_CREDENTIALS || command == KeyCenterCommands.LIST_CREDENTIALS)
              {
                continue;  // REMOVE
              }
            if (next)
              {
                s.append ("<tr><td colspan=\"2\" height=\"6\"></td></tr>");
              }
            else
              {
                next = true;
              }
            String static_color = command == getCommand () ? "#FFF8DC" : "#F4FFF1";
            s.append ("<tr><td onmouseover=\"this.style.backgroundColor='#FFFFFF'\" onmouseout=\"this.style.backgroundColor='").
              append (static_color).
              append ("'\" onclick=\"location.href='");
            boolean sys_ready = is_admin || AdminSetAvailability.availability == null;
            if (sys_ready && command.needsLogin () && user == null)
              {
                s.append (KeyCenterCommands.LOGIN.getServletName ()).
                  append ("?url=");
              }
            s.append (sys_ready || command == KeyCenterCommands.LOGIN ? command.getServletName () : "unavailable").
              append ("'\" style=\"cursor:pointer;background-color:").
              append (static_color).
              append (";border-width:1px;padding:4px;border-color:black;border-style:solid;text-align:center\">&nbsp;").
              append (command.getButtonText ()).
              append ("&nbsp;</td>").
              append (verticalShaddow (1)).
              append ("</tr><tr>").
              append (horizontalShaddow (2)).
              append ("</tr>");
          }
        s.append ("</table></td><td width=\"100%\" align=\"center\" valign=\"middle\">");
        return s;
      }


    public static void bad (String error) throws IOException
      {
        throw new IOException (error);
      }


    static private String aMessage (String message, String image, String background_color)
      {
        StringBuffer s = new StringBuffer ("<table cellpadding=\"0\" cellspacing=\"0\"><tr>" +
                  "<td style=\"padding-left:4px;background-color:").
          append (background_color).
          append (";border-width: 1px 0 1px 1px; border-color: black; border-style: solid\"><img src=\"images/").
          append (image).
          append ("\"></td><td align=\"left\" style=\"padding:6pt;background-color:").
          append (background_color).
          append (";border-width: 1px 1px 1px 0; border-color: black; border-style: solid\">").
          append (message).
          append ("</td>").
          append (verticalShaddow (1)).
          append ("</tr><tr>").
          append (horizontalShaddow (3)).
          append ("</tr></table>");
        return s.toString ();
      }


    public static String infoMessage (String message)
      {
        return aMessage (message, "i.gif", COLOR_INACTIVE);
      }


    public static String errorMessage (String message)
      {
        return aMessage (message, "exclmark.gif", COLOR_ACTIVE);
      }


    protected abstract KeyCenterCommands getCommand ();


    protected String createFooter ()
      {
        return "</td></tr></table></body></html>";
      }


    private static class PopupAuthenticator extends Authenticator
      {
        String username;
        String password;
        public PopupAuthenticator (String username,String password)
          {
            this.username=username;
            this.password=password;
          }

        public PasswordAuthentication getPasswordAuthentication ()
          {
            return new PasswordAuthentication(username,password);
          }
      } 

    
    public static void sendMail (ServletContext context, String to, String from, String subject, String text_msg) throws IOException 
      {
        try
          {
            Properties props = new Properties ();
            props.put ("mail.smtp.host", context.getInitParameter ("mailserver"));
            Session msession = null;
            String mailuid = context.getInitParameter ("mailuid");
            String mailpwd = context.getInitParameter ("mailpwd");
            if (mailuid.length () > 0)
              {
                props.put ("mail.smtp.auth", "true"); 
                msession = Session.getInstance (props, new PopupAuthenticator (mailuid, mailpwd));
              }
            else
              {
                msession = Session.getDefaultInstance (props, null);
              }
            msession.setDebug (false);
            Message msg = new MimeMessage (msession);
            msg.setFrom (new InternetAddress (from));
            msg.setRecipients (Message.RecipientType.TO, new InternetAddress[] {new InternetAddress (to)});
            msg.setSubject (subject);
            msg.setContent (text_msg, "text/plain; charset=utf-8");
            msg.setHeader ("Content-Transfer-Encoding", "8bit");
            Transport.send (msg);
          }
        catch (MessagingException me)
          {
            bad (me.getMessage ());
          }
      }


    public static X509Certificate getNextCA (ServletContext context) throws IOException, GeneralSecurityException
      {
        return CertificateUtil.getCertificateFromBlob (
                 ArrayUtil.readFile (context.getRealPath ("WEB-INF/classes/" +
                                     context.getInitParameter ("nextcacertfile"))));
      }


    private static KeyStore getKeyStore (ServletContext context, String store, String storepass, String storetype) throws IOException
      {
        try
          {
            String filename = context.getInitParameter (store);
            String password = context.getInitParameter (storepass);
            KeyStore ks = KeyStore.getInstance (context.getInitParameter (storetype));
            ks.load (filename == null ? null : new FileInputStream (
               context.getRealPath ("WEB-INF/classes/" + filename)),
                     password == null ? null : password.toCharArray ());
            return ks;
          }
        catch (GeneralSecurityException e)
          {
            throw new IOException (e.getMessage ());
          }
      }


    public static KeyStore getDeviceCAKeyStore (ServletContext context) throws IOException
      {
        return getKeyStore (context, "devicecakeystore", "devicecastorepass", "devicecastoretype");
      }


    public static KeyStore getTLSCertificateKeyStore (ServletContext context) throws IOException
      {
        return getKeyStore (context, "tlscertificatekeystore",
                                     "tlscertificatestorepass",
                                     "tlscertificatestoretype");
      }


    public static SignerInterface getTLSCertificateSignatureKey (ServletContext context) throws IOException
      {
        JKSSignCertStore signer = new JKSSignCertStore (getTLSCertificateKeyStore (context), null);
        signer.setKey (null, context.getInitParameter ("tlscertificatekeypass"));
        return signer;
      }


    public static SignerInterface getIssuerCASignatureKey (ServletContext context) throws IOException
      {
        JKSSignCertStore signer = new JKSSignCertStore (getIssuerCAKeyStore (context), null);
        signer.setKey (null, context.getInitParameter ("issuercakeypass"));
        return signer;
      }


    public static KeyStore getIssuerCAKeyStore (ServletContext context) throws IOException
      {
        return getKeyStore (context, "issuercakeystore", "issuercastorepass", "issuercastoretype");
      }


    public static PrivateKey getKeyArchivalPrivateKey (ServletContext context)
    throws IOException, GeneralSecurityException
      {
        KeyStore ks = getKeyArchivalKeyKeyStore (context);
        return (PrivateKey) ks.getKey (ks.aliases ().nextElement (), 
                                       context.getInitParameter ("key-archival-key-keypass").toCharArray ());
      }


    public static KeyStore getKeyArchivalKeyKeyStore (ServletContext context) throws IOException
      {
        return getKeyStore (context, "key-archival-key-keystore", "key-archival-key-storepass", "key-archival-key-storetype");
      }


    protected boolean adminPriviledgesRequired ()
      {
        return false;
      }

    protected boolean wantStrongCrypto (ServletContext context)
      {
        return new Boolean (context.getInitParameter ("strong-crypto"));
      }

    protected boolean isAdministrator (HttpServletRequest request) throws IOException, ServletException
      {
        HttpSession sess;
        return (sess = request.getSession (false)) != null && sess.getAttribute (SESS_ADMIN) != null;
      }


    protected void hardFailure (HttpServletRequest request, HttpServletResponse response, String message) throws IOException, ServletException
      {
        response.sendRedirect (getHomeURL (request) + "?" + UserHome.ATTENTION + "=" + URLEncoder.encode (message, "UTF-8"));
      }


    private HttpSession getSession (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        HttpSession sess;
        if ((sess = request.getSession (false)) == null)
          {
            hardFailure (request, response, "Session timed-out, all temporary data is lost...");
          }
        else if (adminPriviledgesRequired () && sess.getAttribute (SESS_ADMIN) == null)
          {
            hardFailure (request, response, "You are not authorized to access this application!");
            return null;
          }
        return sess;
      }

/*
    public static JKSCAVerifier getSSLCertVerifier (ServletContext context) throws IOException
      {
        return new JKSCAVerifier (getSSLCAKeyStore (context));
      }
*/

    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        HttpSession session = getSession (request, response);
        if (session == null) return;
        protectedGet (request, response, session);
      }


    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        HttpSession session = getSession (request, response);
        if (session == null) return;
        protectedPost (request, response, session);
      }


    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        throw new IOException ("GET not implemented!");
      }


    public void protectedPost (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        throw new IOException ("POST not implemented!");
      }

  }
