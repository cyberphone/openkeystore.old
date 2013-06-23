package phone;

import java.io.IOException;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

import java.util.Vector;

import javax.servlet.ServletException;
import javax.servlet.http.HttpSession;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.util.HTMLEncoder;

import misc.ProtectedServlet;
import misc.KeyCenterCommands;


@SuppressWarnings("serial")
public class PhoneDebugWin extends ProtectedServlet
  {

    static enum DebugTypes {EVENT, ERROR, RECEIVED_XML, SENT_XML};

    static final String SESS_PHONE_DEBUG_WIN =  "PHONE_DEBUG_WIN";

    static class DebugLine
      {
        boolean    shown;
        String     text_argument;
        DebugTypes type;
        byte[]     xml_data;
      }


    static boolean initDebugWin (HttpSession session) throws IOException
      {
        synchronized (session)
          {
            if (session.getAttribute (SESS_PHONE_DEBUG_WIN) == null)
              {
                session.setAttribute (SESS_PHONE_DEBUG_WIN, new Vector<DebugLine> ());
                return true;
              }
            return false;
          }
      }


    public static void clearDebugWin (HttpSession session) throws IOException
      {
        synchronized (session)
          {
            session.setAttribute (SESS_PHONE_DEBUG_WIN, null);
          }
      }


    private static Vector<DebugLine> getDebugLines (HttpSession session) throws IOException
      {
        @SuppressWarnings("unchecked")
        Vector<DebugLine> lines = (Vector<DebugLine>) session.getAttribute (SESS_PHONE_DEBUG_WIN);
        if (lines == null)
          {
            throw new IOException ("Missing debug Vector!");
          }
        return lines;
      }

    static boolean needsRefresh (HttpSession session) throws IOException
      {
        synchronized (session)
          {
            Vector<DebugLine> lines = getDebugLines (session);
            if (lines.isEmpty ())
              {
                return false;
              }
            return !lines.lastElement ().shown;
          }
      }

    private static void addLine (HttpSession session, String text_argument, byte[] xml_data, DebugTypes type) throws IOException
      {
        DebugLine dl = new DebugLine ();
        dl.text_argument = text_argument;
        dl.xml_data = xml_data;
        dl.type = type;
        synchronized (session)
          {
            getDebugLines (session).add (dl);
            PhoneAJAXHandler.notifyData (session);
          }
      }


    static void setDebugEvent (HttpSession session, String message) throws IOException
      {
        addLine (session, message, null, DebugTypes.EVENT);
      }

    static void setDebugError (HttpSession session, String message) throws IOException
      {
        addLine (session, message, null, DebugTypes.ERROR);
      }

    static void setDebugReceivedXML (HttpSession session, String object_name, byte[] xml_data) throws IOException
      {
        addLine (session, object_name, xml_data, DebugTypes.RECEIVED_XML);
      }

    static void setDebugSentXML (HttpSession session, String object_name, byte[] xml_data) throws IOException
      {
        addLine (session, object_name, xml_data, DebugTypes.SENT_XML);
      }

    static byte[] getXMLData (HttpSession session, int index) throws IOException
      {
        synchronized (session)
          {
            return getDebugLines (session).elementAt (index).xml_data;
          }
      }

    protected KeyCenterCommands getCommand ()
      {
        return null;
      }

    public void protectedGet (HttpServletRequest request, HttpServletResponse response, HttpSession session) throws IOException, ServletException
      {
        StringBuffer s = new StringBuffer ("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\">" +
            "<html><head>" +
            "<style type=\"text/css\">html {overflow:auto} " +
            "html, body {margin:0px;padding:2px;background-color:black} " +
            "body {font-weight:bold;font-size:10px;color:white;font-family:Verdana, Arial} " +
            "a:link {font-weight:bold;font-size:10px;color:#6f69ff;font-family:Verdana, Arial;text-decoration:none} " +
            "a:active {font-weight:bold;font-size:10px;color:#6f69ff;font-family:Verdana, Arial;text-decoration:none} " +
            "a:visited {font-weight:bold;font-size:10px;color:#6f69ff;font-family:Verdana, Arial;text-decoration:none} " +
            "</style>");

        boolean message = false;
        try
          {
            Connection conn = getDatabaseConnection ();
            PreparedStatement stmt = conn.prepareStatement ("SELECT Sender FROM I_EMAIL WHERE UserID=? AND Message IS NOT NULL");
            stmt.setInt (1, getUserID (session));
            ResultSet rs = stmt.executeQuery ();
            message = rs.next ();
            rs.close ();
            stmt.close ();
            conn.close ();
          }
        catch (SQLException sqle)
          {
            ProtectedServlet.bad (sqle.getMessage ());
          }

/*
        if (javascript != null)
          {
            s.append ("<script type=\"text/javascript\">\n").
              append (javascript).
              append ("</script>");
          }
*/
//        s.append ("</head><body onload=\"this.scrollTop = this.scrollHeight\">");
        s.append ("</head><body");
if (message)
  {
    s.append (" onload=\"parent.frames['mobwin'].location.href='phonewinmailalert'\"");
//    s.append (" onload=\"document.href.location='phonewinmailalert'\"");
/*
   s.append (" onload=\"document.forms.shoot.submit ()\">" +
             "<form name=\"shoot\" target=\"mobwin\" method=\"POST\" action=\"phonewinmailalert\">" +
             "<input type=\"hidden\" name=\"from\" value=\"").
     append (sender).
     append ("\"><input type=\"hidden\" name=\"message\" value=\"").
     append (DebugFormatter.getHexString (message.getBytes ("UTF-8"))).
     append ("\"></form");
*/
  }
//        s.append ("</head><body>");
        s.append ("><font color=\"#40FF40\">Debug window</font><br>");
        int i = 0;
        synchronized (session)
          {
            for (DebugLine dl : getDebugLines (session))
              {
                if (i > 0)
                  {
                    s.append ("<br>");
                  }
                dl.shown = true;
                if (dl.type == DebugTypes.RECEIVED_XML)
                  {
                    s.append ("<font color=\"yellow\">Received XML Object: </font><a href=\"phonexmlviewer?S=").
                      append (i).
                      append ("&F=xml&M=").
                      append (dl.text_argument).
                      append ("\" target=\"_blank\">").
                      append (dl.text_argument).
                      append ("</a>");
                  }
                else if (dl.type == DebugTypes.SENT_XML)
                  {
                    s.append ("<font color=\"#ffb870\">Sent XML Object: </font><a href=\"phonexmlviewer?S=").
                      append (i).
                      append ("&F=xml&M=").
                      append (dl.text_argument).
                      append ("\" target=\"_blank\">").
                      append (dl.text_argument).
                      append ("</a>");
                  }
                else
                  {
                    s.append (HTMLEncoder.encodeWithLineBreaks (dl.text_argument.getBytes ("UTF-8")));
                  }
                i++;
              }
          }
        s.append ("<a name=\"last\">&nbsp;</a></body></html>");

        setHTMLMode (response);
        response.getOutputStream ().print (s.toString ());
      }
  }
