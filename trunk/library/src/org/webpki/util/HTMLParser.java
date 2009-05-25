package org.webpki.util;

import java.io.IOException;


public class HTMLParser
  {
    private StringBuffer buf = new StringBuffer ();

    private boolean active_link;
    private int curr_index;
    private String html;
    HTMLParserURLRewriter rewriter;


    private HTMLParser ()
      {
      }


    private HTMLParser (String html, HTMLParserURLRewriter rewriter)
      {
        this.html = html;
        this.rewriter = rewriter;
      }


    private String doit (String url) throws IOException
      {
        return rewriter.rewriteURL (url);
      }

    private boolean matches (String htmltag)
      {
        for (int i = 1; i < htmltag.length (); i++)
          {
            if (Character.toLowerCase (html.charAt (curr_index + i)) != htmltag.charAt (i))
              {
                return false;
              }
          }
        return true;
      }


    private void conditionalReplace (String htmltag, boolean javascripttest) throws IOException
      {
        if (!matches (htmltag)) return;

        String url;
        int index, space_i, end_i;

        buf.append (htmltag);
        curr_index += htmltag.length ();
        if (html.charAt (curr_index) == '\"')
          {
            buf.append (html.charAt (curr_index++));
            index = html.indexOf ('\"', curr_index);                            
          }
        else if (html.charAt(curr_index) == '\'')
          {
            buf.append (html.charAt(curr_index++));
            index = html.indexOf ('\'', curr_index);
          }
        else
          {
            space_i = html.indexOf (' ', curr_index);
            end_i = html.indexOf ('>', curr_index);
            index = space_i < end_i ? space_i : end_i;
          }

        url = html.substring(curr_index, index);
        if (url.indexOf (".pdf") > 0 ||   // IE? Of course!
            (javascripttest &&
             (url.toLowerCase ().startsWith ("javascript") ||
              url.toLowerCase ().startsWith ("mailto"))))
          {
            /* Do not change javascript string */
            buf.append (url);
          }
        else
          {
            buf.append (doit (url));                            
          }
        curr_index = index;
      }

    private String parse () throws IOException
      {
        for (curr_index = 0; curr_index < html.length (); curr_index++)
          {
            switch (html.charAt (curr_index))
              {
                case 'b':
                case 'B':
                  /* Check if this is BACKGROUND=... */
                  conditionalReplace ("background=", false);
                  break;

                case '<':
                  if (matches ("<link") || matches ("<a") || matches ("<?xml-style"))
                    {
                      active_link = true;
                    }
                  break;

                case '>':
                  active_link = false;
                  break;

                case 'h':
                case 'H':
                  /* Check if this is HREF=... */
                  if (active_link) conditionalReplace ("href=", true);
                  break;

                case 's':
                case 'S':
                  /* Check if this is SRC=... */
                  conditionalReplace ("src=", false);
                  break;  

                case 'a':
                case 'A':
                  /* Check if this is ACTION=... */
                  conditionalReplace ("action=", false);
                  break;  

                default:
                  break;
              }
            buf.append (html.charAt (curr_index));
          }

        return buf.toString ();
      }

    public static String parse (String html, HTMLParserURLRewriter rewriter) throws IOException
      {
        return new HTMLParser (html, rewriter).parse ();
      }

  }
