/*
 *  Copyright 2006-2013 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.json;

import java.io.IOException;

import java.util.Vector;

import org.webpki.util.ArrayUtil;

/**
 * Supports HTML descriptions JSON protocols.
 * 
 * @author Anders Rundgren
 */
public class JSONBaseHTML
  {
    public static final String MANDATORY = "m";
    public static final String OPTIONAL  = "o";
    
    static int tables;
    
    public abstract class Content
      {
        Content ()
          {
            contents.add (this);
          }
        abstract void write () throws IOException;
      }

    public class ProtocolTable extends Content
      {
        String protocol;
        boolean is_object;
        boolean main_object;
        int table_id;
        
        Vector<Row> rows = new Vector<Row> ();
        
        public class Row
          {
            Vector<Column> columns = new Vector<Column> ();
            
            public class Column
              {
                StringBuffer column = new StringBuffer ();
                
                Column ()
                  {
                    columns.add (this);
                  }

                public Column newColumn ()
                  {
                    if (rows.lastElement ().columns.size () == 2 && rows.lastElement ().columns.lastElement ().column.length () ==  0)
                      {
                        rows.lastElement ().columns.lastElement ().column.append (MANDATORY);
                      }
                    return rows.lastElement ().newColumn ();
                  }

                public Row newRow ()
                  {
                    return new Row ();
                  }

                public Column addString (String string) throws IOException
                  {
                    if (columns.size () == 2)
                      {
                        throw new IOException ("Cannot set string data for column #2");
                      }
                    column.append (string);
                    return this;
                  }

                public Column addContext (String argument) throws IOException
                  {
                    keyWord (JSONDecoderCache.CONTEXT_JSON, JSONObjectWriter.html_keyword_color, true);
                    return keyWord (argument, JSONObjectWriter.html_string_color, false);
                  }

                public Column addQualifier (String argument) throws IOException
                  {
                    keyWord (JSONDecoderCache.QUALIFIER_JSON, JSONObjectWriter.html_keyword_color, true);
                    return keyWord (argument, JSONObjectWriter.html_string_color, false);
                  }

                private Column keyWord (String string, String color, boolean property) throws IOException
                  {
                    code ();
                    quote ();
                    addString ("<font color=\"");
                    addString (color);
                    addString ("\">");
                    addString (string);
                    addString ("</font>");
                    quote ();
                    if (property)
                      {
                        addString (":&nbsp;");
                      }
                    nocode ();
                    return this;
                  }

                private void nocode () throws IOException
                  {
                    addString ("</code>");
                  }

                private void code () throws IOException
                  {
                    addString ("<code>");
                  }

                private void quote () throws IOException
                  {
                    addString ("&quot;");
                  }

                public Column addProperty (String property) throws IOException
                  {
                    return keyWord (property, JSONObjectWriter.html_property_color, true);
                  }

                public Column addSymbolicValue (String symbol_value) throws IOException
                  {
                    code ();
                    quote ();
                    nocode ();
                    addString ("<i>").addString (symbol_value).addString ("</i>");
                    code ();
                    quote ();
                    nocode ();
                    return this;
                  }

                public Column setUsage (boolean mandatory, int array_min) throws IOException
                  {
                    setUsage (mandatory);
                    column.append (": [").append (array_min).append ("..n]");
                    return this;
                  }

                public Column setUsage (boolean mandatory) throws IOException
                  {
                    if (columns.size () != 2)
                      {
                        throw new IOException ("This method only applies to column #2");
                      }
                    column.append (mandatory ? MANDATORY : OPTIONAL);
                    return this;
                  }

                public Column addArrayLink (String link) throws IOException
                  {
                    leftArray ();
                    link (link, " style=\"margin-left:2pt;margin-right:2pt;\"");
                    rightArray ();
                    return this;
                  }

                private void rightArray () throws IOException
                  {
                    addString ("]");
                  }

                private void leftArray () throws IOException
                  {
                    addString ("[");
                  }

                private void link (String link, String style) throws IOException
                  {
                    addString ("<a href=\"#")
                      .addString (link)
                      .addString ("\"")
                      .addString (style)
                      .addString (">")
                      .addString (link)
                      .addString ("</a>");
                  }

                public Column addLink (String link) throws IOException
                  {
                    link (link, "");
                    return this;
                  }

                public Column addValue (String value) throws IOException
                  {
                    keyWord (value, JSONObjectWriter.html_string_color, false);
                    return this;
                  }

                public Column addIntegerValue (String integer_value) throws IOException
                  {
                    return addString ("<i>").addString (integer_value).addString ("</i>");
                  }
              }
            
            Row ()
              {
                rows.add (this);
              }

            public Column newColumn ()
              {
                return new Column ();
              }
          }

        ProtocolTable (String protocol, boolean is_object, boolean main_object)
          {
            super ();
            this.protocol = protocol;
            this.is_object = is_object;
            this.main_object = main_object;
            this.table_id = ++tables;
          }

        private void addObjectLine (char c)
          {
            html.append ("<tr><td><code>")
                .append (c)
                .append ("</code></td><td>&nbsp;</td><td></td></tr>");
          }

        @Override
        void write () throws IOException
          {
            html.append ("<div class=\"header\">");
            if (!main_object)
              {
                html.append ("<i id=\"")
                    .append (protocol)
                    .append ("\">");
              }
            html.append (protocol)
                .append (main_object ? "" : "</i>")
                .append ("</div>\n<table id=\"table.")
                .append (table_id)
                .append ("\" class=\"tftable\" style=\"margin-bottom:10pt\"><tr><th id=\"elem1.")
                .append (table_id)
                .append ("\">Element</th><th>Usage</th><th id=\"elem3.")
                .append (table_id)
                .append ("\">Comment</th></tr>");
            int i = 0;
            if (is_object)
              {
                addObjectLine ('{');
              }
            for (Row row : rows)
              {
                i++;
                html.append ("<tr>");
                if (row.columns.size () != 3)
                  {
                    throw new IOException ("Wrong number of colums for row: " + i);
                  }
                if (is_object)
                  {
                    row.columns.firstElement ().column.insert (0, "<code>&nbsp;&nbsp;</code>");
                  }
                if (i < rows.size ())
                  {
                    row.columns.firstElement ().column.append ("<code>,</code>");
                  }
                int q = 0;
                for (Row.Column column : row.columns)
                  {
                    html.append (++q == 2 ? "<td align=\"center\">" : "<td>").append (column.column).append ("</td>");
                  }
                html.append ("</tr>");
              }
            if (is_object)
              {
                addObjectLine ('}');
              }
            html.append ("</table>");
          }

        public Row newRow ()
          {
            return new Row ();
          }
      }    

    Vector<Content> contents = new Vector<Content> ();
    
    StringBuffer html;

    public String getHTML () throws IOException
      {
        html = new StringBuffer (
            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\">" +
            "<html><head><title>KeyGen2</title><meta http-equiv=Content-Type content=\"text/html; charset=utf-8\"><style type=\"text/css\">\n" +
            ".tftable {color:#333333;border-width: 1px;border-color: #a9a9a9;border-collapse: collapse;}\n" +
            ".tftable th {font-size:10pt;background-color:#e0e0e0;border-width:1px;padding:4pt 12pt 4pt 12pt;border-style:solid;border-color: #a9a9a9;text-align:center;font-family:arial,verdana,helvetica}\n" +
            ".tftable tr {background-color:#ffffff;}\n" +
            ".tftable td {font-size:10pt;border-width:1px;padding:4pt 8pt 4pt 8pt;border-style:solid;border-color:#a9a9a9;;font-family:arial,verdana,helvetica}\n" +
            ".header {font-size:12pt;padding:10pt 0pt 10pt 0pt;font-family:arial,verdana,helvetica}\n" +
            "a:link {color:blue}" +
            "a:visited {color:blue}" +
            "a:active {color:blue}" +
            "</style>" +
            "<script type=\"text/javascript\">\n" +
            "function tablefix ()\n" +
            "  {\n" +
            "    var max = -1;\n" +
            "    for (var i = 1; i <= ").append (tables).append ("; i++)\n" +
            "      {\n" +
            "        var width = window.document.getElementById ('elem1.' + i).offsetWidth;\n" +
            "        if (width > max) max = width;\n;" +
            "      }\n" +
            "    for (var i = 1; i <= ").append (tables).append ("; i++)\n" +
            "      {\n" +
            "        console.info ('max=' + max);\n" +
//            "        window.document.getElementById ('table.' + i).style.width = '' + (max + max - 16) + 'px';\n" +
 //           "        window.document.getElementById ('elem1.' + i).style.minWidth = '' + (max - 16) + 'px';\n" +
//            "        window.document.getElementById ('elem3.' + i).style.minWidth = '' + (max - 16) + 'px';\n" +
//          "        window.document.getElementById ('elem.' + i).style.minWidth = '500px';\n" +
            "      }\n" +
            "  }\n" +
            "</script>\n" +
            "</head><body onload=\"tablefix ()\">");
        for (Content content : contents)
          {
            content.write ();
          }
        return html.append ("</body></html>").toString ();
      }
    
    public void writeHTML (String filename) throws IOException
      {
        ArrayUtil.writeFile (filename, getHTML ().getBytes ("UTF-8"));
      }

    public ProtocolTable addProtocolTable (String protocol)
      {
        return new ProtocolTable (protocol, true, true);
      }

    public ProtocolTable addSubItemTable (String sub_item, boolean is_object)
      {
        return new ProtocolTable (sub_item, is_object, false);
      }
  }
