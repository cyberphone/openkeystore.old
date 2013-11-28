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
    public static final String MANDATORY    = "m";
    public static final String OPTIONAL     = "o";
    
    public static final String PAGE_WIDTH   = "80em";
    
    public interface Types 
      {
        String JSON_TYPE_BOOLEAN = "bool";
        String JSON_TYPE_SHORT   = "short";
        String JSON_TYPE_BASE64  = "base64";
        String JSON_TYPE_BYTE    = "byte";
        String JSON_TYPE_INT     = "int";
        String JSON_TYPE_OBJECT  = "object";
        String JSON_TYPE_STRING  = "string";
        String JSON_TYPE_URI     = "uri";
        String JSON_TYPE_DATE    = "date";
        String JSON_TYPE_BIGINT  = "bigint";
        
        String SORTED_CERT_PATH  = "Sorted Certificate Path";
        String URI_LIST          = "List of URIs";
        String LINE_SEPARATOR    = "<div style=\"height:6pt;padding:0px\"></div>";
      }
    
    public interface Extender
      {
        ProtocolTable.Row.Column execute (ProtocolTable.Row.Column column) throws IOException;
      }

    public interface RowInterface
      {
        ProtocolTable.Row newRow ();
      }
    
    public abstract class Content
      {
        Content ()
          {
            contents.add (this);
          }
        abstract void write () throws IOException;
      }

    public class ProtocolTable extends Content implements RowInterface 
      {
        String protocols[];
        boolean main_object;
        
        Vector<Row> rows = new Vector<Row> ();
        
        public class Row
          {
            Vector<Column> columns = new Vector<Column> ();
            boolean set_group;
            int depth;
            
            public class Column implements RowInterface 
              {
                StringBuffer column = new StringBuffer ();
                Row parent;
                
                Column (Row parent)
                  {
                    columns.add (this);
                    this.parent = parent;
                  }

                public Column newColumn ()
                  {
                    if (rows.lastElement ().columns.size () == 2 && rows.lastElement ().columns.lastElement ().column.length () ==  0)
                      {
                        rows.lastElement ().columns.lastElement ().column.append ("string");
                      }
                    if (rows.lastElement ().columns.size () == 3 && rows.lastElement ().columns.lastElement ().column.length () ==  0)
                      {
                        rows.lastElement ().columns.lastElement ().column.append (MANDATORY);
                      }
                    return rows.lastElement ().newColumn ();
                  }

                @Override
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
                    if (columns.size () == 3)
                      {
                        throw new IOException ("Cannot set string data for column #3");
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
                    addString ("<span style=\"color:");
                    addString (color);
                    if (property)
                      {
                        addString ("\" id=\"");
                        addString (protocols[0]);
                        addString (".");
                        addString (string.charAt (0) == '@' ? string.substring (1) : string);
                      }
                    addString ("\">");
                    addString (string);
                    addString ("</span>");
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

                public Column addArrayList (String symbol_value) throws IOException
                  {
                    addString ("[");
                    addSymbolicValue (symbol_value);
                    return addString ("]");
                  }

                public Column setUsage (boolean mandatory, int array_min) throws IOException
                  {
                    setUsage (mandatory);
                    column.append (": [").append (array_min).append ("..n]");
                    return this;
                  }

                public Column setUsage (boolean mandatory) throws IOException
                  {
                    if (columns.size () != 3)
                      {
                        throw new IOException ("This method only applies to column #3");
                      }
                    column.append (mandatory ? MANDATORY : OPTIONAL);
                    return this;
                  }

                public Column setType (String type) throws IOException
                  {
                    if (columns.size () != 2)
                      {
                        throw new IOException ("This method only applies to column #2");
                      }
                    column.append (type);
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

                private void link (String name, String style) throws IOException
                  {
                    addString ("<a href=\"#")
                      .addString (name)
                      .addString ("\"")
                      .addString (style)
                      .addString (">")
                      .addString (name)
                      .addString ("</a>");
                  }

                public Column addLink (String name) throws IOException
                  {
                    link (name, "");
                    return this;
                  }

                public Column addValue (String value) throws IOException
                  {
                    keyWord (value, JSONObjectWriter.html_string_color, false);
                    return this;
                  }

                public Column addUnquotedValue (String unquoted_value) throws IOException
                  {
                    return addString ("<i>").addString (unquoted_value).addString ("</i>");
                  }

                public Column setChoice (boolean mandatory, int depth) throws IOException
                  {
                    setUsage (mandatory);
                    parent.depth = depth;
                    parent.set_group = true;
                    return this;
                  }

                public Column newExtensionRow (Extender extender) throws IOException
                  {
                    return extender.execute (this);
                  }
              }
            
            Row ()
              {
                rows.add (this);
              }

            public Column newColumn ()
              {
                return new Column (this);
              }
          }

        ProtocolTable (String[] protocols, boolean main_object)
          {
            super ();
            this.protocols = protocols;
            this.main_object = main_object;
          }

        @Override
        void write () throws IOException
          {
            html.append ("<tr><td colspan=\"4\" style=\"border-width:0px;font-size:12pt;padding:20pt 0pt 10pt 0pt;font-family:arial,verdana,helvetica\">");
            boolean next = false;
            for (String protocol : protocols)
              {
                if (next)
                  {
                    html.append (", &nbsp;");
                  }
                else
                  {
                    next = true;
                  }
                html.append ("<span id=\"")
                    .append (protocol)
                    .append ("\">")
                    .append (main_object ? "" : "<i>")
                    .append (protocol)
                    .append (main_object ? "</span>" : "</i></span>");
              }
            html.append ("</td></tr>\n<tr><th>Property</th><th>Type</th><th>Usage</th><th>Comment</th></tr>");
            int i = 0;
            int supress = 0;
            for (Row row : rows)
              {
                if (row.set_group)
                  {
                    supress = row.depth;
                  }
                i++;
                html.append ("<tr>");
                if (row.columns.size () != 4)
                  {
                    throw new IOException ("Wrong number of colums for row: " + i);
                  }
                int q = 0;
                for (Row.Column column : row.columns)
                  {
                    boolean output = true;
                    boolean standard = true;
                    q++;
                    if (q == 3)
                      {
                        if (supress != 0)
                          {
                            if (row.set_group)
                              {
                                standard = false;
                                html.append ("<td align=\"center\" rowspan=\"")
                                    .append (supress)
                                    .append ("\">");
                              }
                            else
                              {
                                output = false;
                              }
                            supress--;
                          }
                      }
                    if (output == standard)
                      {
                        html.append (q == 1 ? "<td style=\"white-space: nowrap\">" : (q < 4 ? "<td align=\"center\">" : "<td>"));
                      }
                    if (output)
                      {
                        html.append (column.column).append ("</td>");
                      }
                  }
                html.append ("</tr>");
              }
          }

        @Override
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
            ".tftable {width:" + PAGE_WIDTH + ";border-collapse: collapse;}\n" +
            ".tftable th {font-size:10pt;background-color:#e0e0e0;border-width:1px;padding:4pt 12pt 4pt 12pt;border-style:solid;border-color: #a9a9a9;text-align:center;font-family:arial,verdana,helvetica}\n" +
            ".tftable tr {background-color:#ffffff;}\n" +
            ".tftable td {font-size:10pt;border-width:1px;padding:4pt 8pt 4pt 8pt;border-style:solid;border-color:#a9a9a9;;font-family:arial,verdana,helvetica}\n" +
            "a:link {color:blue}" +
            "a:visited {color:blue}" +
            "a:active {color:blue}" +
            "</style></head><body><table class=\"tftable\">");
        for (Content content : contents)
          {
            content.write ();
          }
        return html.append ("</table></body></html>").toString ();
      }
    
    public void writeHTML (String filename) throws IOException
      {
        ArrayUtil.writeFile (filename, getHTML ().getBytes ("UTF-8"));
      }

    public ProtocolTable addProtocolTable (String protocol)
      {
        return new ProtocolTable (new String[]{protocol}, true);
      }

    public ProtocolTable addSubItemTable (String sub_item)
      {
        return new ProtocolTable (new String[]{sub_item}, false);
      }
    
    public ProtocolTable addSubItemTable (String[] sub_items)
      {
        return new ProtocolTable (sub_items, false);
      }

    public void addJSONSignatureDefinitions () throws IOException
      {
        addSubItemTable (JSONSignatureEncoder.SIGNATURE_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.VERSION_JSON)
              .addValue (JSONSignatureEncoder.SIGNATURE_VERSION_ID)
            .newColumn ()
              .setType (Types.JSON_TYPE_URI)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("JCS: <i>Optional</i> signature object version identifier.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.ALGORITHM_JSON)
              .addSymbolicValue (JSONSignatureEncoder.ALGORITHM_JSON)
            .newColumn ()
              .setType (Types.JSON_TYPE_URI)
            .newColumn ()
            .newColumn ()
              .addString ("JCS: Signature algorithm URI.  See SKS &quot;Algorithm Support&quot;.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.KEY_INFO_JSON)
              .addLink (JSONSignatureEncoder.KEY_INFO_JSON)
            .newColumn ()
              .setType (Types.JSON_TYPE_OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("JCS: Signature key info placeholder.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.SIGNATURE_VALUE_JSON)
              .addSymbolicValue (JSONSignatureEncoder.SIGNATURE_VALUE_JSON)
            .newColumn ()
              .setType (Types.JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("JCS: Signature value.");

        addSubItemTable (JSONSignatureEncoder.KEY_INFO_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.PUBLIC_KEY_JSON)
              .addLink (JSONSignatureEncoder.PUBLIC_KEY_JSON)
            .newColumn ()
              .setType (Types.JSON_TYPE_OBJECT)
            .newColumn ()
              .setChoice (true, 3)
            .newColumn ()
              .addString ("JCS option: Public key.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.X509_CERTIFICATE_PATH_JSON)
              .addArrayList (Types.SORTED_CERT_PATH)
            .newColumn ()
              .setType (Types.JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("JCS option: Sorted X.509 certificate path where the first element must hold  the <i style=\"white-space:nowrap\">end-entity</i> certificate.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.KEY_ID_JSON)
              .addSymbolicValue (JSONSignatureEncoder.KEY_ID_JSON)
            .newColumn ()
              .setType (Types.JSON_TYPE_STRING)
            .newColumn ()
            .newColumn ()
              .addString ("JCS option: Symmetric key ID.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.SIGNATURE_CERTIFICATE_JSON)
              .addLink (JSONSignatureEncoder.SIGNATURE_CERTIFICATE_JSON)
            .newColumn ()
              .setType (Types.JSON_TYPE_OBJECT)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString ("JCS: Signature certificate data. Note: only valid for the <code>" +
                          JSONSignatureEncoder.X509_CERTIFICATE_PATH_JSON + "</code> option.");

        addSubItemTable (JSONSignatureEncoder.PUBLIC_KEY_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.EC_JSON)
              .addLink (JSONSignatureEncoder.EC_JSON)
            .newColumn ()
              .setType (Types.JSON_TYPE_OBJECT)
            .newColumn ()
              .setChoice (true, 2)
            .newColumn ()
              .addString ("JCS option: EC public key.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.RSA_JSON)
              .addLink (JSONSignatureEncoder.RSA_JSON)
            .newColumn ()
              .setType (Types.JSON_TYPE_OBJECT)
            .newColumn ()
            .newColumn ()
              .addString ("JCS option: RSA public key.");

        addSubItemTable (JSONSignatureEncoder.RSA_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.MODULUS_JSON)
              .addSymbolicValue (JSONSignatureEncoder.MODULUS_JSON)
            .newColumn ()
              .setType (Types.JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("JCS: RSA modulus.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.EXPONENT_JSON)
              .addSymbolicValue (JSONSignatureEncoder.EXPONENT_JSON)
            .newColumn ()
              .setType (Types.JSON_TYPE_BASE64)
            .newColumn ()
            .newColumn ()
              .addString ("JCS: RSA exponent.");

      addSubItemTable (JSONSignatureEncoder.EC_JSON)
        .newRow ()
          .newColumn ()
            .addProperty (JSONSignatureEncoder.NAMED_CURVE_JSON)
            .addSymbolicValue (JSONSignatureEncoder.NAMED_CURVE_JSON)
          .newColumn ()
            .setType (Types.JSON_TYPE_URI)
          .newColumn ()
          .newColumn ()
            .addString ("JCS: EC named curve.  See SKS &quot;Algorithm Support&quot;.")
        .newRow ()
          .newColumn ()
            .addProperty (JSONSignatureEncoder.X_JSON)
            .addSymbolicValue (JSONSignatureEncoder.X_JSON)
          .newColumn ()
            .setType (Types.JSON_TYPE_BASE64)
          .newColumn ()
          .newColumn ()
            .addString ("JCS: EC curve point X.")
        .newRow ()
          .newColumn ()
            .addProperty (JSONSignatureEncoder.Y_JSON)
            .addSymbolicValue (JSONSignatureEncoder.Y_JSON)
          .newColumn ()
            .setType (Types.JSON_TYPE_BASE64)
          .newColumn ()
          .newColumn ()
            .addString ("JCS: EC curve point Y.");        

      addSubItemTable (JSONSignatureEncoder.SIGNATURE_CERTIFICATE_JSON)
        .newRow ()
          .newColumn ()
            .addProperty (JSONSignatureEncoder.ISSUER_JSON)
            .addSymbolicValue (JSONSignatureEncoder.ISSUER_JSON)
          .newColumn ()
            .setType (Types.JSON_TYPE_STRING)
          .newColumn ()
          .newColumn ()
            .addString ("JCS: X.500 issuer distinguished name in RFC 4514 notation.")
        .newRow ()
          .newColumn ()
            .addProperty (JSONSignatureEncoder.SERIAL_NUMBER_JSON)
            .addUnquotedValue (JSONSignatureEncoder.SERIAL_NUMBER_JSON)
          .newColumn ()
            .setType (Types.JSON_TYPE_BIGINT)
          .newColumn ()
          .newColumn ()
            .addString ("JCS: Certificate serial number.")
        .newRow ()
          .newColumn ()
            .addProperty (JSONSignatureEncoder.SUBJECT_JSON)
            .addSymbolicValue (JSONSignatureEncoder.SUBJECT_JSON)
          .newColumn ()
            .setType (Types.JSON_TYPE_STRING)
          .newColumn ()
          .newColumn ()
            .addString ("JCS: X.500 subject distinguished name in RFC 4514 notation.");        
      }
  }
