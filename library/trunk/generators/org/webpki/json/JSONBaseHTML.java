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

import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SKSAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64;

/**
 * Supports HTML descriptions JSON protocols.
 * 
 * @author Anders Rundgren
 */
public class JSONBaseHTML
  {
    public static final String MANDATORY               = "Y";
    public static final String OPTIONAL                = "O";
    
    public static final String PAGE_WIDTH              = "1000pt";
    public static final String NON_SKS_ALGORITHM_COLOR = "#A0A0A0";
    
    public static final String SECTION_FONT_SIZE       = "14pt";
    
    public static final String HEADER_STYLE            = "font-size:28pt;font-family:'Times New Roman',Times,Serif";
    
    public static final String ARRAY_SUBSCRIPT         = "<span style=\"position:relative;bottom:-0.5em;font-size:.9em\">&thinsp;";
    
    public static final String REQUIRED_COLUMN         = "Req";

    String file_name;
    String subsystem_name;
    
    public JSONBaseHTML (String[] args, String subsystem_name) throws IOException
      {
        if (args.length != 1)
          {
            throw new IOException ("One argument expeced, got: " + args.length);
          }
        file_name = args[0];
        this.subsystem_name = subsystem_name;
      }

    JSONBaseHTML () {}
    
    public static class Types 
      {
        public enum WEBPKI_DATA_TYPES 
          {
            BOOLEAN ("bool",   "<code>true</code> or <code>false</code>", "Boolean"),
            BYTE    ("byte",   "<i>number</i>", "Unsigned byte"),
            SHORT   ("short",  "<i>number</i>", "Unsigned two-byte integer"), 
            INT     ("int",    "<i>number</i>", "Unsigned four-byte integer"),
            BIGINT  ("bigint", "<i>number</i>", "Big integer"),
            STRING  ("string", "<i>string</i>", "Arbitrary string"),
            URI     ("uri",    "<i>string</i>", "URI"),
            ID      ("id",     "<i>string</i>", "Identifier which <b>must</b> consist of 1-32 characters, where each character is in the range <code>'!'</code> - <code>'~'</code> (0x21 - 0x7e)."),
            BASE64  ("base64", "<i>string</i>", "Base64-encoded binary data"),
            CRYPTO  ("crypto", "<i>string</i>", "Base64-encoded large positive integer.  Equivalent to XML DSig's <code>ds:CryptoBinary</code>"),
            DATE    ("date",   "<i>string</i>", "ISO date-time <code>YYYY-MM-DDThh:mm:ss{timezone}</code>."),
            OBJECT  ("object", "<code>{}</code>", "JSON object");

            String data_type;
            String json;
            String description;
            boolean used;
            WEBPKI_DATA_TYPES (String data_type, String json, String description)
              {
                this.data_type = data_type;
                this.json = json;
                this.description = description;
                used = false;
              }

            public String getDataType ()
              {
                return data_type;
              }

            public String getJSON ()
              {
                return json;
              }

            public String getDescription ()
              {
                return description;
              }

            public void setUsed ()
              {
                used = true;
              }

            public boolean isUsed ()
              {
                return used;
              }
          }

        public static final String SORTED_CERT_PATH  = "Sorted Certificate Path";
        public static final String URI_LIST          = "List of URIs";
        public static final String LINE_SEPARATOR    = "<div style=\"height:6pt;padding:0px\"></div>";
      }
    
    abstract class Content
      {
        abstract String getHTML () throws IOException;
        
        Content ()
          {
            division_objects.add (this);
          }
      }
  
    class DataTypesTable extends Content
      {
        static final String DATA_TYPES = "Data Types";

        DataTypesTable ()
          {
            super ();
          }

        @Override
        String getHTML () throws IOException
          {
            StringBuffer s = new StringBuffer ("<table class=\"tftable\" style=\"margin-top:10pt\">" +
                      "<tr><th>Type</th><th>Mapping</th><th>Description</th></tr>");
            for (Types.WEBPKI_DATA_TYPES type : Types.WEBPKI_DATA_TYPES.values ())
              {
                if (type.isUsed ())
                  {
                    s.append ("<tr><td style=\"text-align:center\">")
                     .append (type.getDataType ())
                     .append ("</td><td style=\"text-align:center\">")
                     .append (type.getJSON ())
                     .append ("</td><td>")
                     .append (type.getDescription ())
                     .append ("</td></tr>");
                  }
              }
            return s.append ("</table><div>Note that &quot;Type&quot; refers to the element type for arrays." + Types.LINE_SEPARATOR + "</div>").toString ();
          }
      }

    class Paragraph extends Content
      {
        StringBuffer local_html;
       
        Paragraph ()
          {
            super ();
          }
        
        @Override
        String getHTML () throws IOException
          {
            return local_html.append ("</div>").toString ();
          }
      }

    class ProtocolTable extends Content
      {
        ProtocolTable ()
          {
            super ();
          }

        @Override
        String getHTML () throws IOException
          {
            StringBuffer s = new StringBuffer ("<table class=\"tftable\" style=\"width:" + PAGE_WIDTH + "\">");
            for (ProtocolObject protocol_object : protocol_objects)
              {
                s.append (protocol_object.getObjectHTML ());
              }
            return s.append ("</table>").toString ();
          }
      }

    public interface Extender
      {
        ProtocolObject.Row.Column execute (ProtocolObject.Row.Column column) throws IOException;
      }

    public interface RowInterface
      {
        ProtocolObject.Row newRow ();
        
        void setNotes (String notes) throws IOException;
      }

    public class ProtocolObject implements RowInterface 
      {
        String protocols[];
        boolean main_object;
        String notes;
        
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

                public Column addArrayList (String symbol_value, int array_min) throws IOException
                  {
                    leftArray ();
                    addSymbolicValue (symbol_value);
                    rightArray (array_min);
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

                public Column setType (Types.WEBPKI_DATA_TYPES type) throws IOException
                  {
                    if (columns.size () != 2)
                      {
                        throw new IOException ("This method only applies to column #2");
                      }
                    type.setUsed ();
                    column.append (type.getDataType ());
                    return this;
                  }

                public Column addArrayLink (String link, int array_min) throws IOException
                  {
                    leftArray ();
                    link (link, link, " style=\"margin-left:2pt;margin-right:2pt;\"");
                    rightArray (array_min);
                    return this;
                  }

                private void rightArray (int array_min) throws IOException
                  {
                    addString ("]<span style=\"position:relative;bottom:-0.5em;font-size:.9em\">&thinsp;" + array_min +
                               "-n</span>");
                  }

                private void leftArray () throws IOException
                  {
                    if (columns.size () != 1)
                      {
                        throw new IOException ("This method only applies to column #2");
                      }
                    addString ("[");
                  }

                private void link (String href, String name, String style) throws IOException
                  {
                    addString ("<a href=\"#")
                      .addString (href)
                      .addString ("\"")
                      .addString (style)
                      .addString (">")
                      .addString (name)
                      .addString ("</a>");
                  }

                public Column addLink (String name) throws IOException
                  {
                    link (name, name, "");
                    return this;
                  }

                public Column addPropertyLink (String property, String holding_object) throws IOException
                  {
                    link (holding_object + "." + property, property, "");
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

                @Override
                public void setNotes (String notes) throws IOException
                  {
                    protocol_objects.lastElement ().setNotes (notes);
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

        ProtocolObject (String[] protocols, boolean main_object)
          {
            protocol_objects.add (this);
            this.protocols = protocols;
            this.main_object = main_object;
          }

        String getObjectHTML () throws IOException
          {
            StringBuffer s = new StringBuffer ("<tr><td colspan=\"4\" style=\"border-width:0px;font-size:" + SECTION_FONT_SIZE + ";padding:20pt 0pt 10pt 0pt;font-family:arial,verdana,helvetica\">");
            boolean next = false;
            for (String protocol : protocols)
              {
                if (next)
                  {
                    s.append (", &nbsp;");
                  }
                else
                  {
                    next = true;
                  }
                s.append ("<span id=\"")
                    .append (protocol)
                    .append ("\">")
                    .append (main_object ? "" : "<i>")
                    .append (protocol)
                    .append (main_object ? "</span>" : "</i></span>");
              }
            s.append ("</td></tr>\n<tr><th>Property</th><th>Type</th><th>" + REQUIRED_COLUMN + "</th><th>Comment</th></tr>");
            int i = 0;
            int supress = 0;
            for (Row row : rows)
              {
                if (row.set_group)
                  {
                    supress = row.depth;
                  }
                i++;
                s.append ("<tr>");
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
                                s.append ("<td align=\"center\" rowspan=\"")
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
                        s.append (q == 1 ? "<td style=\"white-space: nowrap\">" : (q < 4 ? "<td align=\"center\">" : "<td>"));
                      }
                    if (output)
                      {
                        s.append (column.column).append ("</td>");
                      }
                  }
                s.append ("</tr>");
              }
            if (notes != null)
              {
                s.append ("<tr><td colspan=\"4\" style=\"border-width:0px;padding:10pt 0pt 10pt 0pt\">")
                 .append (notes)
                 .append ("</td></tr>");
              }
            return s.toString ();
          }

        @Override
        public Row newRow ()
          {
            return new Row ();
          }

        @Override
        public void setNotes (String notes) throws IOException
          {
            if (this.notes == null)
              {
                this.notes = notes;
              }
            else
              {
                throw new IOException ("Notes already defined:" + protocols[0]);
              }
          }
      }

    Vector<ProtocolObject> protocol_objects = new Vector<ProtocolObject> ();
    
    Vector<Content> division_objects = new Vector<Content> ();
    
    StringBuffer html;

    public String getHTML () throws IOException
      {
        html = new StringBuffer (
            "<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\">" +
            "<html><head><title>")
        .append (subsystem_name)
        .append ("</title><meta http-equiv=Content-Type content=\"text/html; charset=utf-8\"><style type=\"text/css\">\n" +
                 ".tftable {border-collapse: collapse}\n" +
                 ".tftable th {font-size:10pt;background-color:#e0e0e0;border-width:1px;padding:4pt 10pt 4pt 10pt;border-style:solid;border-color: #a9a9a9;text-align:center;font-family:arial,verdana,helvetica}\n" +
                 ".tftable tr {background-color:#ffffff;}\n" +
                 ".tftable td {font-size:10pt;border-width:1px;padding:4pt 8pt 4pt 8pt;border-style:solid;border-color:#a9a9a9;;font-family:arial,verdana,helvetica}\n" +
                 "div {font-size:10pt;padding:10pt 0pt 0pt 0pt;font-family:arial,verdana,helvetica}\n" +
                 "a:link {color:blue;font-family:verdana,helvetica;text-decoration:none}" +
                 "a:visited {color:blue;font-family:verdana,helvetica;text-decoration:none}" +
                 "a:active {color:blue;font-family:verdana,helvetica;text-decoration:none}" +
                 "</style></head><body>" +
                 "<a href=\"http://webpki.org\" title=\"WebPKI.org\" style=\"position:absolute;top:15pt;left:15pt;z-index:5;visibility:visible\">" +
                 "<img src=\"data:image/gif;base64,")
          .append (new Base64 (false).getBase64StringFromBinary (ArrayUtil.getByteArrayFromInputStream (getClass().getResourceAsStream ("webpki-logo.gif"))))
          .append ("\" border=\"1\"></a>");
        for (Content division_object : division_objects)
          {
            html.append (division_object.getHTML ());
          }
        return html.append ("</body></html>").toString ();
      }
    
    public void writeHTML () throws IOException
      {
        ArrayUtil.writeFile (file_name, getHTML ().getBytes ("UTF-8"));
      }

    public ProtocolObject addProtocolTable (String protocol)
      {
        return new ProtocolObject (new String[]{protocol}, true);
      }

    public ProtocolObject addSubItemTable (String sub_item)
      {
        return new ProtocolObject (new String[]{sub_item}, false);
      }
    
    public ProtocolObject addSubItemTable (String[] sub_items)
      {
        return new ProtocolObject (sub_items, false);
      }

    public StringBuffer addParagraphObject ()
      {
        return addParagraphObject (null);
      }

    public StringBuffer addParagraphObject (String header)
      {
        Paragraph p = new Paragraph ();
        StringBuffer s = new StringBuffer ("<div style=\"width:" + PAGE_WIDTH + "\">");
        if (header != null)
          {
            s.append ("<div style=\"padding:10pt 0pt 10pt 0pt\"><span style=\"font-size:" + SECTION_FONT_SIZE + "\">")
             .append (header)
             .append ("</span></div>");
          }
        return p.local_html = s;
      }

    public void addDataTypesDescription (String intro)
      {
        addParagraphObject ("Notation").append (intro).append (
            "JSON objects are described as tables with associated properties. When a property holds a JSON object this is denoted by a link to the actual definition. " + Types.LINE_SEPARATOR +
            "Properties may either be <i>required</i> (" + MANDATORY + ") or <i>optional</i> (" + OPTIONAL + ") as defined in the &quot;" + REQUIRED_COLUMN + "&quot; column." + Types.LINE_SEPARATOR +
            "Array properties are identified by [&thinsp;]" + JSONBaseHTML.ARRAY_SUBSCRIPT  + "x-y</span> where the range expression represents the valid number of array elements. " + Types.LINE_SEPARATOR +
            "In some JSON objects there is a choice " +
            "from a set of <i>mutually exclusive</i> alternatives.<br>This is manifested in object tables like the following:" +
            "<table class=\"tftable\" style=\"font-style:italic;margin-top:10pt;margin-bottom:5pt\">" +
            "<tr><td>Property selection 1</td><td>Type selection 1</td><td rowspan=\"2\">Req</td><td>Comment selection 1</td></tr>" +
            "<tr><td>Property selection 2</td><td>Type selection 2</td><td>Comment selection 2</td></tr>" +
            "</table>");
        addParagraphObject ("Data Types").append ("The following table shows how the data types used by this specification are mapped into native JSON types:");
        new DataTypesTable ();
      }

    public static String enumerateAlgorithms (SKSAlgorithms[] algorithms, boolean symmetric, boolean filter, boolean reference)
      {
        StringBuffer s = new StringBuffer ("<ul>");
        for (SKSAlgorithms algorithm : algorithms)
          {
            if (filter && algorithm instanceof KeyAlgorithms && !((KeyAlgorithms)algorithm).isECKey ())
              {
                continue;
              }
            if (symmetric ^ algorithm.isSymmetric ())
              {
                continue;
              }
            if (algorithm instanceof AsymSignatureAlgorithms && ((AsymSignatureAlgorithms)algorithm).getDigestAlgorithm () == null && filter)
              {
                continue;
              }
            s.append ("<li><code")
             .append ((algorithm.isMandatorySKSAlgorithm () || reference) ? ">" : " style=\"color:" + NON_SKS_ALGORITHM_COLOR + "\">")
             .append (algorithm.getURI ())
             .append ("</code></li>");
          }
        return s.append ("</ul>").toString ();
      }

    public void addJSONSignatureDefinitions (boolean reference) throws IOException
      {
        String jcs = reference ? "" : "JCS: ";
        String option = reference ? "Option: " : "JCS option: ";
        String sks_alg_ref = reference ? " " : " See SKS &quot;Algorithm Support&quot;." + Types.LINE_SEPARATOR;
        
        addSubItemTable (JSONSignatureEncoder.SIGNATURE_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.VERSION_JSON)
              .addValue (JSONSignatureEncoder.SIGNATURE_VERSION_ID)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.URI)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString (jcs)
              .addString ("<i>Optional</i> signature object version identifier.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.ALGORITHM_JSON)
              .addSymbolicValue (JSONSignatureEncoder.ALGORITHM_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.URI)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("Signature algorithm URI.")
              .addString (sks_alg_ref)
              .addString ("The currently recognized symmetric key algorithms include:" +
                          enumerateAlgorithms (MACAlgorithms.values (), true, false, reference) +
                          "The currently recognized asymmetric key algorithms include:" +
                          enumerateAlgorithms (AsymSignatureAlgorithms.values (), false, true, reference))
              .addString ("For detailed descriptions of these algorithms, see XML DSig.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.KEY_INFO_JSON)
              .addLink (JSONSignatureEncoder.KEY_INFO_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("Signature key info placeholder.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.SIGNATURE_VALUE_JSON)
              .addSymbolicValue (JSONSignatureEncoder.SIGNATURE_VALUE_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("Signature value. " + 
                  "This value is calculated by applying the algorithm specified in <code>" +
                  JSONSignatureEncoder.ALGORITHM_JSON + "</code> using the key specified in <code>" +
                  JSONSignatureEncoder.KEY_INFO_JSON + "</code> on the <span style=\"white-space:nowrap\">UTF-8</span> representation of the " +
                  "canonicalized JSON object.");

        addSubItemTable (JSONSignatureEncoder.KEY_INFO_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.KEY_ID_JSON)
              .addSymbolicValue (JSONSignatureEncoder.KEY_ID_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.STRING)
            .newColumn ()
              .setChoice (true, 4)
            .newColumn ()
              .addString (option)
              .addString ("Symmetric key ID.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.PUBLIC_KEY_JSON)
              .addLink (JSONSignatureEncoder.PUBLIC_KEY_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString (option)
              .addString ("Public key.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.URL_JSON)
              .addSymbolicValue (JSONSignatureEncoder.URL_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.URI)
            .newColumn ()
            .newColumn ()
              .addString (option)
              .addString ("A single public key or X.509 certificate path stored in a PEM file accesible via an HTTP URL." + Types.LINE_SEPARATOR +
                          "Key algorithms <b>must</b> be compatible with those specified for ")
              .addLink (JSONSignatureEncoder.PUBLIC_KEY_JSON)
              .addString (".")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.X509_CERTIFICATE_PATH_JSON)
              .addArrayList (Types.SORTED_CERT_PATH, 1)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString (option)
              .addString ("Sorted X.509 certificate path where the <i>first</i> element in the array <b>must</b> contain the <i style=\"white-space:nowrap\">signature certificate</i>. " +
                          "The certificate path <b>must</b> be <i>contiguous</i> but is not required to be complete." + Types.LINE_SEPARATOR +
                          "Key algorithms <b>must</b> be compatible with those specified for ")
              .addLink (JSONSignatureEncoder.PUBLIC_KEY_JSON)
              .addString (".")   .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.SIGNATURE_CERTIFICATE_JSON)
              .addLink (JSONSignatureEncoder.SIGNATURE_CERTIFICATE_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString (jcs)
              .addString ("<i>Optional</i> signature certificate attribute data for usage with the <code>" +
                          JSONSignatureEncoder.X509_CERTIFICATE_PATH_JSON + "</code> option." + Types.LINE_SEPARATOR +
                          "A compliant JCS implementation <b>must</b> verify that the <code>" + JSONSignatureEncoder.SIGNATURE_CERTIFICATE_JSON +
                          "</code> object matches the first certificate in the <code>" + JSONSignatureEncoder.X509_CERTIFICATE_PATH_JSON +
                          "</code>.");

        addSubItemTable (JSONSignatureEncoder.PUBLIC_KEY_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.EC_JSON)
              .addLink (JSONSignatureEncoder.EC_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
              .setChoice (true, 2)
            .newColumn ()
              .addString (option)
              .addString ("EC public key.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.RSA_JSON)
              .addLink (JSONSignatureEncoder.RSA_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString (option)
              .addString ("RSA public key.");

        addSubItemTable (JSONSignatureEncoder.EC_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.NAMED_CURVE_JSON)
              .addSymbolicValue (JSONSignatureEncoder.NAMED_CURVE_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.URI)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("EC named curve.")
              .addString (sks_alg_ref)
              .addString ("The currently recognized EC curves include:" +
                      enumerateAlgorithms (KeyAlgorithms.values (), false, true,  reference))
              .addString (reference ?
  "The NIST algorithms are described in FIPS 186-4, while Brainpool algorithms are covered by RFC&nbsp;5639. " + Types.LINE_SEPARATOR +
  "Compatible EC curves may also be expressed in the XML&nbsp;DSig notation (<code>urn:oid:1.2.840.10045.3.1.7</code>).": "")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.X_JSON)
              .addSymbolicValue (JSONSignatureEncoder.X_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.CRYPTO)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("EC curve point X.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.Y_JSON)
              .addSymbolicValue (JSONSignatureEncoder.Y_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.CRYPTO)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("EC curve point Y.");        

        addSubItemTable (JSONSignatureEncoder.RSA_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.MODULUS_JSON)
              .addSymbolicValue (JSONSignatureEncoder.MODULUS_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.CRYPTO)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("RSA modulus.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.EXPONENT_JSON)
              .addSymbolicValue (JSONSignatureEncoder.EXPONENT_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.CRYPTO)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("RSA exponent.");

        addSubItemTable (JSONSignatureEncoder.SIGNATURE_CERTIFICATE_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.ISSUER_JSON)
              .addSymbolicValue (JSONSignatureEncoder.ISSUER_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.STRING)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("X.500 issuer distinguished name in RFC 4514 notation.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.SERIAL_NUMBER_JSON)
              .addUnquotedValue (JSONSignatureEncoder.SERIAL_NUMBER_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.BIGINT)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("Certificate serial number.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureEncoder.SUBJECT_JSON)
              .addSymbolicValue (JSONSignatureEncoder.SUBJECT_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.STRING)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("X.500 subject distinguished name in RFC 4514 notation.");
      }

    public void addProtocolTableEntry ()
      {
        new ProtocolTable ();
      }

    public void sampleRun (Class parent, String header, String[] files) throws IOException
      {
        StringBuffer s = addParagraphObject ("Sample Run").append (header);
        JSONObjectWriter.html_indent = 2;
        s.append ("<table class=\"tftable\" style=\"margin-top:10pt\">");
        boolean next = false;
        for (String file : files)
          {
            JSONObjectReader or = JSONParser.parse (ArrayUtil.getByteArrayFromInputStream (parent.getResourceAsStream (file)));
            if (next)
              {
                s.append ("<tr><td style=\"border-width:0px;height:5px\"></td></tr>");
              }
            else
              {
                next = true;
              }
            s.append ("<tr><th>")
             .append (or.getString (JSONDecoderCache.QUALIFIER_JSON))
             .append ("</th></tr><tr><td><code>")
             .append (new String (new JSONObjectWriter (or).serializeJSONObject (JSONOutputFormats.PRETTY_HTML), "UTF-8"))
             .append ("</code></td></tr>");
          }
        s.append ("</table>");
      }
  }
