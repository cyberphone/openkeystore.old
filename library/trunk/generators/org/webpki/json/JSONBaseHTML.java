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

import java.util.LinkedHashMap;
import java.util.TreeSet;
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
    
    public static final String CHAPTER_FONT_SIZE       = "14pt";

    public static final String SECTION_FONT_SIZE       = "14pt";
    
    public static final String HEADER_STYLE            = "font-size:28pt;font-family:'Times New Roman',Times,Serif";
    
    public static final String ARRAY_SUBSCRIPT         = "<span style=\"position:relative;bottom:-0.5em;font-size:.9em\">&thinsp;";

    public static final String REQUIRED_COLUMN         = "Req";
    
    public static final String REF_JSON                = "RFC4627";
    
    public static final String REF_X509                = "RFC5280";

    public static final String REF_XMLDSIG             = "XMLDSIG";
    
    public static final String REF_XMLENC              = "XMLENC";
    
    public static final String REF_JCS                 = "JCS";
    
    public static final String REF_JOSE                = "JOSE";
    
    public static final String REF_BASE64              = "RFC4648";
    
    public static final String REF_PEM                 = "PEM";
    
    public static final String REF_URI                 = "RFC3986";

    public static final String REF_DSKPP               = "RFC6063";

    public static final String REF_SKS                 = "SKS";

    public static final String REF_CMP                 = "RFC4210";

    public static final String REF_LDAP_NAME           = "RFC4514";

    public static final String REF_PKCS8               = "RFC5208";

    public static final String REF_BRAINPOOL           = "RFC5639";
    
    public static final String REF_FIPS186             = "FIPS-186-4";

    public static final String REF_WEBPKI_FOR_ANDROID  = "W4A";

    String file_name;
    String subsystem_name;
    
    class Reference
      {
        String html_description;
        boolean referenced;
      }
    
    LinkedHashMap<String,Reference> references = new LinkedHashMap<String,Reference> ();
    
    class TOCEntry
      {
        String link;
        boolean indented;
        boolean appendix;
        int sequence;
        boolean prefix_on;
        int sub_seq;
        boolean italic;

        public String getPrefix ()
          {
            StringBuffer s = new StringBuffer ();
            if (prefix_on)
              {
                if (appendix)
                  {
                    s.append ("Appendix ")
                     .append ((char) (('A' - 1) + sequence));
                  }
                else
                  {
                    s.append (String.valueOf (sequence));
                  }
                if (indented)
                  {
                    s.append (".")
                     .append (String.valueOf (sub_seq));
                  }
                s.append (appendix ? ':' : '.')
                 .append ("&nbsp;");
              }
            return s.toString ();
          }

        String PrefixPlusLink ()
          {
            return prefix_on ? "<td style=\"text-align:right\"><a href=\"#" + link + "\">" + getBeginItalic () + getPrefix () + getEndItalic () + "</a></td>" : "";
          }

        private String getEndItalic ()
          {
            return italic ? "</i>" : "";
          }

        private String getBeginItalic ()
          {
            return italic ? "<i>" : "";
          }

        public int remainingColums ()
          {
            boolean prefix_on_flag = false;
            boolean indent_flag = false;
            for (String toc_entry : toc.keySet ())
              {
                TOCEntry te = toc.get (toc_entry);
                if (te.appendix == appendix)
                  {
                    if (te.indented)
                      {
                        indent_flag = true;
                        if (te.prefix_on)
                          {
                            prefix_on_flag = true;
                          }
                      }
                  }
              }
            return (indented || ! indent_flag)? (prefix_on || !prefix_on_flag) ? 1 : 2 : prefix_on_flag ? 3 : 2;
          }
      }

    LinkedHashMap<String,TOCEntry> toc = new LinkedHashMap<String,TOCEntry> ();
    
    int curr_toc_seq = 0;
    
    boolean appendix_mode;
    
    String externalWebReference (String url)
      {
        return "<a target=\"_blank\" title=\"External link opened in a new windows\" href=\"" + url + "\">" + url + "</a>";
      }
    
    StringBuffer external_styles = new StringBuffer ();
    
    public void addGlobalStyle (String style)
      {
        external_styles.append (style);
      }
    
    public JSONBaseHTML (String[] args, String subsystem_name) throws IOException
      {
        if (args.length != 1)
          {
            throw new IOException ("One argument expeced, got: " + args.length);
          }
        file_name = args[0];
        this.subsystem_name = subsystem_name;

        addReferenceEntry (REF_JSON,
            "Crockford, D., \"The application/json Media Type for " +
            "JavaScript Object Notation (JSON)\", RFC&nbsp;4627, July&nbsp;2006.");

        addReferenceEntry (REF_URI,
            "Berners-Lee, T., Fielding, R., and L. Masinter, \"Uniform " +
            "Resource Identifier (URI): Generic Syntax\", RFC&nbsp;3986, January&nbsp;2005.");

        addReferenceEntry (REF_XMLDSIG,
            "D. Eastlake, J. Reagle, D. Solo, F. Hirsch, M. Nystrom, T. Roessler, K. Yiu, " +
            "\"XML Signature Syntax and Processing Version 1.1.\", W3C Recommendation, " +
            "April&nbsp;2013. <br>" +
            externalWebReference ("http://www.w3.org/TR/2013/REC-xmldsig-core1-20130411/"));

        addReferenceEntry (REF_XMLENC,
            "\"XML Encryption Syntax and Processing\", J. Reagle, " +
            "D. Eastlake, April&nbsp;2013. " +
            externalWebReference ("http://www.w3.org/TR/xmlenc-core1/"));

        addReferenceEntry (REF_JCS,
            "Rundgren, A., \"JCS - JSON Cleartext Signature\", Work in progress, " +
            externalWebReference ("https://openkeystore.googlecode.com/svn/resources/trunk/docs/jcs.html") +
            ", <span style=\"white-space: nowrap\">January&nbsp;2014.</span>");

        addReferenceEntry (REF_SKS, "Rundgren, A., \"Secure Key Store (SKS) - API and Architecture\", Work in progress, " +
            externalWebReference ("https://openkeystore.googlecode.com/svn/resources/trunk/docs/sks-api-arch.pdf") +
            ", <span style=\"white-space: nowrap\">V0.97, December 2013.</span>");

        addReferenceEntry (REF_WEBPKI_FOR_ANDROID, "\"WebPKI Suite\", " +
            externalWebReference ("https://play.google.com/store/apps/details?id=org.webpki.mobile.android"));

       addReferenceEntry (REF_JOSE,
            "Jones, M. et al, Work in progress, " +
            externalWebReference ("https://ietf.org/wg/jose/") +
            ", <span style=\"white-space: nowrap\">December&nbsp;2013.</span>");

        addReferenceEntry (REF_X509,
            "Cooper, D., Santesson, S., Farrell, S., Boeyen, S., " +
            "Housley, R., and W. Polk, \"Internet X.509 Public Key " +
            "Infrastructure Certificate and Certificate Revocation List " +
            "(CRL) Profile\", RFC&nbsp;5280, May&nbsp;2008.");

        addReferenceEntry (REF_BASE64,
            "Josefsson, S., \"The Base16, Base32, and Base64 Data " +
            "Encodings\", RFC&nbsp;4648, October&nbsp;2006.");

        addReferenceEntry (REF_PEM,
            "Josefsson, S., \"Text Encodings of PKIX and CMS Structures\", " +
            "I-D, draft-josefsson-pkix-textual-02, October&nbsp;2013.");

        addReferenceEntry (REF_DSKPP,
            "Doherty, A., Pei, M., Machani, S., and M. Nystrom, " +
            "\"Dynamic Symmetric Key Provisioning Protocol (DSKPP)\", RFC&nbsp;6063, December&nbsp;2010.");

        addReferenceEntry (REF_CMP, "Adams, C., Farrell, S., Kause, T., and T. Mononen, " +
             "\"Internet X.509 Public Key Infrastructure Certificate Management Protocol (CMP)\", " +
             "RFC&nbsp;4210, September&nbsp;2005.");

        addReferenceEntry (REF_LDAP_NAME, "Zeilenga, K., " +
            "\"Lightweight Directory Access Protocol (LDAP): String Representation of Distinguished Names\", " +
            "RFC&nbsp;4514, June&nbsp;2006.");

        addReferenceEntry (REF_PKCS8,
            "Kaliski, B., \"Public-Key Cryptography Standards (PKCS) #8: " +
            "Private-Key Information Syntax Specification Version 1.2\", " +
            "RFC&nbsp;5208, May&nbsp;2008.");

        addReferenceEntry (REF_BRAINPOOL, "Lochter, M., and J. Merkle, " +
            "\"Elliptic Curve Cryptography (ECC) Brainpool Standard Curves and Curve Generation\", " +
            "RFC&nbsp;5639, March&nbsp;2010.");

        addReferenceEntry (REF_FIPS186,
            "\"FIPS PUB 186-4: Digital Signature Standard (DSS)\", " +
            "U.S. Department of Commerce/National Institute of Standards and Technology, June&nbsp;2013.");
      }

    JSONBaseHTML () {}
    
    public static class Types 
      {
        public enum WEBPKI_DATA_TYPES 
          {
            ANY     ("any", "&quot;any&quot;",                            null,
                     "Arbitrary JSON type or object"),

            BOOLEAN ("bool",   "<code>true</code> or <code>false</code>", null,
                     "Boolean"),
                     
            BYTE    ("byte",   "<i>number</i>",                           null,
                     "Unsigned byte"),
                     
            SHORT   ("short",  "<i>number</i>",                           null,
                     "Unsigned two-byte integer"),
                     
            INT     ("int",    "<i>number</i>",                           null,
                     "Unsigned four-byte integer"),
                     
            BIGINT  ("bigint", "<i>number</i>",                           null,
                     "Big integer"),
                     
            STRING  ("string", "<i>string</i>",                           null,
                     "Arbitrary string"),
                     
            URI     ("uri",    "<i>string</i>",                           REF_URI,
                     "URI <a href=\"#Reference." + REF_URI + "\">[" + REF_URI + "]</a>"),

            ID      ("id",     "<i>string</i>",                           null,
                     "Identifier which <b>must</b> consist of 1-32 characters, where each character is in the range <code>'!'</code> - <code>'~'</code> (0x21 - 0x7e)."),
                     
            BASE64  ("base64", "<i>string</i>",                           REF_BASE64,
                     "Base64URL-encoded <a href=\"#Reference." + REF_BASE64 + "\">[" + REF_BASE64 + "]</a> binary data"),
                     
            CRYPTO  ("crypto", "<i>string</i>",                           REF_XMLDSIG,
                     "Base64URL-encoded positive integer. Note that leading zero-valued bytes <b>must</b> be discarded"),
                     
            DATE    ("date",   "<i>string</i>",                           null,
                     "ISO date-time <code>YYYY-MM-DDThh:mm:ss{timezone}</code>."),
                     
            OBJECT  ("object", "<code>{}</code>",                         null,
                     "JSON object");

            String data_type;
            String json;
            String ref;
            String description;
            boolean used;
            WEBPKI_DATA_TYPES (String data_type, String json, String ref, String description)
              {
                this.data_type = data_type;
                this.json = json;
                this.ref = ref;
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

            public String getRef ()
              {
                return ref;
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
        
        static final String LINK_PREFIX = "Datatype.";

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
                    s.append ("<tr id=\"" + LINK_PREFIX)
                     .append (type.getDataType ())
                     .append ("\"><td style=\"text-align:center\">")
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

    class References extends Content
      {
        References ()
          {
            super ();
          }

        @Override
        String getHTML () throws IOException
          {
            StringBuffer s = new StringBuffer ("<table class=\"tftable\" style=\"width:600pt\"><tr><th>Reference</th><th>Description</th></tr>");
            for (String reference : new TreeSet<String>(references.keySet()).toArray (new String[0]))
              {
                Reference r = references.get (reference);
                if (r.referenced)
                  {
                    s.append ("<tr><td id=\"")
                     .append ("Reference.")
                     .append (reference)
                     .append ("\" style=\"white-space:nowrap\">")
                     .append (brackit (reference))
                     .append ("</td><td>")
                     .append (r.html_description)
                     .append ("</td></tr>");
                  }
              }
            return s.append ("</table>").toString ();
          }
      }

    class TOC extends Content
      {
        TOC ()
          {
            super ();
          }

        @Override
        String getHTML () throws IOException
          {
            StringBuffer s = new StringBuffer ("<div><span style=\"font-size:" + 
                CHAPTER_FONT_SIZE + ";font-family:arial,verdana,helvetica\">" +
                "Table of Contents</span>" +
                "<table style=\"margin-left:20pt;margin-top:5pt\">");
            boolean new_tab = true;
            for (String toc_entry : toc.keySet ())
              {
                if (toc.get (toc_entry).appendix && new_tab)
                  {
                    new_tab = false;
                    s.append ("</table><table style=\"margin-left:20pt;margin-top:5pt\">");
                  }
                TOCEntry te = toc.get (toc_entry);
                s.append ("<tr style=\"white-space: nowrap\">")
                 .append (te.indented ? "<td></td><td style=\"width:15pt\"></td>" : te.PrefixPlusLink ())
                 .append (te.indented ? te.PrefixPlusLink () : "")
                 .append ("<td colspan=\"")
                 .append (te.remainingColums ())
                 .append ("\"><a href=\"#")
                 .append (te.link)
                 .append ("\">")
                 .append (te.getBeginItalic ())
                 .append (toc_entry)
                 .append (te.getEndItalic ())
                 .append ("</a></td></tr>");
              }
            return s.append ("</table></div>").toString ();
          }
      }

    public interface Extender
      {
        ProtocolObject.Row.Column execute (ProtocolObject.Row.Column column) throws IOException;
      }

    public interface RowInterface
      {
        ProtocolObject.Row newRow ();
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
            String property_link;
            
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
                        parent.property_link = makeLink (protocols[0]) + "." + (string.charAt (0) == '@' ? string.substring (1) : string);
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
                    if (type.getRef () != null)
                      {
                        createReference (type.getRef ());
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

                public Column addDataTypeLink (Types.WEBPKI_DATA_TYPES type) throws IOException
                  {
                    link (DataTypesTable.LINK_PREFIX + type.getDataType (), type.getDataType (), "");
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

                public Column setNotes (String notes) throws IOException
                  {
                    protocol_objects.lastElement ().setNotes (notes);
                    return this;
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
            StringBuffer s = new StringBuffer ("<tr><td colspan=\"4\" style=\"border-width:0px;font-size:" + SECTION_FONT_SIZE + ";padding:20pt 0pt 10pt 0pt;font-family:arial,verdana,helvetica;background-color:white\">");
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
                    .append (makeLink (protocol))
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
                                s.append ("<td style=\"text-align:center\" rowspan=\"")
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
                        s.append (q == 1 ? "<td style=\"white-space:nowrap\" id=\"" + row.property_link + "\">" : (q < 4 ? "<td style=\"text-align:center\">" : "<td>"));
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
                s.append ("<tr><td colspan=\"4\" style=\"background-color:white;border-width:0px;padding:10pt 0pt 0pt 0pt\">")
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

        void setNotes (String notes) throws IOException
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
    int local_toc_sec;

    public String getHTML () throws IOException
      {
        LinkedHashMap<String,TOCEntry> save = toc;
        toc = new LinkedHashMap<String,TOCEntry> ();
        for (String toc_entry : save.keySet ())
          {
            toc.put (toc_entry, save.get (toc_entry));
            if (toc_entry.equals (protocol_table_header))
              {
                for (ProtocolObject protocol_object : protocol_objects)
                  {
                    for (String prot : protocol_object.protocols)
                      {
                        TOCEntry te = new TOCEntry ();
                        te.link = makeLink (prot);
                        te.indented = true;
                        te.italic = !protocol_object.main_object;
                        toc.put (prot, te);
                      }
                  }
              }
          }
        
        html = new StringBuffer (
            "<!DOCTYPE html>" +
            "<html><head><title>")
        .append (subsystem_name)
        .append ("</title><meta http-equiv=Content-Type content=\"text/html; charset=utf-8\"><style type=\"text/css\">\n" +
                 ".tftable {border-collapse: collapse}\n" +
                 ".tftable th {font-size:10pt;background: linear-gradient(to bottom, #eaeaea 14%,#fcfcfc 52%,#e5e5e5 89%);border-width:1px;padding:4pt 10pt 4pt 10pt;border-style:solid;border-color: #a9a9a9;text-align:center;font-family:arial,verdana,helvetica}\n" +
                 ".tftable tr {background-color:#FFFFE0}\n" +
                 ".tftable td {font-size:10pt;border-width:1px;padding:4pt 8pt 4pt 8pt;border-style:solid;border-color:#a9a9a9;;font-family:arial,verdana,helvetica}\n" +
                 "div {font-size:10pt;padding:10pt 0pt 0pt 0pt;font-family:arial,verdana,helvetica}\n" +
                 "a:link {color:blue;font-family:verdana,helvetica;text-decoration:none}" +
                 "a:visited {color:blue;font-family:verdana,helvetica;text-decoration:none}" +
                 "a:active {color:blue;font-family:verdana,helvetica;text-decoration:none}");
        html.append (external_styles)
         .append("</style></head><body style=\"margin:15pt\">" +
                 "<div style=\"position:absolute;top:5pt;left:15pt;z-index:5;visibility:visible\"><a href=\"http://webpki.org\" title=\"WebPKI.org\">" +
                 "<img src=\"data:image/gif;base64,")
          .append (new Base64 (false).getBase64StringFromBinary (ArrayUtil.getByteArrayFromInputStream (getClass().getResourceAsStream ("webpki-logo.gif"))))
          .append ("\" style=\"border-width:1px;border-style:solid;border-color:blue;box-shadow:3pt 3pt 3pt #D0D0D0\" alt=\"WebPKI.org logo...\"></a></div>");
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

    public StringBuffer addParagraphObject () throws IOException
      {
        return addParagraphObject (null);
      }

    public StringBuffer addParagraphObject (String header) throws IOException
      {
        return addParagraphObject (header, true);
      }
    
    public StringBuffer addParagraphSubObject (String header) throws IOException
      {
        return addParagraphObject (header, false);
      }

    StringBuffer addParagraphObject (String header, boolean top_level) throws IOException
      {
        Paragraph p = new Paragraph ();
        StringBuffer s = new StringBuffer ("<div style=\"width:" + PAGE_WIDTH + "\">");
        if (header != null)
          {
            if (top_level)
              {
                curr_toc_seq++;
                local_toc_sec = 0;
              }
            else
              {
                local_toc_sec++;
              }
            TOCEntry te = new TOCEntry ();
            te.link = makeLink (header);
            te.sequence = curr_toc_seq;
            te.sub_seq = local_toc_sec;
            te.appendix = appendix_mode;
            te.indented = !top_level;
            te.prefix_on = true;
            if (toc.put (header, te) != null)
              {
                throw new IOException ("Duplicate TOC: " + header);
              }
            s.append ("<div style=\"padding:10pt 0pt 10pt 0pt\" id=\"")
             .append (te.link)
             .append ("\"><span style=\"font-size:" + (top_level ? CHAPTER_FONT_SIZE : SECTION_FONT_SIZE) + "\">")
             .append (te.getPrefix ())
             .append (header)
             .append ("</span></div>");
          }
        return p.local_html = s;
      }

    public void niceSquare (String html_in_div, int bottom_margin) throws IOException
      {
        addParagraphObject (null).append ("<table style=\"border-width:1px;padding:4pt 10pt 4pt 10pt;border-style:solid;border-color: #808080;margin-left:auto;margin-right:auto;box-shadow:3pt 3pt 3pt #D0D0D0;margin-bottom:")
                                 .append (bottom_margin)
                                 .append ("pt\"><tr><td>")
                                 .append (html_in_div)
                                 .append ("</td></tr></table>");
      }

    String makeLink (String header)
      {
        StringBuffer s = new StringBuffer ();
        for (char c : header.toCharArray ())
          {
            if (c == ' ')
              {
                c = '_';
              }
            s.append (c);
          }
        return s.toString ();
      }

    public void addDataTypesDescription (String intro) throws IOException
      {
        addParagraphObject ("Notation").append (intro).append (
            "JSON objects are described as tables with associated properties. When a property holds a JSON object this is denoted by a <a href=\"#Notation\">link</a> to the actual definition. " + Types.LINE_SEPARATOR +
            "Properties may either be <i>required</i> (" + MANDATORY + ") or <i>optional</i> (" + OPTIONAL + ") as defined in the &quot;" + REQUIRED_COLUMN + "&quot; column." + Types.LINE_SEPARATOR +
            "Array properties are identified by [&thinsp;]" + JSONBaseHTML.ARRAY_SUBSCRIPT  + "x-y</span> where the range expression represents the valid number of array elements. " + Types.LINE_SEPARATOR +
            "In some JSON objects there is a choice " +
            "from a set of <i>mutually exclusive</i> alternatives.<br>This is manifested in object tables like the following:" +
            "<table class=\"tftable\" style=\"font-style:italic;margin-top:10pt;margin-bottom:5pt\">" +
            "<tr><td>Property selection 1</td><td>Type selection 1</td><td rowspan=\"2\">Req</td><td>Comment selection 1</td></tr>" +
            "<tr><td>Property selection 2</td><td>Type selection 2</td><td>Comment selection 2</td></tr>" +
            "</table>");
        addParagraphObject ("Data Types").append ("The table below shows how the data types used by this specification are mapped into native JSON types:");
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

    String protocol_table_header;
    
    public StringBuffer addProtocolTableEntry (String header) throws IOException
      {
        StringBuffer s = addParagraphObject (protocol_table_header = header);
        new ProtocolTable ();
        return s;
      }

    public void addReferenceTable () throws IOException
      {
        addParagraphObject ("References");
        new References ();
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
                s.append ("<tr><td style=\"border-width:0px;height:10px;background-color:white\"></td></tr>");
              }
            else
              {
                next = true;
              }
            s.append ("<tr><th id=\"Sample.")
             .append (or.getString (JSONDecoderCache.QUALIFIER_JSON))
             .append ("\">")
             .append (or.getString (JSONDecoderCache.QUALIFIER_JSON))
             .append ("</th></tr><tr><td><code>")
             .append (new String (new JSONObjectWriter (or).serializeJSONObject (JSONOutputFormats.PRETTY_HTML), "UTF-8"))
             .append ("</code></td></tr>");
          }
        s.append ("</table>");
      }

    public String globalLinkRef (String name)
      {
        return "<a href=\"#" + name + "\">" + name +"</a>"; 
      }

    public String globalLinkRef (String parent, String name)
      {
        return "<a href=\"#" + parent + "." + name + "\">" + name +"</a>"; 
      }

    String brackit (String string)
      {
        return "[" + string + "]";
      }

    public void addReferenceEntry (String reference, String html_description) throws IOException
      {
        Reference r = new Reference ();
        r.html_description = html_description;
        Reference old = references.put (reference, r);
        if (old != null && !old.html_description.equals (html_description))
          {
            throw new IOException ("Reference ambigiously defined: " + reference);
          }
      }
    
    public String createReference (String reference) throws IOException
      {
        Reference r = references.get (reference);
        if (r == null)
          {
            throw new IOException ("No such reference: " + reference);
          }
        r.referenced = true;
        return "<a href=\"#Reference." + reference + "\">" + brackit (reference) +"</a>"; 
      }

    StringBuffer doc_history;
    
    public void addDocumentHistoryLine (String date, String version, String comment) throws IOException
      {
        if (doc_history == null)
          {
            doc_history = addParagraphObject ("Document History")
                       .append ("<table class=\"tftable\"><tr><th>Date</th><th>Ver</th><th>Comment</th></tr></table>");
          }
        doc_history.insert (doc_history.lastIndexOf ("</table>"), "<tr><td>" + date + "</td><td style=\"text-align:center\">" + version + "</td><td>" + comment + "</td></tr>");
      }

    public void addJSONSignatureDefinitions (boolean reference, String url_option, String extension_option) throws IOException
      {
        String jcs = reference ? "" : createReference (REF_JCS) + ": ";
        String option = reference ? "Option: " : createReference (REF_JCS) + " option: ";
        String sks_alg_ref = reference ? " " : " See SKS &quot;Algorithm Support&quot;." + Types.LINE_SEPARATOR;
       
        RowInterface row_interface = addSubItemTable (JSONSignatureDecoder.SIGNATURE_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.VERSION_JSON)
              .addValue (JSONSignatureDecoder.SIGNATURE_VERSION_ID)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.URI)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString (jcs)
              .addString ("<i>Optional</i> signature object version identifier.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.ALGORITHM_JSON)
              .addSymbolicValue (JSONSignatureDecoder.ALGORITHM_JSON)
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
              .addString ("For detailed descriptions of these algorithms, see XML&nbsp;DSig " + createReference (REF_XMLDSIG) + ".")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.KEY_INFO_JSON)
              .addLink (JSONSignatureDecoder.KEY_INFO_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("Signature key information placeholder.");
        if (extension_option != null)
          {
            row_interface = row_interface
              .newRow ()
                .newColumn ()
                  .addProperty (JSONSignatureDecoder.EXTENSIONS_JSON)
                  .addArrayLink (JSONSignatureDecoder.EXTENSIONS_JSON, 1)
                .newColumn ()
                  .setType (Types.WEBPKI_DATA_TYPES.OBJECT)
                .newColumn ()
                  .setUsage (false)
                .newColumn ()
                  .addString (jcs)
                  .addString ("<i>Optional</i> array holding custom extension objects like time-stamps, CRLs, and OCSP responses.")
                  .addString (extension_option);
          }
        row_interface
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.SIGNATURE_VALUE_JSON)
              .addSymbolicValue (JSONSignatureDecoder.SIGNATURE_VALUE_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("The signature value is calculated by applying the algorithm specified in <code>" +
                  JSONSignatureDecoder.ALGORITHM_JSON + "</code> using the key specified in <code>" +
                  JSONSignatureDecoder.KEY_INFO_JSON +
                  "</code> on the <span style=\"white-space:nowrap\">UTF-8</span> representation of the " +
                  "canonicalized JSON object.");

        row_interface = addSubItemTable (JSONSignatureDecoder.KEY_INFO_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.KEY_ID_JSON)
              .addSymbolicValue (JSONSignatureDecoder.KEY_ID_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.STRING)
            .newColumn ()
              .setChoice (true, url_option == null ? 3 : 4)
            .newColumn ()
              .addString (option)
              .addString ("Symmetric key ID.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.PUBLIC_KEY_JSON)
              .addLink (JSONSignatureDecoder.PUBLIC_KEY_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString (option)
              .addString ("Public key.");
        if (url_option!= null)
          {
            row_interface = row_interface
              .newRow ()
                .newColumn ()
                  .addProperty (JSONSignatureDecoder.URL_JSON)
                  .addSymbolicValue (JSONSignatureDecoder.URL_JSON)
                .newColumn ()
                  .setType (Types.WEBPKI_DATA_TYPES.URI)
                .newColumn ()
                .newColumn ()
                  .addString (option)
                  .addString ("A single public key or X.509 ")
                  .addString (createReference (REF_X509))
                  .addString (" certificate path stored in a PEM ")
                  .addString (createReference (REF_PEM))
                  .addString (" file accessible via an HTTP&nbsp;URL." + 
                              Types.LINE_SEPARATOR +
                              "The <i>signing key's</i> algorithm <b>must</b> be compatible with those specified for ")
                  .addLink (JSONSignatureDecoder.PUBLIC_KEY_JSON)
                  .addString (".")
                  .addString (url_option);
              }
        row_interface
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON)
              .addArrayList (Types.SORTED_CERT_PATH, 1)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.BASE64)
            .newColumn ()
            .newColumn ()
              .addString (option)
              .addString ("Sorted X.509 ")
              .addString (createReference (REF_X509))
              .addString (" certificate path where the <i>first</i> array element <b>must</b> contain the <i style=\"white-space:nowrap\">signature certificate</i>. " +
                          "The certificate path <b>must</b> be <i>contiguous</i> but is not required to be complete." + Types.LINE_SEPARATOR +
                          "The <i>signing key's</i> algorithm <b>must</b> be compatible with those specified for ")
              .addLink (JSONSignatureDecoder.PUBLIC_KEY_JSON)
              .addString (".")   .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.SIGNATURE_CERTIFICATE_JSON)
              .addLink (JSONSignatureDecoder.SIGNATURE_CERTIFICATE_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
              .setUsage (false)
            .newColumn ()
              .addString (jcs)
              .addString ("<i>Optional</i> signature certificate attribute data for usage with the <code>" +
                          JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON + "</code> option." + Types.LINE_SEPARATOR +
                          "A compliant JCS implementation <b>must</b> verify that the <code>" + JSONSignatureDecoder.SIGNATURE_CERTIFICATE_JSON +
                          "</code> object matches the first certificate in the <code>" + JSONSignatureDecoder.X509_CERTIFICATE_PATH_JSON +
                          "</code>.");

        addSubItemTable (JSONSignatureDecoder.PUBLIC_KEY_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.EC_JSON)
              .addLink (JSONSignatureDecoder.EC_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
              .setChoice (true, 2)
            .newColumn ()
              .addString (option)
              .addString ("EC public key.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.RSA_JSON)
              .addLink (JSONSignatureDecoder.RSA_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.OBJECT)
            .newColumn ()
            .newColumn ()
              .addString (option)
              .addString ("RSA public key. <i>Algorithm restrictions</i>: 1024-4096 bit keys appear to work just about &quot;everywhere&quot;.");

        addSubItemTable (JSONSignatureDecoder.EC_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.NAMED_CURVE_JSON)
              .addSymbolicValue (JSONSignatureDecoder.NAMED_CURVE_JSON)
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
  "The NIST algorithms are described in FIPS 186-4 " + createReference (REF_FIPS186) +
  ", while Brainpool algorithms are covered by RFC&nbsp;5639 " + createReference (REF_BRAINPOOL) + ". " + Types.LINE_SEPARATOR +
  "The algorithm names were derived from the SKS " + createReference (REF_SKS) + " specification. " + Types.LINE_SEPARATOR +
  "Compatible EC curves may also be expressed in the XML&nbsp;DSig " +  createReference (REF_XMLDSIG) +
  " notation (<code>urn:oid:1.2.840.10045.3.1.7</code>).": "")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.X_JSON)
              .addSymbolicValue (JSONSignatureDecoder.X_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.CRYPTO)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("EC curve point X. Also see the ")
              .addDataTypeLink (Types.WEBPKI_DATA_TYPES.CRYPTO)
              .addString (" data type.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.Y_JSON)
              .addSymbolicValue (JSONSignatureDecoder.Y_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.CRYPTO)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("EC curve point Y. Also see the ")        
              .addDataTypeLink (Types.WEBPKI_DATA_TYPES.CRYPTO)
             .addString (" data type.");

        addSubItemTable (JSONSignatureDecoder.RSA_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.MODULUS_JSON)
              .addSymbolicValue (JSONSignatureDecoder.MODULUS_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.CRYPTO)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("RSA modulus. Also see the ")
              .addDataTypeLink (Types.WEBPKI_DATA_TYPES.CRYPTO)
              .addString (" data type.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.EXPONENT_JSON)
              .addSymbolicValue (JSONSignatureDecoder.EXPONENT_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.CRYPTO)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("RSA exponent. Also see the ")
              .addDataTypeLink (Types.WEBPKI_DATA_TYPES.CRYPTO)
              .addString (" data type.");

        addSubItemTable (JSONSignatureDecoder.SIGNATURE_CERTIFICATE_JSON)
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.ISSUER_JSON)
              .addSymbolicValue (JSONSignatureDecoder.ISSUER_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.STRING)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("Issuer distinguished name in LDAP ")
              .addString (createReference (REF_LDAP_NAME))
              .addString (" notation.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.SERIAL_NUMBER_JSON)
              .addUnquotedValue (JSONSignatureDecoder.SERIAL_NUMBER_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.BIGINT)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("Certificate serial number.")
          .newRow ()
            .newColumn ()
              .addProperty (JSONSignatureDecoder.SUBJECT_JSON)
              .addSymbolicValue (JSONSignatureDecoder.SUBJECT_JSON)
            .newColumn ()
              .setType (Types.WEBPKI_DATA_TYPES.STRING)
            .newColumn ()
            .newColumn ()
              .addString (jcs)
              .addString ("Subject distinguished name in LDAP ")
              .addString (createReference (REF_LDAP_NAME))
              .addString (" notation.");

        if (extension_option != null)
          {
            addSubItemTable (JSONSignatureDecoder.EXTENSIONS_JSON)
              .newRow ()
                .newColumn ()
                  .addProperty (JSONSignatureDecoder.TYPE_JSON)
                  .addSymbolicValue (JSONSignatureDecoder.TYPE_JSON)
                .newColumn ()
                  .setType (Types.WEBPKI_DATA_TYPES.URI)
                .newColumn ()
                .newColumn ()
                  .addString (jcs)
                  .addString ("Mandatory unique extension type.")
              .newRow ()
                .newColumn ()
                  .addProperty ("...")
                  .addUnquotedValue ("<code>...</code>")
                .newColumn ()
                  .setType (Types.WEBPKI_DATA_TYPES.ANY)
                .newColumn ()
                  .setUsage (false)
                .newColumn ()
                  .addString (jcs)
                  .addString ("Extension-specfic properties.");
          }
      }

    public void addTOC ()
      {
        new TOC ();
      }

    public void setAppendixMode ()
      {
        curr_toc_seq = 0;
        appendix_mode = true;
      }
  }
