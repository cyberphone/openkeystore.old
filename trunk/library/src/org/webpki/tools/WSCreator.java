/*
 *  Copyright 2006-2011 WebPKI.org (http://webpki.org).
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
package org.webpki.tools;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Vector;
import java.io.FileOutputStream;
import java.io.File;
import java.io.IOException;

import org.webpki.util.ArrayUtil;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.XMLSchemaCache;

/*
 * From an XML description file create Web Services artifacts.
 * @author Anders Rundgren
 */
public class WSCreator extends XMLObjectWrapper
  {
    private static final String JCLIENT = "jclient";
    private static final String JSERVER = "jserver";
    private static final String JCOMMON = "jcommon";
    private static final String WSDL = "wsdl";
    private static final String DOTNETCLIENT = "dotnetclient";
    
    private static boolean jclient;
    private static boolean jserver;
    private static boolean jcommon;
    private static boolean wsdl_gen;
    private static boolean dotnet_gen;
    
    private static String output_directory;
    
    private FileOutputStream wsdl_file;
    
    DOMAttributeReaderHelper attr;
    
    private String tns;
    
    private String service_name;
    
    private String default_url;
    
    static class DataType
    {
      boolean nullable;
      String xsd_name;
      String enum_name;
      String csname;
      String jname;
      DataType (boolean nullable, String xsd_name, String enum_name, String csname, String jname)
      {
        this.nullable = nullable;
        this.xsd_name = xsd_name;
        this.enum_name = enum_name;
        this.csname = csname;
        this.jname = jname;
      }
    }
    
    static Vector<DataType> types = new Vector<DataType> ();
    
    static
    {
      types.add (new DataType (false, "xs:int",          "int",     "int",     "int"));
      types.add (new DataType (false, "xs:short",        "short",   "short",   "short"));
      types.add (new DataType (false, "xs:byte",         "byte",    "sbyte",   "byte"));
      types.add (new DataType (false, "xs:boolean",      "boolean", "boolean", "boolean"));
      types.add (new DataType (true,  "xs:string",       "string",  "string",  "String"));
      types.add (new DataType (true,  "xs:base64Binary", "binary",  "byte[]",  "byte[]"));
    }
  
    class Property extends Container
      {
        String type;
        
        String xsd_name;
        
        boolean nullable;
        
        boolean listtype;
      }
    
    abstract class Container
      {
        String name;
        String xml_name;
        
        public String getXMLName ()
          {
            return xml_name == null ? name : xml_name;
          }

      }
    
    class Method extends Container
      {
        String[] execptions;
        
        public String getXMLResponseName ()
          {
            return getXMLName () + "Response";
          }
        Collection<Property> inputs;
        Collection<Property> outputs;
      }

    class WSException extends Container
      {
        Collection<Property> properties;
    
      }
    
    private HashSet<String> xml_names = new HashSet <String> ();
    private LinkedHashMap<String,WSException> exceptions = new LinkedHashMap<String,WSException> ();
    private Vector<Method> methods = new Vector<Method> ();

  @Override
  protected boolean hasQualifiedElements ()
    {
      return true;
    }

  @Override
  protected void init () throws IOException
    {
      addSchema ("wscreator.xsd");
    }

  @Override
    protected void fromXML (DOMReaderHelper rd) throws IOException
      {
        attr = rd.getAttributeHelper ();
        wsdl_file = open (wsdl_gen);
        tns = attr.getString ("NameSpace");
        default_url = attr.getString ("DefaultURL");
        service_name = attr.getString ("Service");
        write (wsdl_file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + 
               "<wsdl:definitions targetNamespace=\"" + tns + "\"\n" + 
               "                  xmlns:wsdl=\"http://schemas.xmlsoap.org/wsdl/\"\n" + 
               "                  xmlns:tns=\"" + tns + "\"\n" + 
               "                  xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"\n" + 
               "                  xmlns:soap=\"http://schemas.xmlsoap.org/wsdl/soap/\">\n\n" +
               "  <wsdl:types>\n\n" + 
               "    <xs:schema targetNamespace=\"" + tns + "\"\n" + 
               "               xmlns:tns=\"" + tns + "\"\n" + 
               "               elementFormDefault=\"qualified\" attributeFormDefault=\"unqualified\">\n");

        rd.getChild ();
        while (rd.hasNext ("Exception"))
          {
            rd.getNext ("Exception");
            WSException exception = new WSException ();
            exception.name = attr.getString ("Name");
            exception.xml_name = attr.getStringConditional ("XMLName");
            rd.getChild ();
            exception.properties = getProperties (rd, "Property");
            rd.getParent ();
            exceptions.put (exception.name, exception);
          }
        do
          {
            rd.getNext ("Method");
            Method method = new Method ();
            method.name = attr.getString ("Name");
            method.xml_name = attr.getStringConditional ("XMLName");
            method.execptions = attr.getListConditional ("Throws");
            if (method.execptions == null) method.execptions = new String[0];
            rd.getChild ();
            method.inputs = getProperties (rd, "Input");
            method.outputs = getProperties (rd, "Output");
            rd.getParent ();
            for (String exception : method.execptions)
              {
                if (!exceptions.containsKey (exception))
                  {
                    bad ("Exception '" + exception + "' missing declaration");
                  }
              }
            methods.add (method);
          }
        while (rd.hasNext ("Method"));
        
        for (WSException exception : exceptions.values ())
          {
            write (wsdl_file, "\n" + 
                "      <xs:element name=\"" + exception.getXMLName () + "\">\n" + 
                "        <xs:complexType>\n" + 
                "          <xs:sequence>\n");
            writeWSDLProperties (exception.properties);
            write (wsdl_file, 
                "          </xs:sequence>\n" + 
                "        </xs:complexType>\n" + 
                "      </xs:element>\n");
          }

        for (Method meth : methods)
          {
            write (wsdl_file, "\n" + 
                "      <xs:element name=\"" + meth.getXMLName () + "\">\n" + 
                "        <xs:complexType>\n" + 
                "          <xs:sequence>\n");
            writeWSDLProperties (meth.inputs);
            write (wsdl_file,
                "          </xs:sequence>\n" + 
                "        </xs:complexType>\n" + 
                "      </xs:element>\n\n" + 
                "      <xs:element name=\"" + meth.getXMLResponseName () + "\">\n" + 
                "        <xs:complexType>\n" + 
                "          <xs:sequence>\n"); 
            writeWSDLProperties (meth.outputs);
            write (wsdl_file,
                "          </xs:sequence>\n" + 
                "        </xs:complexType>\n" + 
                "      </xs:element>\n");
          }

        write (wsdl_file, "\n    </xs:schema>\n\n  </wsdl:types>\n");
        
        for (WSException exception : exceptions.values ())
          {
            write (wsdl_file, "\n" + 
                "  <wsdl:message name=\"" + exception.getXMLName () + "\">\n" + 
                "    <wsdl:part name=\"fault\" element=\"tns:" + exception.getXMLName () + "\"/>\n" + 
                "  </wsdl:message>\n");
          }

        for (Method meth : methods)
          {
            write (wsdl_file, "\n" + 
                "  <wsdl:message name=\"" + meth.getXMLName () + "\">\n" + 
                "    <wsdl:part name=\"parameters\" element=\"tns:" + meth.getXMLName () + "\"/>\n" + 
                "  </wsdl:message>\n\n" + 
                "  <wsdl:message name=\"" + meth.getXMLResponseName () + "\">\n" + 
                "    <wsdl:part name=\"parameters\" element=\"tns:" + meth.getXMLResponseName () + "\"/>\n" + 
                "  </wsdl:message>\n");
          }

        write (wsdl_file, "\n  <wsdl:portType name=\"" + service_name + ".Interface\">\n");

        for (Method meth : methods)
          {
            write (wsdl_file, "\n" + 
                "    <wsdl:operation name=\"" + meth.getXMLName () + "\">\n" + 
                "      <wsdl:input message=\"tns:" + meth.getXMLName () + "\"/>\n" + 
                "      <wsdl:output message=\"tns:" + meth.getXMLResponseName () + "\"/>\n");
            for (String exception : meth.execptions)
              {
                String xml_name = exceptions.get (exception).getXMLName ();
                write (wsdl_file,
                    "      <wsdl:fault message=\"tns:" + xml_name + "\" name=\"" + xml_name + "\"/>\n");
              }
            write (wsdl_file, "    </wsdl:operation>\n");
            /*
             * <wsdl:operation name="abortProvisioningSession"> <wsdl:input
             * message="SKS:abortProvisioningSession"/> <wsdl:output
             * message="SKS:abortProvisioningSessionResponse"/> 
             * <wsdl:fault message="SKS:SKSException" name="SKSException"/>
             * </wsdl:operation>
             */
          }

        write (wsdl_file, "\n  </wsdl:portType>\n\n" +
            "  <wsdl:binding name=\"" + service_name + ".PortBinding\" type=\"tns:" + service_name + ".Interface\">\n" +
            "    <soap:binding style=\"document\" transport=\"http://schemas.xmlsoap.org/soap/http\"/>\n");

        for (Method meth : methods)
          {
            write (wsdl_file, "\n" + 
                "      <wsdl:operation name=\"" + meth.getXMLName () + "\">\n" + 
                "        <wsdl:input>\n" +
                "          <soap:body use=\"literal\"/>\n" +
                "        </wsdl:input>\n" +
                "        <wsdl:output>\n" +
                "          <soap:body use=\"literal\"/>\n" +
                "        </wsdl:output>\n");
                for (String exception : meth.execptions)
                  {
                    String xml_name = exceptions.get (exception).getXMLName ();
                    write (wsdl_file,
                        "        <wsdl:fault name=\"" + xml_name + "\">\n" +
                        "          <soap:fault name=\"" + xml_name + "\" use=\"literal\"/>\n" +
                        "        </wsdl:fault>\n");
                  }
                write (wsdl_file, "      </wsdl:operation>\n");
            /*
    <wsdl:operation name="getVersion">
      <soap:operation soapAction=""/>
      <wsdl:input>
        <soap:body use="literal"/>
      </wsdl:input>
      <wsdl:output>
        <soap:body use="literal"/>
      </wsdl:output>
      <wsdl:fault name="SKSException">
        <soap:fault name="SKSException" use="literal"/>
      </wsdl:fault>
    </wsdl:operation>
             */
          }

        write (wsdl_file, "\n    </wsdl:binding>\n\n" +
            "  <wsdl:service name=\""+ service_name + "\">\n" +
            "     <wsdl:port name=\"" + service_name + ".Port\" binding=\"tns:" + service_name + ".PortBinding\">\n" +
            "       <soap:address location=\"" + default_url + "\"/>\n" +
            "     </wsdl:port>\n" +
            "  </wsdl:service>\n\n" +
            "</wsdl:definitions>\n");
        close (wsdl_file);
      }

  private void writeWSDLProperties (Collection<Property> properties) throws IOException
    {
      for (Property property : properties)
        {
          write (wsdl_file,
              "            <xs:element name=\"" + property.getXMLName () +
                   "\" type=\"" + property.xsd_name + "\"" + 
                   (property.nullable ? " minOccurs=\"0\"" : "") +
                   (property.listtype ? " maxOccurs=\"unbounded\"" : "") +
                   "/>\n");
        }
    }

  private Collection<Property> getProperties (DOMReaderHelper rd, String property) throws IOException
    {
      LinkedHashMap<String,Property> props = new LinkedHashMap<String,Property> ();
      HashSet<String> xsd_names = new HashSet<String> ();
      while (rd.hasNext (property))
        {
          rd.getNext ();
          Property prop = new Property ();
          prop.name = attr.getString ("Name");
          prop.xml_name = attr.getStringConditional ("XMLName");
          if (xsd_names.add (prop.getXMLName ()))
            {
              bad ("Duplicate XML name: " + prop.getXMLName ());
            }
          prop.type = attr.getString ("Type");
          prop.nullable = attr.getBoolean ("Null");
          prop.listtype = attr.getBoolean ("List");
          for (DataType type : types)
            {
              if (type.enum_name.equals (prop.type))
                {
                  prop.xsd_name = type.xsd_name;
                  break;
                }
            }
          if (prop.xsd_name == null)
            {
              bad ("Type '" + prop.type + "' not found");
            }
          if (props.put (prop.name, prop) != null)
            {
              bad ("Duplicate property: " + prop.name);
            }
        }
      return props.values ();
    }

  private void bad (String string) throws IOException
    {
      throw new IOException (string);
    }

  private void close (FileOutputStream file) throws IOException
    {
      if (file != null) file.close ();
    }

  private void write (FileOutputStream file, String data) throws IOException
    {
      if (file != null)
        {
          file.write (data.getBytes ("UTF-8"));
        }
    }
  
    private FileOutputStream open (boolean open_it) throws IOException
      {
        if (open_it)
          {
            return new FileOutputStream (output_directory);
          }
        return null;
      }

  private FileOutputStream open (String base_file_name, boolean open_it) throws IOException
    {
System.out.println ("f=" + output_directory + File.separatorChar + base_file_name);
      if (open_it)
        {
          return new FileOutputStream (output_directory + File.separatorChar + base_file_name);
        }
      return null;
    }

  @Override
  protected void toXML (DOMWriterHelper ws) throws IOException
    {
      // TODO Auto-generated method stub
      
    }

  @Override
  public String namespace ()
    {
      return "http://xmlns.webpki.org/wscreator.1.00";
    }

  @Override
  public String element ()
    {
      return "WebService";
    }
  
  private static void show ()
    {
      System.out.println (WSCreator.class.getName () + " '" + JCLIENT + "'|'" +
                                                              JSERVER + "'|'" +
                                                              JCOMMON + "'|'" +
                                                              WSDL + "'|'" +
                                                              DOTNETCLIENT + "' input-file output-directory\n" +
                             "Note: output-directory is actually file-name for the '" + WSDL + "' option");
      System.exit (3);
    }
  
  public static void main (String args[]) throws IOException
    {
      if (args.length != 3) show ();
      if (args[0].equals (JCLIENT)) jclient = true;
      else if (args[0].equals (JSERVER)) jserver = true;
      else if (args[0].equals (JCOMMON)) jcommon = true;
      else if (args[0].equals (WSDL)) wsdl_gen = true;
      else if (args[0].equals (DOTNETCLIENT)) dotnet_gen = true;
      else show ();
      output_directory = args[2];
      XMLSchemaCache xsc = new XMLSchemaCache ();
      xsc.addWrapper (WSCreator.class);
      WSCreator wsc = (WSCreator) xsc.parse (ArrayUtil.readFile (args[1]));
    }

  }
