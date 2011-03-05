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
import java.util.TreeSet;
import java.util.Vector;

import java.io.FileOutputStream;
import java.io.File;
import java.io.IOException;

import javax.xml.bind.annotation.XmlElement;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.XMLSchemaCache;

/**
 * From an XML description file create Web Services artifacts.
 * @author Anders Rundgren
 */
public class WSCreator extends XMLObjectWrapper
  {
    private static final String JCLIENT = "jclient";
    private static final String JSERVER = "jserver";
    private static final String WSDL = "wsdl";
    private static final String DOTNETCLIENT = "dotnetclient";
    
    private static final String VERSION = "1.0";
    
    private static boolean jclient;
    private static boolean jserver;
    private static boolean jcommon;
    private static boolean wsdl_gen;
    private static boolean dotnet_gen;
    
    private static String output_directory;
    
    private FileOutputStream wsdl_file;
    
    private String license_header = "";
    
    abstract class Package
    {
      FileOutputStream jfile;
      String class_name;
      String class_header = "";
      String package_name;
      String path;
      boolean next;
      boolean schema_validation;
      String support_code ="";
      
      abstract String decoration ();
      
      abstract String class_interface ();
      
      Package (DOMReaderHelper rd, String elem)
      {
        rd.getNext (elem);
        schema_validation = attr.getBooleanConditional ("SchemaValidation");
        String canonicalized_class_name = attr.getString ("ClassName");
        class_name = canonicalized_class_name;
        path = output_directory;
        int i = canonicalized_class_name.lastIndexOf ('.');
        if (i > 0)
          {
            class_name = canonicalized_class_name.substring (i + 1);
            package_name = canonicalized_class_name.substring (0, i);
            path += File.separatorChar;
            for (int j = 0; j < i; j++)
              {
                path += canonicalized_class_name.charAt (j) == '.' ? File.separatorChar : canonicalized_class_name.charAt (j);  
              }
          }
        rd.getChild ();
        if (rd.hasNext ())
          {
            class_header = rd.getString ("ClassHeader");
          }
        rd.getParent ();
      }

      void genSlashes (String gen) throws IOException 
        {
          for (int i = 0; i < gen.length (); i++)
            {
              write (jfile, "/");
            }
          write (jfile, "\n");
        }
      public void writePackage () throws IOException
      {
        write (jfile, license_header);
        if (package_name != null)
          {
            writeln (jfile, "package " + package_name + ";");
          }
        String gen = "// Created by " + WSCreator.class.getSimpleName () + " " + VERSION + " - Do not edit! //";
        write (jfile, "\n");
        genSlashes (gen);
        writeln (jfile, gen);
        genSlashes (gen);
      }
      public void writeImports () throws IOException
      {
        String last_import_pack ="";
        for (String impstr : jimports)
          {
            int i = impstr.lastIndexOf ('.');
            if (!last_import_pack.equals (impstr.substring (0, i)))
              {
                write (jfile, "\n");
                last_import_pack = impstr.substring (0, i);
              }
            writeln (jfile, "import " + impstr + ";");
          }
      }
    }
    
    class ServerPack extends Package
    {
      ServerPack (DOMReaderHelper rd)
      {
        super (rd, "JavaServer");
      }
      String decoration ()
        {
          return ",\n" + "" +
                 "            name=\"" + service_name + ".Interface\",\n" +
                 "            portName=\"" + service_name + ".Port\",\n" +
                 "            wsdlLocation=\"" +wsdl_location + "\"";
        }

      String class_interface ()
        {
          return "class";
        }
     
    }
    class ClientPack extends Package
    {
      ClientPack (DOMReaderHelper rd)
        {
          super (rd, "JavaClient");
        }

      String decoration ()
        {
          return "";
        }

      String class_interface ()
        {
          return "interface";
        }

      public void openAddedClass (String class_name) throws IOException
        {
          jimports.clear ();
          jfile = new FileOutputStream (path + File.separatorChar + class_name + ".java");
          writePackage ();
        }

    }
   
    ServerPack jserver_pck;

    ClientPack jclient_pck;
    
    TreeSet<String> jimports = new TreeSet<String> ();
  
    DOMAttributeReaderHelper attr;
    
    private String tns;
    
    private boolean qualified_ns;
    
    String wsdl_location;

    String sub_target_ns;
    
    private String service_name;
    
    private String default_url;
    
   
    static class DataType
    {
      boolean nullable;
      String xsd_name;
      String enum_name;
      String csname;
      String jname;
      String jholder;
      DataType (boolean nullable, String xsd_name, String enum_name, String csname, String jname, String jholder)
      {
        this.nullable = nullable;
        this.xsd_name = xsd_name;
        this.enum_name = enum_name;
        this.csname = csname;
        this.jname = jname;
        this.jholder = jholder;
      }
    }
    
    static Vector<DataType> types = new Vector<DataType> ();
    
    static
    {
      types.add (new DataType (false, "xs:int",          "int",     "int",     "int",     "Integer"));
      types.add (new DataType (false, "xs:short",        "short",   "short",   "short",   "Short"));
      types.add (new DataType (false, "xs:byte",         "byte",    "sbyte",   "byte",    "Byte"));
      types.add (new DataType (false, "xs:boolean",      "boolean", "boolean", "boolean", "Boolean"));
      types.add (new DataType (true,  "xs:string",       "string",  "string",  "String",  "String"));
      types.add (new DataType (true,  "xs:base64Binary", "binary",  "byte[]",  "byte[]",  "byte[]"));
    }
  
    class Property extends Container
      {
        DataType data_type;
        
        boolean nullable;
        
        boolean listtype;
        
        String jName (boolean object_type)
          {
            return object_type || listtype ? (listtype ? "List<" + data_type.jholder + ">" : data_type.jholder) : data_type.jname;
          }
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
        
        String code;
        
        public String getXMLResponseName ()
          {
            return getXMLName () + ".Response";
          }
        Collection<Property> inputs;
        Collection<Property> outputs;
      }

    class WSException extends Container
      {
        String class_name;
        
        String getName ()
          {
            return jclient ? name + "_Exception" : name;
          }
        
        String getBeanName ()
          {
            return name + "Bean";
          }
        
        Collection<Property> properties;
    
      }
    
    private HashSet<String> xml_names = new HashSet <String> ();
    private LinkedHashMap<String,WSException> exceptions = new LinkedHashMap<String,WSException> ();
    private Vector<Method> methods = new Vector<Method> ();
    private boolean add_main;

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
        if (wsdl_gen)
          {
            wsdl_file = new FileOutputStream (output_directory);
          }
        tns = attr.getString ("NameSpace");
        default_url = attr.getString ("DefaultURL");
        service_name = attr.getString ("Service");
        qualified_ns = attr.getBoolean ("Qualified");
        wsdl_location = attr.getString ("WSDLLocation");
        sub_target_ns = qualified_ns ? "\", targetNamespace=\"" + tns + "\"" : "\"";
        write (wsdl_file, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" + 
               "<wsdl:definitions targetNamespace=\"" + tns + "\"\n" + 
               "                  xmlns:wsdl=\"http://schemas.xmlsoap.org/wsdl/\"\n" + 
               "                  xmlns:tns=\"" + tns + "\"\n" + 
               "                  xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"\n" + 
               "                  xmlns:soap=\"http://schemas.xmlsoap.org/wsdl/soap/\">\n\n" +
               "  <wsdl:types>\n\n" + 
               "    <xs:schema targetNamespace=\"" + tns + "\"\n" + 
               "               elementFormDefault=\"" + (qualified_ns ? "qualified" : "unqualified") + "\" attributeFormDefault=\"unqualified\">\n");

        rd.getChild ();
        
        addImport ("javax.jws.WebMethod");
        addImport ("javax.jws.WebService");
        
        addImport("javax.xml.ws.RequestWrapper");
        addImport("javax.xml.ws.ResponseWrapper");

        if (rd.hasNext ("LicenseHeader"))
          {
            license_header = rd.getString ("LicenseHeader");
          }

        if (rd.hasNext ("JavaServer"))
          {
            jserver_pck = new ServerPack (rd);
            if (jserver)
              {
                open (jserver_pck, true);
                String[] imports = attr.getListConditional ("Imports");
                if (imports != null)
                  {
                    for (String string : imports)
                      {
                        addImport (string);
                      }
                  }
                if (add_main = attr.getBooleanConditional ("AddMain"))
                  {
                    addImport ("javax.xml.ws.Endpoint");
                  }
              }
            rd.getChild ();
            if (rd.hasNext ("SupportCode"))
              {
                jserver_pck.support_code = rd.getString ("SupportCode");
              }
            rd.getParent ();
          }
        else if (jserver)
          {
            bad ("The '" + JSERVER + "' option requires a \"JavaServer\" definition!");
          }
        if (rd.hasNext ("JavaClient"))
          {
            jclient_pck = new ClientPack (rd);
            if (jclient)
              {
                open (jclient_pck, true);
              }
          }
        else if (jclient)
          {
            bad ("The '" + JCLIENT + "' option requires a \"JavaClient\" definition!");
          }
        while (rd.hasNext ("Exception"))
          {
            rd.getNext ("Exception");
            WSException exception = new WSException ();
            exception.name = exception.class_name = attr.getString ("ClassName");
            if (jserver)
              {
                addImport (exception.name);
              }
            int i = exception.name.lastIndexOf ('.');
            if (i++ > 0)
              {
                exception.name = exception.name.substring (i);
              }
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
            if (method.outputs.size () == 1)
              {
                addImport ("javax.jws.WebResult");
              }
            else if (method.outputs.size () > 1)
              {
                addImport ("javax.jws.WebParam");
                addImport ("javax.xml.ws.Holder");
              }
            String code = rd.getStringConditional ("Code");
            method.code = jserver ? "\n      {" + (code == null? "\n" : code) + "      }" : ";";
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
            "  <wsdl:binding name=\"" + service_name + ".Binding\" type=\"tns:" + service_name + ".Interface\">\n" +
            "    <soap:binding style=\"document\" transport=\"http://schemas.xmlsoap.org/soap/http\"/>\n");
        
        javaHeader (jserver_pck);
        javaHeader (jclient_pck);

         for (Method meth : methods)
          {
            javaMethod (jserver_pck, meth);
            javaMethod (jclient_pck, meth);
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
          }

        write (wsdl_file, "\n    </wsdl:binding>\n\n" +
            "  <wsdl:service name=\""+ service_name + "\">\n" +
            "     <wsdl:port name=\"" + service_name + ".Port\" binding=\"tns:" + service_name + ".Binding\">\n" +
            "       <soap:address location=\"" + default_url + "\"/>\n" +
            "     </wsdl:port>\n" +
            "  </wsdl:service>\n\n" +
            "</wsdl:definitions>\n");
        close (wsdl_file);
        javaTerminate (jserver_pck);
        javaTerminate (jclient_pck);
        if (jclient)
          {
            for (WSException wse : exceptions.values ())
              {
                jclient_pck.openAddedClass (wse.getBeanName ());
                addImport ("javax.xml.bind.annotation.XmlAccessType");
                addImport ("javax.xml.bind.annotation.XmlAccessorType");
                addImport ("javax.xml.bind.annotation.XmlElement");
                addImport ("javax.xml.bind.annotation.XmlType");
                for (Property prop : wse.properties)
                  {
                    if (prop.listtype)
                      {
                        addImport ("java.util.List");
                      }
                  }
                jclient_pck.writeImports ();
                write (jclient_pck.jfile, "\n" +
                    "@XmlAccessorType(XmlAccessType.NONE)\n" +
                    "@XmlType(propOrder={");
                boolean next = false;
                for (Property prop : wse.properties)
                  {
                    if (next)
                      {
                        write (jclient_pck.jfile, ",\n                    ");
                      }
                    else
                      {
                        next = true;
                      }
                    write (jclient_pck.jfile, "\"" + prop.name + "\"");
                  }
                writeln (jclient_pck.jfile, "})\npublic class " +
                    wse.getBeanName () + "\n  {");
                next = false;
                for (Property prop : wse.properties)
                  {
                    if (next) write (jclient_pck.jfile, "\n");
                    next = true;
                    writeln (jclient_pck.jfile, "    @XmlElement(required=" + (!prop.nullable) + ", name=\"" +
                                              prop.getXMLName () + "\")\n    " +
                                              prop.jName (false) + " " + prop.name + ";");
                  }
                for (Property prop : wse.properties)
                  {
                    if (next) write (jclient_pck.jfile, "\n");
                    next = true;
                    String methn = prop.name;
                    writeln (jclient_pck.jfile, "    public " +
                        prop.jName (false) + " get" +
                        methn.substring (0,1).toUpperCase () + methn.substring (1) +
                        " ()\n      {\n        return " + prop.name + ";\n      }"); 
                  }
                writeln (jclient_pck.jfile, "  }");
                close (jclient_pck);
                jclient_pck.openAddedClass (wse.getName ());
                addImport ("javax.xml.ws.WebFault");
                jclient_pck.writeImports ();
                write (jclient_pck.jfile, "\n" +
          "@SuppressWarnings(\"serial\")\n" +
          "@WebFault(name=\"" + wse.getXMLName () + "\",\n" +
          "          targetNamespace=\"" + tns + "\")\n" +
          "public class " + wse.getName () + " extends Exception\n" +
          "  {\n" +
          "    /**\n" +
          "     * Java type that goes as soapenv:Fault detail element.\n" +
          "     */\n" +
          "    private " + wse.getBeanName () + " faultInfo;\n" +
          "\n"+
          "    /**\n" +
          "     * @param message\n" +
          "     * @param faultInfo\n" +
          "     */\n" +
          "    public " + wse.getName () + " (String message, " + wse.getBeanName () + " faultInfo)\n"+
          "      {\n" +
          "         super (message);\n" +
          "         this.faultInfo = faultInfo;\n" +
          "      }\n" +
          "\n" +
          "    /**\n" +
          "     * @param message\n" +
          "     * @param faultInfo\n" +
          "     * @param cause\n" +
          "     */\n" +
          "    public " + wse.getName () + " (String message, " + wse.getBeanName () + " faultInfo, Throwable cause)\n" +
          "      {\n" +
          "        super (message, cause);\n" +
          "        this.faultInfo = faultInfo;\n" +
          "      }\n" +
          "\n" +
          "    /**\n" +
          "     * @return fault bean: " + wse.name + "\n" +
          "     */\n" +
          "    public " + wse.getBeanName () + " getFaultInfo ()\n" +
          "      {\n" +
          "        return faultInfo;\n" +
          "      }\n" +
          "  }\n");
                
                close (jclient_pck);
              }
          }
      }

      private void close (Package pck) throws IOException
    {
      close (pck.jfile);
    }

      private void addImport (String string)
    {
      jimports.add (string);
    }

      private void javaHeader (Package pck) throws IOException
    {
      if (pck == null) return;
      FileOutputStream jfile = pck.jfile;
      pck.writePackage ();
      pck.writeImports ();
      write (jfile,"\n" + pck.class_header);
      if (pck.schema_validation)
        {
          write (jfile,"@com.sun.xml.ws.developer.SchemaValidation\n");
        }
      if (pck.support_code.length () > 0)
        {
          pck.next = true;
        }
      write (jfile, "@WebService(serviceName=\"" + service_name + "\",\n" +
                    "            targetNamespace=\"" + tns + "\"" + pck.decoration () + ")\npublic " + pck.class_interface () + " " +
                    pck.class_name + "\n  {\n" + pck.support_code);
      }

      private void javaTerminate (Package pck) throws IOException
    {
      if (pck != null)
        {
          if (add_main)
            {
              writeln (pck.jfile, "\n" +
                                  "    public static void main (String[] args)\n" +
                                  "      {\n" +
                                  "        if (args.length != 1)\n" +
                                  "          {\n" +
                                  "            System.out.println (\"Missing URL\");\n" +
                                  "          }\n" +
                                  "        Endpoint endpoint = Endpoint.create (new " + pck.class_name + " ());\n" +
                                  "        endpoint.publish (args[0]);\n" +
                                  "      }");

            }
          write (pck.jfile, "  }\n");
        close (pck);
        }
       
    }

      void javaMethod (Package pck, Method meth) throws IOException
      {
        if (pck == null) return;
        FileOutputStream jfile = pck.jfile;
        if (pck.next)
          {
            write (jfile, "\n");
          }
        pck.next = true;
  writeln (jfile,
      "    @WebMethod(operationName=\"" + meth.getXMLName () +"\")\n" +
      "    @RequestWrapper(localName=\"" + meth.getXMLName () + "\", targetNamespace=\"" + tns + "\")\n" +
      "    @ResponseWrapper(localName=\"" + meth.getXMLResponseName () + "\", targetNamespace=\"" + tns + "\")");
  int indent = 4;
  if (meth.outputs.isEmpty () || meth.outputs.size () > 1)
    {
      write (jfile, "    public void");
    }
  if (meth.outputs.size () == 1)
    {
      Property prop = meth.outputs.iterator ().next ();
      write (jfile, "    @WebResult(name=\"" + prop.getXMLName () + sub_target_ns  + ")\n    public ");
      write (jfile, prop.jName (false));
      indent = prop.jName (false).length ();
    }
  write (jfile, " " + meth.name + " (");
  indent += meth.name.length ();
  boolean next = false;
  for (Property prop : meth.inputs)
    {
      if (next)
        {
          writeln (jfile, ",");
          for (int i = -14; i < indent; i++)
            {
              write (jfile, " ");
            }
        }
      writeln (jfile, "@WebParam(name=\"" + prop.getXMLName () + sub_target_ns + ")");
      for (int i = -14; i < indent; i++)
            {
              write (jfile, " ");
            }
          write (jfile, prop.jName (false) + " " + prop.name);
      next = true;
    }
  if (meth.outputs.size () > 1) for (Property prop : meth.outputs)
    {
      if (next)
        {
          writeln (jfile, ",");
          for (int i = -14; i < indent; i++)
            {
              write (jfile, " ");
            }
        }
      writeln (jfile, "@WebParam(name=\"" + prop.getXMLName () + sub_target_ns + ", mode=WebParam.Mode.OUT)");
      for (int i = -14; i < indent; i++)
            {
              write (jfile, " ");
            }
          write (jfile, "Holder<" + prop.jName (true) + "> " + prop.name);
      next = true;
    }
  write (jfile, ")");
  next = false; 
  for (String ex : meth.execptions)
    {
      if (next)
        {
          write (jfile, ", ");
        }
      else
        {
      next = true;
      write (jfile, "\n    throws ");
        }
      write (jfile, exceptions.get (ex).getName ());
    }
  write (jfile, meth.code + "\n");
/*
  if (meth.outputs.size () > 1)
    {
      
    }
*/
      }

  private void open (Package pck, boolean java) throws IOException
    {
      if (pck != null)
        {
          new File (pck.path).mkdirs ();
          pck.jfile = new FileOutputStream (pck.path + File.separatorChar + pck.class_name + (java ? ".java" : ".cs"));
        }
    }

  private void writeWSDLProperties (Collection<Property> properties) throws IOException
    {
      for (Property property : properties)
        {
          write (wsdl_file,
              "            <xs:element name=\"" + property.getXMLName () +
                   "\" type=\"" + property.data_type.xsd_name + "\"" + 
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
          if (!xsd_names.add (prop.getXMLName ()))
            {
              bad ("Duplicate XML name: " + prop.getXMLName ());
            }
          String type = attr.getString ("Type");
          prop.nullable = attr.getBoolean ("Null");
          if (prop.listtype = attr.getBoolean ("List"))
            {
              addImport ("java.util.List");
            }

          for (DataType dtype : types)
            {
              if (dtype.enum_name.equals (type))
                {
                  prop.data_type = dtype;
                  break;
                }
            }
          if (prop.data_type == null)
            {
              bad ("Type '" + type + "' not found");
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

  private void writeln (FileOutputStream file, String data) throws IOException
  {
    write (file, data + "\n");
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
      else if (args[0].equals (WSDL)) wsdl_gen = true;
      else if (args[0].equals (DOTNETCLIENT)) dotnet_gen = true;
      else show ();
      output_directory = args[2];
      XMLSchemaCache xsc = new XMLSchemaCache ();
      xsc.addWrapper (WSCreator.class);
      WSCreator wsc = (WSCreator) xsc.parse (ArrayUtil.readFile (args[1]));
    }

  }
