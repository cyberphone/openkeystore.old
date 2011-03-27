package org.webpki.xml;

import java.io.InputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.FileInputStream;

import java.util.Enumeration;
import java.util.Hashtable;

import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.apache.xerces.parsers.XMLGrammarPreparser;
import org.apache.xerces.parsers.DOMParser;
import org.apache.xerces.parsers.IntegratedParserConfiguration;
import org.apache.xerces.util.XMLGrammarPoolImpl;
import org.apache.xerces.impl.Constants;
import org.apache.xerces.util.SymbolTable;

import org.apache.xerces.xni.parser.XMLParserConfiguration;
import org.apache.xerces.xni.grammars.XMLGrammarDescription;
import org.apache.xerces.xni.parser.XMLInputSource;
import org.apache.xerces.xni.parser.XMLErrorHandler;
import org.apache.xerces.xni.parser.XMLParseException;
import org.apache.xerces.xni.XNIException;

import org.webpki.util.ArrayUtil;

/**
 * Repository for schemas and classes for wrapping XML elements as Java objects.
 * <p>The schema cache is used to handle XML messages for an application, keeping
 * some of the XML-related details out of the application code.
 * <p>The schema cache stores the XML schemas/DTDs used by the application for
 * fast and reliable access. In doing that, it also keeps track of what target 
 * namespaces are allowed to be used in messages (protecting the application from
 * corrupt or unknown messages and schemas).
 * <p>The schema cache also stores the association of specific XML elements to
 * {@link XMLObjectWrapper wrapper classes} that convert that element/message to and 
 * from XML form, allowing the application to access messages as Java objects.
 * <p>The schema cache itself will not remember schemas or wrappers between sessions.
 * <h3>A small example</h3>
 * An example on how to write {@link XMLObjectWrapper wrapper classes} is provided with the
 * distribution.
 * <p><b>Initialization</b>
 * <pre>
 *   XMLSchemaCache cache = new XMLSchemaCache ();
 * 
 *   cache.addSchemaFromFile("b2b.xsd");
 *   
 *   cache.addWrapper ("com.example.xmlwrappers.Order");
 *   cache.addWrapper ("com.example.xmlwrappers.RequestForQuote");
 *   cache.addWrapper ("com.example.xmlwrappers.Quote");
 *   cache.addWrapper ("com.example.xmlwrappers.Invoice");
 * </pre>
 * The {@link #addSchemaFromFile addSchemaFromFile method} parses the schema file
 * to find it's target namespace. {@link XMLObjectWrapper Wrapper classes} themselves provide 
 * information on what element (of what target namespace) they handle.
 * <p><b>Use</b>
 * <pre>
 *   public void processMessage(byte[] xmlMessage) throws ...
 *     {
 *       XMLObjectWrapper message = cache.wrap(xmlMessage);
 * 
 *       if(message instanceof Order)
 *         {
 *           Order order = (Order)message;
 *           erpSystem.enterOrder(order.customer(), order.orderNumber(), order.orderLines());
 *         }
 *       else if(message instanceof RequestForQuote)
 *         {
 *           RequestForQuote rfq = (RequestForQuote)rfq;
 *           Quote quote = new Quote(rfq.requestNumber(), 
 *                                   erpSystem.getQuote(rfq.customer(), rfq.itemList()));
 *           sendMessage(quote.toXML());
 *         }
 *     }
 * </pre>
 */
public class XMLSchemaCache
  {
    // Property identifier: symbol table
    public static final String SYMBOL_TABLE =
        Constants.XERCES_PROPERTY_PREFIX + Constants.SYMBOL_TABLE_PROPERTY;

    // Property identifier: grammar pool
    public static final String GRAMMAR_POOL =
        Constants.XERCES_PROPERTY_PREFIX + Constants.XMLGRAMMAR_POOL_PROPERTY;

    // Namespaces feature id (http://xml.org/sax/features/namespaces)
    private static final String NAMESPACES_FEATURE_ID = "http://xml.org/sax/features/namespaces";

    // Validation feature id (http://xml.org/sax/features/validation)
    private static final String VALIDATION_FEATURE_ID = "http://xml.org/sax/features/validation";

    // Schema validation feature id (http://apache.org/xml/features/validation/schema)
    private static final String SCHEMA_VALIDATION_FEATURE_ID = "http://apache.org/xml/features/validation/schema";

    // Schema full checking feature id (http://apache.org/xml/features/validation/schema-full-checking)
    private static final String SCHEMA_FULL_CHECKING_FEATURE_ID = "http://apache.org/xml/features/validation/schema-full-checking";

    // a larg(ish) prime to use for a symbol table to be shared
    // among potentially many parsers.  Start one as close to 2K (20
    // times larger than normal) and see what happens...
    private static final int BIG_PRIME = 2039;

    private XMLGrammarPoolImpl grammarPool;

    private XMLGrammarPreparser preparser;

    private SymbolTable symtab;

    private XMLParserConfiguration parserConfiguration;

    private DOMParser parser;

    private Hashtable<String,byte[]> knownURIs;

    private Hashtable<ElementID,Class<?>> classMap;
    
    private Hashtable<String,String> schemaFiles;
    
    private static class ElementID
      {
        String namespace, element;
        
        ElementID(String namespace, String element)
          {
            this.namespace = namespace;
            this.element = element;
          }
        
        public int hashCode()
          {
            return namespace.hashCode() ^ element.hashCode();
          }
        
        public boolean equals(Object o)
          {
            return o instanceof ElementID &&
                   namespace.equals(((ElementID)o).namespace) &&
                   element.equals(((ElementID)o).element);
          }
      }
    

    //
    // Parser error handler
    //
    private static void parseError (String domain, String key, XMLParseException exception) throws XNIException
      {
        throw exception;
      }

    private static XMLErrorHandler simpleErrorHandler = new XMLErrorHandler ()
      {
        public void error (String domain, String key, XMLParseException exception) throws XNIException
          {
            parseError (domain, key, exception);
          }
        public void fatalError (String domain, String key, XMLParseException exception) throws XNIException
          {
            parseError (domain, key, exception);
          }
        public void warning (String domain, String key, XMLParseException exception) throws XNIException
          {
            parseError (domain, key, exception);
          }
      };


   public XMLSchemaCache () throws IOException
      {
        symtab = new SymbolTable (BIG_PRIME);
        preparser = new XMLGrammarPreparser (symtab);
        grammarPool = new XMLGrammarPoolImpl ();
        preparser.registerPreparser (XMLGrammarDescription.XML_SCHEMA, null);
        preparser.setGrammarPool (grammarPool);
        preparser.setFeature (NAMESPACES_FEATURE_ID, true);
        preparser.setFeature( VALIDATION_FEATURE_ID, true);
        // We set schema features just in case...
        preparser.setFeature (SCHEMA_VALIDATION_FEATURE_ID, true);
        preparser.setFeature (SCHEMA_FULL_CHECKING_FEATURE_ID, true);
        preparser.setErrorHandler (simpleErrorHandler);

        parserConfiguration = new IntegratedParserConfiguration (symtab, grammarPool);
        parserConfiguration.setFeature (NAMESPACES_FEATURE_ID, true);
        parserConfiguration.setFeature (VALIDATION_FEATURE_ID, true);
            // now we can still do schema features just in case,
            // so long as it's our configuraiton......
        parserConfiguration.setFeature (SCHEMA_VALIDATION_FEATURE_ID, true);
        parserConfiguration.setFeature (SCHEMA_FULL_CHECKING_FEATURE_ID, true);
        parserConfiguration.setErrorHandler (simpleErrorHandler);
        parser = new DOMParser (parserConfiguration);

        classMap = new Hashtable<ElementID,Class<?>> ();
        knownURIs = new Hashtable<String,byte[]> ();
        schemaFiles = new Hashtable <String, String> ();
      }


    public void addSchema (InputStream is, String fname) throws IOException
      {
        addSchema (ArrayUtil.getByteArrayFromInputStream (is), fname);
      }


    public void addSchemaFromFile (String fname) throws IOException
      {
        addSchema (new FileInputStream (new File (fname)), fname);
      }


    public boolean hasSchema(String targetNamespace)
      {
        return knownURIs.containsKey(targetNamespace);
      }
    

    public void addSchema (byte[] schema, String fname) throws IOException
      {
        Enumeration<byte[]> schemas = knownURIs.elements ();
        while (schemas.hasMoreElements ())
          {
            if (ArrayUtil.compare (schemas.nextElement (), schema))
              {
                return;
              }
          }
        DOMParser scparser = new DOMParser ();
        try
          {
            scparser.setFeature (SCHEMA_VALIDATION_FEATURE_ID, false);
            scparser.setFeature ("http://apache.org/xml/features/dom/defer-node-expansion", true);
            scparser.setFeature (NAMESPACES_FEATURE_ID, true);
            scparser.setFeature (VALIDATION_FEATURE_ID, false);
          }
        catch (Exception ex)
          {
            throw new IOException (ex.getMessage ());
          }
        scparser.parse (new XMLInputSource (null, null, null, new ByteArrayInputStream (schema), null));
        Element e = scparser.getDocument ().getDocumentElement ();
        // Add more checks?
        String targetNamespace = e.getLocalName ().equals ("schema") ? e.getAttribute ("targetNamespace") : null;
        if (targetNamespace == null)
          {
            throw new IOException ("Schema did not decode");
          }
        byte[] old = knownURIs.get (targetNamespace);
        if (old == null)
          {
            knownURIs.put (targetNamespace, schema);
            schemaFiles.put (targetNamespace, fname == null ? "file.xsd" : fname);
            preparser.preparseGrammar (XMLGrammarDescription.XML_SCHEMA, 
                                       new XMLInputSource (targetNamespace, null, null, new ByteArrayInputStream (schema), null));
          }
        else
          {
            throw new IOException ("Attempt to redefine target namespace '" + targetNamespace + "'.");
          }
      }
    

    private XMLObjectWrapper wrap (Element e, String namespace) throws IOException
      {
        try
          {
            String element = e.getLocalName ();
            Class<?> wrapperClass = classMap.get (new ElementID (namespace, element));
            if (wrapperClass == null)
              {
                throw new RuntimeException ("Unknown element type: " + namespace + ", " + element);
              }
            XMLObjectWrapper r = (XMLObjectWrapper)wrapperClass.newInstance ();
            r.createRootObject (e.getOwnerDocument (), e);
            r.schemaCache = this;
            DOMReaderHelper drh = new DOMReaderHelper (e);
            drh.getNext (r.element ());
            r.fromXML (drh);
            return r;
          }
        catch (InstantiationException ie)
          {
            throw new RuntimeException ("Unexpected InstantiationException.");
          }
        catch (IllegalAccessException iae)
          {
            throw new RuntimeException ("Unexpected IllegalAccessException.");
          }
      }
    

    /**
     * Wrap a parsed XML document using the appropriate {@link XMLObjectWrapper wrapper class}.
     * <p>An instance of the appropriate {@link XMLObjectWrapper wrapper class} is created and
     * populated using it's {@link XMLObjectWrapper#fromXML(DOMReaderHelper) fromXML method}
     * <p>The document is not validated.
     */
    public XMLObjectWrapper wrap (Document d) throws IOException
      {
        Element e = d.getDocumentElement ();
        String namespace = DOMUtil.getDefiningNamespace (e);
        return wrap (e, namespace);
      }
    
    XMLObjectWrapper wrap (Element e) throws IOException
      {
        XMLObjectWrapper o = wrap (e, DOMUtil.getDefiningNamespace (e));
        return o;
      }

    public XMLObjectWrapper wrap (XMLCookie cookie) throws IOException
      {
        return wrap (cookie.element);
      }
    
    public boolean hasWrapper (Element e)
      {
        return classMap.containsKey (new ElementID (DOMUtil.getDefiningNamespace (e), e.getLocalName ()));
      }
    
    /**
     * Add a {@link XMLObjectWrapper wrapper class}.
     */
    public void addWrapper (XMLObjectWrapper instance) throws IOException
      {
        instance.schemaCache = this;
        instance.init ();
        classMap.put (new ElementID (instance.namespace(), instance.element ()), instance.getClass ());
      }

    /**
     * Add a {@link XMLObjectWrapper wrapper class}.
     */
    public void addWrapper (Class<?> wrapperClass) throws IOException
      {
        try
          {
            addWrapper ((XMLObjectWrapper)wrapperClass.newInstance ());
          }
        catch (InstantiationException ie)
          {
            throw new IllegalArgumentException("Class " + wrapperClass.getName () + 
                                               " is not a valid xml wrapper (InstantiationException instantiating).");
          }
        catch (IllegalAccessException iae)
          {
            throw new IllegalArgumentException("Class " + wrapperClass.getName () + 
                                               " is not a valid xml wrapper (IllegalAccessException instantiating).");
          }
      }
    
    
    /**
     * Add a {@link XMLObjectWrapper wrapper class}.
     */
    public void addWrapper (String wrapperClass) throws IOException
      {
        try
          {
            addWrapper (Class.forName (wrapperClass));
          }
        catch (ClassNotFoundException cnfe)
          {
            throw new IllegalArgumentException("Class " + wrapperClass + 
                                               " can't be found (ClassNotFoundException).");
          }
      }
    
    /**
     * Add a number of {@link XMLObjectWrapper wrapper classes}.
     */
    public void addWrappers (String[] classes) throws IOException
      {
        for(int i = 0; i < classes.length; i++)
          {
            addWrapper (classes[i]);
          }
      }
    
    /**
     * Get the list of registered wrapper classes.
     * <p>Can be used to extract and store the set of wrapper classes between sessions.
     */
    public String[] getWrapperClasses ()
      {
        String[] r = new String[classMap.size()];

        Enumeration<?> e = classMap.elements();
        for(int i = 0; i < r.length; i++)
          {
            r[i] = ((Class<?>)e.nextElement()).getName();
          }
        
        return r;
      }
    
    /**
     * Get the XML schema associated with a target namespace.
     * @return The XML schema as a blob.
     */
    public byte[] getSchema (String targetNamespace)
      {
        return knownURIs.get (targetNamespace);
      }

    /**
     * Get the XML schema file with a target namespace.
     * @return The XML schema file as a name.
     */
    public String getFile (String targetNamespace)
      {
        return schemaFiles.get (targetNamespace);
      }

    /**
     * Get the list of known target namespaces.
     */
    public String[] getTargetNamespaces ()
      {
        String[] r = new String[knownURIs.size()];
        
        Enumeration<String> e = knownURIs.keys();
        for(int i = 0; i < r.length; i++)
          {
            r[i] = e.nextElement ();
          }
      
        return r;
      }


    public Document validate (InputStream is) throws IOException
      {
        parser.parse (new XMLInputSource (null, null, null, is, null));
        return parser.getDocument ();
      }

    public Document validate (byte[] xmldata) throws IOException
      {
        return validate (new ByteArrayInputStream (xmldata));
      }


    public Document validate (Document d) throws IOException
      {
        return validate (DOMUtil.writeXML (d));
      }


    public Document validateXMLFromFile (String fname) throws IOException
      {
        return validate (new FileInputStream (new File (fname)));
      }

    public XMLObjectWrapper parse (byte[] xmldata) throws IOException
      {
        return wrap (validate (xmldata));
      }


    public XMLObjectWrapper parse (InputStream is) throws IOException
      {
        return wrap (validate (is));
      }


    public static void main (String argv[]) throws IOException
      {
        XMLSchemaCache xmlp = new XMLSchemaCache ();
        if (argv.length < 2)
          {
            System.out.println ("Usage: " + xmlp.getClass ().getName () + "  schema_1 [schema_2 ... schema_n]  xml_doc");
            System.exit (3);
          }
        int last = argv.length - 1;
        for (int i = 0; i < last; i++)
          {
            xmlp.addSchemaFromFile (argv[i]);
          }
        Element e = xmlp.validateXMLFromFile (argv[last]).getDocumentElement ();
        System.out.println ("E=" + e.getLocalName() + " NS=" + DOMUtil.getDefiningNamespace (e));
      }

  }
