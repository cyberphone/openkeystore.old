package com.example.xercesporttester;

import java.io.ByteArrayInputStream;
import java.util.Vector;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import android.os.Bundle;
import android.app.Activity;
import android.content.Intent;
import android.util.Log;
import android.view.View;
import android.view.View.OnClickListener;
import android.widget.Button;
import android.widget.EditText;

public class MainActivity extends Activity {
	
	static final String XML_MESSAGE = "com.example.xercesporttester.XML";

    static String xsd1 =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<xs:schema targetNamespace=\"http://example.com/xmldsig11\"" +
        "           xmlns:ds11=\"http://example.com/xmldsig11\"" +
        "           xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"" +
        "           elementFormDefault=\"qualified\" attributeFormDefault=\"unqualified\">" +

        "   <xs:element name=\"ECKeyValue\" type=\"xs:base64Binary\"/>" +
        
        "</xs:schema>";

    static String xsd2 =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<xs:schema targetNamespace=\"http://example.com/xmldsig\"" +
        "           xmlns:ds=\"http://example.com/xmldsig\"" +
        "           xmlns:ds11=\"http://example.com/xmldsig11\"" +
        "           xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"" +
        "           elementFormDefault=\"qualified\" attributeFormDefault=\"unqualified\">" +

        "   <xs:import namespace=\"http://example.com/xmldsig11\"/>" +

        "   <xs:element name=\"KeyInfo\">" +
        "      <xs:complexType>" +
        "         <xs:sequence>" +
        "            <xs:element ref=\"ds11:ECKeyValue\"/>" +
        "         </xs:sequence>" +
        "      </xs:complexType>" +
        "   </xs:element>" +

        "</xs:schema>";
      
    static String xsd3 =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
        "<xs:schema targetNamespace=\"http://example.com/xmldsig3\"" +
        "           xmlns:ds=\"http://example.com/xmldsig3\"" +
        "           xmlns:ds11=\"http://example.com/xmldsig11\"" +
        "           xmlns:xs=\"http://www.w3.org/2001/XMLSchema\"" +
        "           elementFormDefault=\"qualified\" attributeFormDefault=\"unqualified\">" +

        "   <xs:import namespace=\"http://example.com/xmldsig11\"/>" +

        "   <xs:element name=\"KeyInfo\">" +
        "      <xs:complexType>" +
        "         <xs:sequence>" +
        "            <xs:element ref=\"ds11:ECKeyValue\"/>" +
        "         </xs:sequence>" +
        "      </xs:complexType>" +
        "   </xs:element>" +

        "</xs:schema>";

    static String xml =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n" +
        "<key:KeyInfo xmlns:key=\"http://example.com/xmldsig\"" +
        " xmlns:ds11=\"http://example.com/xmldsig11\">\n" +
        "  <ds11:ECKeyValue>AmA0R1CUdde3nakEJAFEqa29xtYQRaRXc7zB+iTOsV4=</ds11:ECKeyValue>\n" +
        "</key:KeyInfo>";
    
    static DocumentBuilderFactory dbf;
    
    static Schema schema;
    
    private static DOMSource getDOM (DocumentBuilder parser, String xml) throws Exception
    {
      return new DOMSource (parser.parse (new ByteArrayInputStream (xml.getBytes ("UTF-8"))));
    }

    static
	{
		try 
		{
			dbf = DocumentBuilderFactory.newInstance ("org.webpki.android.org.apache.xerces.jaxp.DocumentBuilderFactoryImpl",
					                                  MainActivity.class.getClassLoader ());
            dbf.setNamespaceAware (true);
            DocumentBuilder parser = dbf.newDocumentBuilder ();
            Vector<DOMSource> xsds = new Vector<DOMSource> ();
            xsds.add (getDOM (parser, xsd1));
            xsds.add (getDOM (parser, xsd2));
            xsds.add (getDOM (parser, xsd3));
			Log.v("XML", "Parsed");
            schema = SchemaFactory.newInstance (XMLConstants.W3C_XML_SCHEMA_NS_URI, 
                                                "org.webpki.android.org.apache.xerces.jaxp.validation.XMLSchemaFactory",
                                                MainActivity.class.getClassLoader ()).newSchema (xsds.toArray(new DOMSource[0]));
			Log.v("XML", "Schema");

		}
		catch (Exception e)
		{
			Log.e("XML", "Failed");
			throw new RuntimeException (e);
		}
	}

    EditText xml_control;
    
    void restoreXML ()
    {
    	xml_control.setText(xml);
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        xml_control = (EditText) findViewById(R.id.editXML);

        Button restoreXML = (Button)findViewById(R.id.buttonRestoreXML);
        restoreXML.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                restoreXML ();
            }
        });

        Button validateXML = (Button)findViewById (R.id.buttonValidateXML);
        validateXML.setOnClickListener(new OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent(MainActivity.this, ValidationActivity.class);
                String xml_message = xml_control.getText().toString();
                intent.putExtra(XML_MESSAGE, xml_message);
                startActivity(intent);
            }
        });

        restoreXML ();
    }

}
