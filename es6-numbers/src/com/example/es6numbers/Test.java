package com.example.es6numbers;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.text.DecimalFormat;
import java.text.SimpleDateFormat;

import java.util.Date;
import java.util.Vector;

import javax.script.*;

public class Test {
    
    static final double UNDERFLOW_LIMIT_D15 = 2.22507385850721E-308;

    // This code is emulating 7.1.12.1 of the EcmaScript V6 specification.
    // The purpose is for supporting signed JSON/JavaScript objects which
    // though forces us dropping (after rounding) the 16:th digit since it
    // is not deterministic in the ECMA specification (IEEE 754-2008 double
    // precision values have 15.95 digits of precision).
    public static String es6JsonNumberSerialization(double value) {

        // 0. Check for JSON compatibility.
        if (Double.isNaN(value) || Double.isInfinite(value)) {
            throw new IllegalArgumentException("NaN/Infinity are not permitted in JSON");
        }
        
        // 1. Take care of the sign.
        String hyphen = "";
        if (value < 0) {
            value = -value;
            hyphen = "-";
        }

        // 2. Underflow doesn't interoperate well (edge case)
        if (value < UNDERFLOW_LIMIT_D15) {
            return "0";
        }

        // 3. Serialize using Java with 15 digits of precision.
        StringBuffer num = new StringBuffer(new DecimalFormat("0.##############E000").format(value));
        
        // 4. Special treatment of zero.
        if (num.charAt(0) == '0') {
            return "0";
        }

        // 5. Collect and remove the exponent.
        int i = num.indexOf("E");
        int j = i;
        if (num.indexOf("-") > 0) {
            j++;
        }
        int exp = Integer.valueOf(num.substring(j + 1));
        if (j != i) {
            exp = -exp;
        }
        num.delete(i, num.length());

        // 6. There may be a decimal point.
        //    Remove it from the string and record its position.
        int dp = num.indexOf(".");
        if (dp < 0) {;
            dp = num.length();
        } else {
            num.deleteCharAt(dp);
        }

        // 7. Normalize decimal point to position 0.
        //    Update exponent accordingly.
        exp += dp;
        dp = 0;

        // 8. Remove trailing zeroes.
        while (num.charAt(num.length() - 1) == '0') {
            num.deleteCharAt(num.length() - 1);
        }
        int len = num.length();

        // 9. This is the really difficult one...
        //    Compute or remove decimal point. 
        //    Add missing zeroes if needed.
        //    Update or remove exponent.
        if (exp >= len && exp <= 21) {
            // 9.a Integer which fits the maximum field width.
            //     Drop decimal point and remove exponent.
            exp -= len;
            while (exp > 0) {
                // It is a big integer which lacks some zeroes.
                num.append('0');
                exp--;
            }
            // No decimal point please, I'm an integer.
            dp = -1;
        } else if (exp <= 0 && exp > -6 && len - exp < 21) {
            // 9.b Small number which fits the field width.
            //     Add leading zeroes and remove exponent.
            while (exp < 0) {
                num.insert(0, '0');
                exp++;
            }
        } else if (exp < 0) {
            // 9.c Small number with exponent, move decimal point one step to the right.
            //     If it is just a single digit we remove decimal point.
            dp = len == 1 ? -1 : 1;
            exp--;
        } else if (exp < len) {
            // 9.d Decimal number which is within limits.
            //     Update decimal point position and remove exponent.
            dp = exp;
            exp = 0;
        } else {
            // 9.e Large number with exponent is our final alternative.
            dp = 1;
            exp--;
        }

        // 10. Add optional exponent including +/- sign.
        if (exp != 0) {
            num.append('e').append(exp > 0 ? "+" : "").append(exp);
        }

        // 11. Set optional decimal point.
        if (dp == 0) {
            // Small decimal number without exponent (0.005).
            num.insert(0, "0.");
        } else if (dp > 0) {
            // Exponent or normal decimal number (3.5e+24, 3.5, 3333.33).
            num.insert(dp, '.');
        }

        // 12. Finally, return the assembled number including sign.
        return num.insert(0, hyphen).toString();
    }

    static String toJsonString(double d) {
        double ad = Math.abs(d);
        if (1e-6d <= ad && ad < 1e21d) return String.format("%f", d).replaceFirst("\\.?0++$", "");
        else if (ad == 0) return "0";
        else return String.format("%g", d).replaceFirst("\\.?0++e", "e");
    }

    static ScriptEngine engine;
    
    static FileOutputStream fos;
    
    static class Pair {
        double value;
        String d15;
    }
    
    static Vector<Pair> testValues = new Vector<Pair>();

    static void write(byte[] utf8) throws Exception {
        fos.write(utf8);
    }

    static void write(String utf8) throws Exception {
        write(utf8.getBytes("UTF-8"));
    }
    
    static void test(double value) throws Exception {
        String d15 = es6JsonNumberSerialization(value);
        Pair pair = new Pair();
        pair.value = value;
        pair.d15 = d15;
        testValues.add(pair);
        engine.put("fl", value);
        engine.eval("res=parseFloat((Math.abs(fl) < " + UNDERFLOW_LIMIT_D15 + " ? 0 : fl).toPrecision(15)).toString()");
        String js = engine.get("res").toString();
        if (!d15.equals(es6JsonNumberSerialization(Double.valueOf(d15)))) {
            throw new RuntimeException("Roundtrip 1 failed for:" + d15);
        }
        DecimalFormat df = new DecimalFormat("0.##############E000");
        if (!d15.equals(es6JsonNumberSerialization(Double.valueOf(df.format(value))))) {
            throw new RuntimeException("Roundtrip 2 failed for:" + d15);
        }
        if (!js.equals(d15)) {
            d15 = "<span style=\"color:red\">" + d15 + "</span>";
        }
        write("<tr><td>" 
              + Double.toString(value)
              + "</td><td>"
              + js
              + "</td><td>"
              + d15
              + "</td><td>"
              + toJsonString(value)
              + "</td></tr>");
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.out.println("\nUsage: " + Test.class.getCanonicalName()
                    + "resultpage browsertestpage source");
            System.exit(-3);
        }
        fos = new FileOutputStream(args[0]);
        // Header
        write("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>ES6 - Number Canonicalizer</title>"
                + "<style type=\"text/css\">"
                + "body {font-family:verdana}"
                + "th {width:150pt;background:lightgrey;font-family:verdana;font-size:10pt;font-weight:normal;padding:4pt}"
                + "td {font-family:verdana;font-size:10pt;font-weight:normal;padding:2pt}"
                + "</style></head><body><h3>ES6 - JSON Number Canonicalizer ["
                + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()) 
                + "]</h3>"
                + "<table border=\"1\" cellspacing=\"0\"><tr><th>Java (parsed)</th><th>JS/Java (15 digit)</th><th>Emulation/Workaround<br>(red=error wrt JS/Java)</th><th>Alternative ES6 formatter</th></tr>");

        ScriptEngineManager manager = new ScriptEngineManager();
        engine = manager.getEngineByName("JavaScript");
        for (int i = -1; i < 2; i += 2) {
            double factor = 3e-22;
            for (int q = 0; q < 50; q++) {
                test(i / factor);
                factor *= 10;
            }
        }
        test(10);
        test(0);
        for (int i = 0; i < 10; i++) {
            test(5.0 / Math.pow(10, i));
        }
        test(0.00000506);
        test(0.000005006);
        test(0.0000050006);
        test(0.00000500006);
        test(0.000005000006);
        test(0.0000050000006);
        test(0.00000500000006);
        test(0.000005000000006);
        test(0.0000050000000006);
        test(0.00000500000000006);
        test(0.000005000000000006);
        test(0.0000050000000000006);
        test(0.00000500000000000006);
        test(0.000005000000000000006);
        test(0.0000050000000000000006);
        test(0.999999999999999999999999999);
        test(-0.999999999999999999999999999);
        test(-0.9999999999999993);
        test(-0.9999999999999995);
        test(0.9999999999999993);
        test(0.9999999999999995);
        test(0.9999999999999996);
        test(0.9999999999999998);
        test(-0.9999999999999999);
        test(-0.9999999999999999);
        test(0.9999999999999999);
        test(0.9999999999999999);
        test(0.29999999999999993338661852249060757458209991455078125);
        test(0.299999999999999988897769753748434595763683319091796875);
        test(0.3000000000000000444089209850062616169452667236328125);
        test(2.22507385850721E-308);
        test(Double.MIN_NORMAL);
        test(Double.MIN_VALUE);
        try {
            test(Double.POSITIVE_INFINITY);
            throw new RuntimeException("fallthrough");
        } catch (IllegalArgumentException e) {
            
        }
        try {
            test(Double.NaN);
            throw new RuntimeException("fallthrough");
        } catch (IllegalArgumentException e) {
            
        }

        write("</table>&nbsp;<br>You may also try <a href=\"" + 
              args[1].substring(args[1].lastIndexOf(File.separatorChar) + 1) +
              "\">testing this in a browser</a><br><pre>");
        FileInputStream fis = new FileInputStream(args[2]);
        int c;
        byte[] buffer = new byte[1];
        while ((c = fis.read()) != -1) {
            if (c == '>') {
                write("&gt;");
            } else if (c == '<') {
                write("&lt;");
            } else if (c == '"') {
                write("&quot;");
            } else if (c == '&') {
                write("&amp;");
            } else {
                buffer[0] = (byte) c;
                write(buffer);
            }
        }
        write("</pre></body></html>\n");
        fos.close();
        fos = new FileOutputStream(args[1]);
        write("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>ES6 - Browser Number Canonicalizer Test</title>"
                + "<style type=\"text/css\">"
                + "body {font-family:verdana;font-size:10pt}"
                + "th {width:150pt;background:lightgrey;font-family:verdana;font-size:10pt;font-weight:normal;padding:4pt}"
                + "td {font-family:verdana;font-size:10pt;font-weight:normal;padding:2pt}"
                + "</style></head><body><h3>ES6 - Browser Number Canonicalizer Test</h3>"
                + "Note: Test-values are supplied in a JS vector and the &quot;workaround&quot; solution"
                + "<div style=\"padding:5pt\"><code style=\"font-size:12pt\">newValue = parseFloat((Math.abs(originalValue) &lt; " + UNDERFLOW_LIMIT_D15 + " ? 0 : originalValue).toPrecision(15));</code></div>"
                + "is applied.<br>&nbsp;"
                + "<table border=\"1\" cellspacing=\"0\"><tr><th>Original</th><th>Expected</th><th>Browser (red=diff)</th></tr>"
                + "<script type=\"text/javascript\">\nvar testSuite = [");
       boolean comma = false;
        for (Pair pair : testValues) {
            if (comma) {
                write(",\n");
            }
            write("\"");
            write(Double.toString(pair.value));
            write("\", \"");
            write(pair.d15);
            write("\"");
            comma = true;
        }
        write("];\nvar i = 0;\n");
        write("while (i < testSuite.length) {\n" +
              "  var original = testSuite[i++];\n" +
              "  var value = parseFloat(original);\n" +
              "  var browser = parseFloat((Math.abs(value) < " + (UNDERFLOW_LIMIT_D15) + " ? 0 : value).toPrecision(15));\n" +
              "  var expected = testSuite[i++];\n" +
              "  if (browser.toString() != expected || parseFloat(expected) != browser) browser = '<span style=\"color:red\">' + browser + '</span>';\n" +
              "  document.write('<tr><td>' + original + '</td><td>' + expected + '</td><td>' + browser + '</td></tr>');\n" +
              "}\n");
        write("</script></table></body></html>\n");
        fos.close();

    }
}
