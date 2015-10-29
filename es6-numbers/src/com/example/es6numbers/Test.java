package com.example.es6numbers;

import java.io.FileOutputStream;

import javax.script.*;

public class Test {
    static ScriptEngine engine;
    
    static int d15Errors;

    private static String dtoa(double d) throws Exception {
        String hyphen = "";
        if (d < 0) {
            d = -d;
            hyphen = "-";
        }
        d = d + (d / 1e15) / 2;
        String num = Double.toString(d);
        int exp = 0;
        int i = num.indexOf('E');
        if (i > 0) {
            int j = i;
            if (num.indexOf('-') > 0) {
                j++;
            }
            exp = Integer.valueOf(num.substring(j + 1));
            if (j != i) {
                exp = -exp;
            }
            num = num.substring(0, i);
        }
        int dp = num.indexOf('.');
        num = num.substring(0, dp) + num.substring(dp + 1);
        int len = num.length();
        int first = -1;
        int last = -1;
        for (int q = 0; q < num.length(); q++) {
            if (num.charAt(q) != '0') {
                if (first < 0) {
                    first = q;
                }
                last = q;
            }
        }
        if (last - first >= 15) {
            num = num.substring(0, first + 15);
            for (int q = 0; q <= last - first - 15; q++) {
                num += "@";
            }
        }
        if (exp >= (len - dp) && exp < 21) {
            System.out.println("h=" + (exp + dp));
            exp -= (len - dp - 1);
            while (--exp > 0) {
                num += "#";
            }
            dp = 0;
        } else if (exp == 0) {
            // if (num.substring(dp)
        }
        StringBuffer s = new StringBuffer();
        if (len - dp == 1 && num.charAt(dp) == '0') {
            num = num.substring(0, dp);
            dp = 0;
        }
        s.append(num);
        if (dp > 0) {
            s.insert(dp, '.');
        }
        if (exp != 0) {
            s.append('e').append(exp > 0 ? "+" : "").append(exp);
        }
        return s.insert(0, hyphen).toString();
    }

    static FileOutputStream fos;

    static void write(byte[] utf8) throws Exception {
        fos.write(utf8);
    }

    static void write(String utf8) throws Exception {
        write(utf8.getBytes("UTF-8"));
    }
    
    static String bad(String string) {
        return "<span style=\"color:red\">" + string + "</span>";
    }
    
    static boolean compare(String js, String calc) {
        if (js.length() != calc.length()) {
            return false;
        }
        for (int i = 0; i < js.length(); i++) {
            if (calc.charAt(i) == '#') {
                if (js.charAt(i) != '0') {
                    return false;
                }
            } else if (calc.charAt(i) != js.charAt(i) && calc.charAt(i) != '@') {
                return false;
            }
        }
        return true;
    }

    private static void test(double d) throws Exception {
        engine.put("fl", d);
        engine.eval("res=parseFloat(fl.toPrecision(15)).toString()");
        String js = engine.get("res").toString();
        String d15 = dtoa(d);
        if (!compare(js, d15)) {
            d15 = bad(d15);
            d15Errors++;
        }
        write("<tr><td>" 
              + Double.toString(d)
              + "</td><td>"
              + js
              + "</td><td>"
              + d15
              + "</td></tr>");
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("\nUsage: " + Test.class.getCanonicalName()
                    + "testpage");
            System.exit(-3);
        }
        fos = new FileOutputStream(args[0]);
        // Header
        write("<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>ES6 - Number Canonicalizer</title>"
                + "<style type=\"text/css\">"
                + "body {font-family:verdana}"
                + "th {width:150pt;background:lightgrey;font-family:verdana;font-size:10pt;font-weight:normal;padding:4pt}"
                + "td {font-family:verdana;font-size:10pt;font-weight:normal;padding:2pt}"
                + "</style></head><body><h3>ES6 - Number Canonicalizer</h3>"
                + "<table border=\"1\" cellspacing=\"0\"><tr><th>Java (unmodified)</th><th>JS (15 digit)</th><th>15 digits</th></tr>");

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
        test(0.0005);
        test(0.0000000005);
        test(0.999999999999999999999999999);
        test(-0.999999999999999999999999999);
        test(-0.9999999999999993);
        test(-0.9999999999999995);
        test(0.9999999999999993);
        test(0.9999999999999995);
        test(-0.9999999999999999);
        test(-0.9999999999999999);
        test(0.9999999999999999);
        test(0.9999999999999999);
        write("</table></body></html>\n");

        fos.close();
    }
}
