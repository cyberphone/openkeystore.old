package com.example.es6numbers;

import java.io.FileOutputStream;

import javax.script.*;

public class Test {

    public static String es6DoubleSerialization(double value) {

        // 1. Take care of the sign
        String hyphen = "";
        if (value < 0) {
            value = -value;
            hyphen = "-";
        }

        // We may need to start-over due to rounding of the dropped 16:th digit
        boolean round = true;
        while (true) {

            // 2. Serialize using Java default
            StringBuffer num = new StringBuffer(Double.toString(value));

            // 4. Collect and remove the optional exponent
            int exp = 0;
            int i = num.indexOf("E");
            if (i > 0) {
                int j = i;
                if (num.indexOf("-") > 0) {
                    j++;
                }
                exp = Integer.valueOf(num.substring(j + 1));
                if (j != i) {
                    exp = -exp;
                }
                num.delete(i, num.length());
            }

            // 5. There must be a decimal point.  Remove it from the string and record the position
            int dp = num.indexOf(".");
            num.deleteCharAt(dp);

            // 6. Normalize decimal point to position 0
            exp += dp;
            dp = 0;

            // 7. Normalize number so that MSD != 0
            int lastNonZero = 0;
            i = 0;
            while (i < num.length()) {
                if (num.charAt(0) == '0') {
                    num.deleteCharAt(0);
                    exp--;
                } else {
                    if (num.charAt(i) != '0') {
                        lastNonZero = i;
                    }
                    i++;
                }
            }

            // 8. Check if we got nothing (0)
            if (num.length() == 0) {
                return "0";
            }

            // 9. Check digit 16 for rounding
            if (round && lastNonZero >= 15 && num.charAt(15) >= '5') {
                value += Math.pow(10, exp - 15) / 2;
                round = false;
                continue;
            }

            // 10. Remove digits beyond 15
            if (lastNonZero >= 15) {
                num.delete(15, num.length());
            }

            // 11. Remove trailing zeroes
            while (num.charAt(num.length() - 1) == '0') {
                num.deleteCharAt(num.length() - 1);
            }

            // 12. Put decimal point and add missing zeroes if needed
            int len = num.length();
            if (exp >= len && exp <= 21) {
                // It is an integer, drop decimal point
                exp -= len;
                while (exp > 0) {
                    num.append('0');
                    exp--;
                }
                dp = -1;
            }
            else if (exp <= 0 && exp > -6 && len - exp < 21) {
                while (exp < 0) {
                    num.insert(0, '0');
                    exp++;
                }
            } else if (exp < 0) {
                dp = len == 1 ? -1 : 1;
                exp--;
            } else if (exp < len) {
                dp = exp;
                exp = 0;
            } else {
                dp = 1;
                exp--;
            }

            if (exp != 0) {
                num.append('e').append(exp > 0 ? "+" : "").append(exp);
            }
            if (dp == 0) {
                num.insert(0, "0.");
            } else if (dp > 0) {
                num.insert(dp, '.');
            }
            return num.insert(0, hyphen).toString();
        }
    }

    static ScriptEngine engine;
    
    static int d15Errors;

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
        String d15 = es6DoubleSerialization(d);
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
        test(-0.9999999999999999);
        test(-0.9999999999999999);
        test(0.9999999999999999);
        test(0.9999999999999999);
        write("</table></body></html>\n");

        fos.close();
    }
}
