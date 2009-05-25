<%@ page contentType="text/html" import="java.io.*, java.net.*, java.util.*" %>
<%
try {
	String line = null;
	URL u = new URL("http://www.google.com");
	HttpURLConnection con = (HttpURLConnection) u.openConnection();
	con.connect();
	InputStream in = con.getInputStream();
	BufferedReader reader = new BufferedReader(new InputStreamReader(con.getInputStream(),"US-ASCII"));
	while((line = reader.readLine()) != null) {
		out.println(line);
	}
} catch (Exception e) {
	out.println(e);
}
%>