package org.webpki.mobile.android.proxy;

public class InterruptedProtocolException extends Exception
{
	private static final long serialVersionUID = 1L;

	InterruptedProtocolException ()
	{
		super ("Interrupted protocol");
	}
}
