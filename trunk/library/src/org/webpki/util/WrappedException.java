package org.webpki.util;


/**
 * Wrapped exception handler.
 * Note: the use of RuntimeException is deliberate, declared exceptions only complicate
 * programming and was excluded in .NET.
 */
public class WrappedException extends RuntimeException
  {
    static final long serialVersionUID = 10000000000L;

    /**
     * Takes an existing exception and creates a new one while keeping the stack intact.
     * @param wrapped_exception The exception.
     */
    public WrappedException (Exception wrapped_exception)
      {
        super (wrapped_exception.getMessage ());
        setStackTrace (wrapped_exception.getStackTrace ());
      }
  }
