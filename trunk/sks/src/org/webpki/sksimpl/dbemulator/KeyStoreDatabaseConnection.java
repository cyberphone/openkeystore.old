package org.webpki.sksimpl.dbemulator;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Extension consumer interface
 */
public interface KeyStoreDatabaseConnection
  {
    public Connection getDatabaseConnection () throws SQLException;
  }
