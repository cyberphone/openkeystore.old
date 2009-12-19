package org.webpki.sks;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Extension consumer interface
 */
public interface KeyStoreDatabaseConnection
  {
    public Connection getDatabaseConnection () throws SQLException;
  }
