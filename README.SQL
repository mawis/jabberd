This file contains an introduction to using your SQL server (currently
MySQL or PostgreSQL) as your data storage for jabberd14 1.6.0. Using
SQL is now the default storage of jabberd14.

Starting with jabberd14 1.6.0 the xdb_sql storage module now is delivered
with a default database configuration, which is suggested to be used,
if you do not require to access any existent database layout. In the
later case the configuration settings of the xdb_sql module give you a
very powerful tool to customize jabberd14's access to your database.

The jabber.xml.dist configuration file example provides you with all
necessary configuration settings, that you require to access the default
database layout when using a MySQL 4.1+ server.
If you are using an older version of MySQL, you have to comment out the
<onconnect>SET NAMES utf8</onconnect> setting in your jabberd14's
configuration file. But using MySQL version 4.1+ is strongly recommended,
else you have to take special care, that when you are upgrading to
MySQL 4.1+ at a later time, that the contents of your tables are marked
as containing utf8 data. (By default MySQL thinks the content of 4.0
databases is encoded using the ISO-8859-1 character set when upgrading.)

To create the tables used by jabberd14 in your MySQL server, please use
the file 'mysql.sql' distributed together with jabberd14 1.6.0.

If you are using the default layout for storing data, the following SQL
commands are some ideas on what data might be interesting for you to
see:

- See how many accounts you have on each of your domains:

  SELECT COUNT(*),realm FROM users GROUP BY realm;

- See how many online users you have:

  SELECT COUNT(*) FROM presence WHERE presence!='unavailable';

- See how many users are in which presence state:

  SELECT COUNT(*),presence FROM presence GROUP BY presence;


Using PostgreSQL

If you are using PostgreSQL instead of MySQL, you have to use slightly
different SQL statements in your configuration file. Please have a look
at xdb_postgresql.xml for statements, that can be used with PostgreSQL.
