This file contains a short introduction using SQL (MySQL or PostgreSQL)
as storage for jabberd 1.4.4 beta2.

The xdb_sql storage module does not define any database layout by itself,
you define how your tables are organized yourself and can create queries
that can be used with existing user tables on your system.

The jabber.xml.dist configuration file example does contain example
queries to store authentication data (user passwords) in your database,
and it contains a second set of definitions to store presence in your
database. This presence is not used by jabberd itself (presence of users
is kept in memory as this information is accessed quite often), but
you might want to use it to implement features on your website, that
need this presence information (e.g. online indicators).

If you want to use these two sets of example definitions with MySQL you
can create the tables using the following commands:

CREATE TABLE users (
    jid TEXT NOT NULL,
    password TINYTEXT NOT NULL);

CREATE UNIQUE INDEX jid ON users (jid(16));

CREATE TABLE presence (
    jid TEXT NOT NULL,
    presence ENUM('unavailable', 'available', 'away', 'chat', 'dnd', 'xa')
	NOT NULL,
    priority TINYINT NOT NULL,
    status TEXT NOT NULL);

CREATE UNIQUE INDEX jid ON presence (jid(16));



If you use virtual hosting of multiple domains on your server, I would
recommend not using a single field to store the full jid, but to use two
fields, one storing the username and the other storing the domain. I call
these two fields on my own tables "user" and "realm" as I use them for
my SASL library as well. Splitting the jid is done to speed up access
to the table, as the database engine can select a subset of relevant
records before searching for the right username.

At amessage, I use the following query definitions at time of writing:

For authentication:

<handler ns="jabber:iq:auth">
  <get>
     <query>SELECT password FROM users
     WHERE
       realm=SUBSTRING('{attribute::to}', INSTR('{attribute::to}', '@')+1)
     AND
       user=SUBSTRING('{attribute::to}', 1, INSTR('{attribute::to}', '@')-1)
     </query>
     <result><password xmlns='jabber:iq:auth'><value xmlns='http://jabberd.org/ns/xdbsql' value='1'/></password></result>
   </get>
   <set>INSERT INTO users (user,realm,password) VALUES
   (SUBSTRING('{attribute::to}', 1, INSTR('{attribute::to}', '@')-1),
   SUBSTRING('{attribute::to}', INSTR('{attribute::to}', '@')+1),
   '{password/text()}')</set>
   <delete>DELETE FROM users WHERE
     realm=SUBSTRING('{attribute::to}', INSTR('{attribute::to}', '@')+1)
   AND
     user=SUBSTRING('{attribute::to}', 1, INSTR('{attribute::to}', '@')-1)
   </delete>
</handler>

For presence:

<handler ns="http://jabberd.org/ns/storedpresence">
  <get>
    <query>SELECT 'this namespace is never selected'</query>
    <result><this-namespace-is-never-selected/></result>
  </get>
  <set>INSERT INTO presence (user,realm,presence,priority,status,timestamp)
  VALUES (SUBSTRING('{attribute::to}', 1, INSTR('{attribute::to}', '@')-1),
  SUBSTRING('{attribute::to}', INSTR('{attribute::to}', '@')+1),
  IF ('{presence}'='','unavailable',
    IF ('{presence/show/text()}'='','available', '{presence/show/text()}')),
  IF ('{presence/priority/text()}'='', '0', '{presence/priority/text()}'),
  '{presence/status/text()}', now())</set>
  <delete>DELETE FROM presence WHERE
    realm=SUBSTRING('{attribute::to}', INSTR('{attribute::to}', '@')+1)
  AND
    user=SUBSTRING('{attribute::to}', 1, INSTR('{attribute::to}', '@')-1)
  </delete>
</handler>

The corresponding tables are:

CREATE TABLE users (
  user TEXT NOT NULL,
  realm TINYTEXT NOT NULL,	-- a domain of a JID can be longer
  				-- but no domain of amessage is that long
  password TINYTEXT NOT NULL);

CREATE UNIQUE KEY jid ON users(realm(16), `user`(16));

CREATE TABLE presence (
  user TEXT NOT NULL,
  realm TINYTEXT NOT NULL,
  presence ENUM('unavailable', 'available', 'away', 'chat', 'dnd', 'xa')
    NOT NULL,
  priority TINYINT NOT NULL,
  status TEXT NOT NULL);

CREATE UNIQUE KEY jid ON presence(realm(16), `user`(16));

Note: How many characters you use in the key for the realm value depends
on how many characters are needed to differentiate between all the domains
you are using. For example if you host two domains 'jabberfun.example.com'
and 'jabbersucks.example.com', your the key should use at least 7 characters
of the realm as the 7th character is the first that is different in the
two hostnames.

If you have the setup with these tables, you might like queries like these:

To see how many accounts you have at which domain:
  SELECT COUNT(*),realm FROM users GROUP BY realm;

To see how many online users you have:
  SELECT COUNT(*) FROM presence WHERE presence!='unavailable';

To see how many users are in which state:
  SELECT COUNT(*),presence FROM presence GROUP BY presence;
