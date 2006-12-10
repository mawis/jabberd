-- This file can be used to create the tables the jabberd14 server is	--
-- using on a MySQL database.						--
--									--
-- To use this file open the mysql command line utility 'mysql':	--
-- 	mysql -u<user> -p						--
-- Where you replace "<user>" with a valid user account on your MySQL	--
-- server. Then create the database you want to use for your Jabber	--
-- server (if it does not already exist):				--
--	CREATE DATABASE <databasename> CHARACTER SET utf8;		--
-- Then switch to this database using the following SQL command:	--
--	USE <databasename>;						--
-- Then execute this file using						--
--	\. mysql.sql							--
-- (Assuming the mysql.sql file is in your current working directory.)	--

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `browse`
--

-- DROP TABLE IF EXISTS `browse`;
CREATE TABLE `browse` (
  `user` text NOT NULL,
  `realm` tinytext NOT NULL,
  `xml` longtext NOT NULL,
  UNIQUE KEY `jid` (`realm`(16),`user`(16))
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- Table structure for table `last`
--

-- DROP TABLE IF EXISTS `last`;
CREATE TABLE `last` (
  `user` text NOT NULL,
  `realm` tinytext NOT NULL,
  `last` int(11) default NULL,
  `text` tinytext,
  `xml` text NOT NULL,
  UNIQUE KEY `jid` (`realm`(16),`user`(16))
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- Table structure for table `mailaddresses`
--

-- DROP TABLE IF EXISTS `mailaddresses`;
CREATE TABLE `mailaddresses` (
  `user` text NOT NULL,
  `realm` tinytext NOT NULL,
  `mailaddress` tinytext,
  `lastmodified` datetime default NULL,
  UNIQUE KEY `jid` (`realm`(16),`user`(16))
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- Table structure for table `messages`
--

-- DROP TABLE IF EXISTS `messages`;
CREATE TABLE `messages` (
  `user` text NOT NULL,
  `realm` tinytext NOT NULL,
  `node` varchar(24) default NULL,
  `correspondent` text NOT NULL,
  `type` enum('offline','recv','sent') NOT NULL default 'offline',
  `storetime` datetime NOT NULL default '0000-00-00 00:00:00',
  `delivertime` datetime default NULL,
  `subject` tinytext,
  `body` text NOT NULL,
  `xml` text NOT NULL,
  KEY `jid` (`realm`(16),`user`(16),`type`),
  KEY `getmessage` (`realm`(16),`user`(16),`type`,`storetime`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- Table structure for table `presence`
--

-- DROP TABLE IF EXISTS `presence`;
CREATE TABLE `presence` (
  `user` text NOT NULL,
  `realm` tinytext NOT NULL,
  `presence` enum('available','unavailable','away','chat','dnd','xa') NOT NULL default 'unavailable',
  `priority` tinyint(4) NOT NULL default '0',
  `status` text NOT NULL,
  `timestamp` datetime NOT NULL default '0000-00-00 00:00:00',
  UNIQUE KEY `jid` (`realm`(16),`user`(16))
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- Table structure for table `privacy`
--

-- DROP TABLE IF EXISTS `privacy`;
CREATE TABLE `privacy` (
  `user` text NOT NULL,
  `realm` tinytext NOT NULL,
  `name` tinytext NOT NULL,
  `isdefault` enum('default') default NULL,
  `xml` longtext NOT NULL,
  `last_modified` datetime NOT NULL,
  UNIQUE KEY `jid_name` (`realm`(16),`user`(16),`name`(16))
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- Table structure for table `private`
--

-- DROP TABLE IF EXISTS `private`;
CREATE TABLE `private` (
  `user` text NOT NULL,
  `realm` tinytext NOT NULL,
  `ns` text NOT NULL,
  `xml` longtext NOT NULL,
  `last_modified` datetime NOT NULL,
  UNIQUE KEY `jid_ns` (`realm`(16),`user`(16),`ns`(48))
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- Table structure for table `roster`
--

-- DROP TABLE IF EXISTS `roster`;
CREATE TABLE `roster` (
  `user` text NOT NULL,
  `realm` tinytext NOT NULL,
  `xml` longtext NOT NULL,
  UNIQUE KEY `jid` (`realm`(16),`user`(16))
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- Table structure for table `storedsubscriptionrequests`
--

-- DROP TABLE IF EXISTS `storedsubscriptionrequests`;
CREATE TABLE `storedsubscriptionrequests` (
  `user` text NOT NULL,
  `realm` tinytext NOT NULL,
  `fromjid` text NOT NULL,
  `xml` text NOT NULL,
  KEY `jid` (`realm`(16),`user`(16))
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- Table structure for table `users`
--

-- DROP TABLE IF EXISTS `users`;
CREATE TABLE `users` (
  `user` text NOT NULL,
  `realm` tinytext NOT NULL,
  `password` tinytext NOT NULL,
  UNIQUE KEY `jid` (`realm`(16),`user`(16))
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

--
-- Table structure for table `vcard`
--

-- DROP TABLE IF EXISTS `vcard`;
CREATE TABLE `vcard` (
  `user` text NOT NULL,
  `realm` tinytext NOT NULL,
  `name` text,
  `email` text,
  `nickname` tinytext,
  `birthday` tinytext,
  `photo` longtext,
  `xml` longtext,
  UNIQUE KEY `jid` (`realm`(16),`user`(16))
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;
