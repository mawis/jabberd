 CREATE TRUSTED PROCEDURAL LANGUAGE 'plpgsql'
  HANDLER plpgsql_call_handler
  VALIDATOR plpgsql_validator;

CREATE SEQUENCE seq_presence_history;


CREATE TABLE browse ( 
	"user" 	varchar(250) NOT NULL,
	realm	varchar(250) NOT NULL,
	xml  	text NOT NULL 
	);

CREATE TABLE last ( 
	"user" 	varchar(250) NOT NULL,
	realm	varchar(250) NOT NULL,
	last 	int8 NULL,
	text 	varchar(250) NOT NULL,
	xml  	text NOT NULL 
	);

CREATE TABLE mailaddresses ( 
	"user"        	varchar(250) NOT NULL,
	realm       	varchar(250) NOT NULL,
	mailaddress 	text NULL,
	lastmodified	timestamp NULL 
	);

CREATE TABLE messages ( 
	"user"         	varchar(250) NOT NULL,
	realm        	varchar(250) NOT NULL,
	node         	varchar(24) NULL,
	correspondent	varchar(250) NOT NULL,
	type         	varchar(250) NOT NULL DEFAULT 'offline'::character varying,
	storetime    	timestamp NOT NULL DEFAULT now(),
	delivertime  	timestamp NULL,
	subject      	varchar(250) NULL,
	body         	text NOT NULL,
	xml          	text NOT NULL 
	);

CREATE TABLE presence ( 
	"user"     	varchar(250) NOT NULL,
	realm    	varchar(250) NOT NULL,
	presence 	varchar(250) NOT NULL DEFAULT 'unavailable'::character varying,
	priority 	varchar(250) NOT NULL DEFAULT 0,
	status   	text NOT NULL,
	timestamp	timestamp NOT NULL DEFAULT now() 
	);

CREATE TABLE presence_history ( 
	idpresencehistory	int4 NOT NULL DEFAULT nextval('seq_presence_history'::regclass),
	datewhen         	timestamp NOT NULL DEFAULT now(),
	"user"             	varchar(250) NOT NULL,
	realm            	varchar(250) NOT NULL,
	presence         	varchar(250) NOT NULL DEFAULT 'unavailable'::character varying,
	priority         	varchar(250) NOT NULL DEFAULT 0,
	status           	text NOT NULL,
	timestamp        	timestamp NOT NULL DEFAULT now(),
	opcode           	varchar(5) NULL 
	);

CREATE TABLE privacy ( 
	"user"         	varchar(250) NOT NULL,
	realm        	varchar(250) NOT NULL,
	name         	varchar(250) NOT NULL,
	isdefault    	varchar(250) NULL,
	xml          	text NOT NULL,
	last_modified	timestamp NOT NULL 
	);

CREATE TABLE private ( 
	"user"         	varchar(250) NOT NULL,
	realm        	varchar(250) NOT NULL,
	ns           	text NOT NULL,
	xml          	text NOT NULL,
	last_modified	timestamp NOT NULL 
	);

CREATE TABLE roster ( 
	"user" 	varchar(250) NOT NULL,
	realm	varchar(250) NOT NULL,
	xml  	text NOT NULL 
	);

CREATE TABLE storedsubscriptionrequests ( 
	"user"   	varchar(250) NOT NULL,
	realm  	varchar(250) NOT NULL,
	fromjid	text NOT NULL,
	xml    	text NOT NULL 
	);

CREATE TABLE users ( 
	"user"    	varchar(250) NOT NULL,
	realm   	varchar(250) NOT NULL,
	"password"	text NOT NULL 
	);

CREATE TABLE vcard ( 
	"user"    	varchar(250) NOT NULL,
	realm   	varchar(250) NOT NULL,
	name    	text NULL,
	email   	text NULL,
	nickname	varchar(250) NULL,
	birthday	varchar(250) NULL,
	photo   	text NULL,
	xml     	text NULL 
	);



CREATE FUNCTION public.if (B1 bool, C1 varchar, C2 varchar) RETURNS varchar AS
'BEGIN
	IF ("B1") THEN
		RETURN "C1";
	ELSE
		RETURN "C2";
	END IF;
END;'
LANGUAGE 'plpgsql';

CREATE FUNCTION public.if (B1 bool, C1 int4, C2 int4) RETURNS varchar AS
'BEGIN
	IF ("B1") THEN
		RETURN "C1";
	ELSE
		RETURN "C2";
	END IF;
END;'
LANGUAGE 'plpgsql';

ALTER TABLE browse ADD CONSTRAINT xmpp_browse_pkey PRIMARY KEY ("user", realm);

ALTER TABLE last ADD CONSTRAINT xmpp_last_pkey PRIMARY KEY ("user", realm);

ALTER TABLE mailaddresses ADD CONSTRAINT mailaddresses_pkey PRIMARY KEY ("user", realm);

ALTER TABLE presence ADD CONSTRAINT presence_pkey PRIMARY KEY ("user", realm);

ALTER TABLE presence_history ADD CONSTRAINT xmpp_presence_history_pkey PRIMARY KEY (idpresencehistory);

ALTER TABLE privacy ADD CONSTRAINT privacy_pkey	PRIMARY KEY ("user", realm, name);

ALTER TABLE private ADD CONSTRAINT private_pkey	PRIMARY KEY ("user", realm, ns);

ALTER TABLE roster ADD CONSTRAINT roster_pkey PRIMARY KEY ("user", realm);

ALTER TABLE storedsubscriptionrequests ADD CONSTRAINT storedsubscriptionrequests_pkey PRIMARY KEY ("user", realm);

ALTER TABLE users ADD CONSTRAINT users_pkey PRIMARY KEY ("user", realm);

ALTER TABLE vcard ADD CONSTRAINT vcard_pkey PRIMARY KEY ("user", realm);


CREATE OR REPLACE FUNCTION tg_xmpp_presence()
  RETURNS "trigger" AS
$BODY$BEGIN

	IF (TG_OP = 'DELETE') THEN
		INSERT INTO presence_history (
			"user",
			realm,
			presence,
			priority,
			status,
			"timestamp",
			opcode
		) VALUES (
			OLD."user",
			OLD.realm,
			OLD.presence,
			OLD.priority,
			OLD.status,
			OLD."timestamp",
			'DEL'
		);
            RETURN OLD;
        ELSIF (TG_OP = 'UPDATE') THEN
		INSERT INTO presence_history (
			"user",
			realm,
			presence,
			priority,
			status,
			"timestamp",
			opcode
		) VALUES (
			NEW."user",
			NEW.realm,
			NEW.presence,
			NEW.priority,
			NEW.status,
			NEW."timestamp",
			'UPD'
		);
		RETURN NEW;
        ELSIF (TG_OP = 'INSERT') THEN
		INSERT INTO presence_history (
			"user",
			realm,
			presence,
			priority,
			status,
			"timestamp",
			opcode
		) VALUES (
			NEW."user",
			NEW.realm,
			NEW.presence,
			NEW.priority,
			NEW.status,
			NEW."timestamp",
			'INS'
		);
		RETURN NEW;
        END IF;
	RETURN NULL;
END$BODY$
  LANGUAGE 'plpgsql' VOLATILE;
ALTER FUNCTION tg_xmpp_presence() OWNER TO postgres;

CREATE TRIGGER t_iud_xmpp_presence
  AFTER INSERT OR UPDATE OR DELETE
  ON presence
  FOR EACH ROW
  EXECUTE PROCEDURE tg_xmpp_presence();

CREATE ROLE xmpp_daemons NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE;

GRANT ALL ON TABLE browse TO xmpp_daemons;

GRANT ALL ON TABLE last TO xmpp_daemons;

GRANT ALL ON TABLE mailaddresses TO xmpp_daemons;

GRANT ALL ON TABLE messages TO xmpp_daemons;

GRANT ALL ON TABLE presence TO xmpp_daemons;

GRANT INSERT ON TABLE presence_history TO xmpp_daemons;

GRANT ALL ON TABLE privacy TO xmpp_daemons;

GRANT ALL ON TABLE private TO xmpp_daemons;

GRANT ALL ON TABLE roster TO xmpp_daemons;

GRANT ALL ON TABLE storedsubscriptionrequests TO xmpp_daemons;

GRANT ALL ON TABLE users TO xmpp_daemons;

GRANT ALL ON TABLE vcard TO xmpp_daemons;

CREATE ROLE jabber14 LOGIN PASSWORD 'test' NOSUPERUSER INHERIT NOCREATEDB NOCREATEROLE;
GRANT xmpp_daemons TO jabber14;
