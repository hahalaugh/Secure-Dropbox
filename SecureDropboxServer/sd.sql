CREATE TABLE [key_chain] (
[id] INTEGER  PRIMARY KEY NOT NULL,
[username] TEXT  NOT NULL,
[doc_id] TEXT  UNIQUE NOT NULL,
[doc_key] TEXT  NOT NULL
);
CREATE TABLE [sharing_pool] (
[id] INTEGER  PRIMARY KEY NOT NULL,
[from_user] TEXT  NOT NULL,
[to_user] TEXT  NOT NULL,
[doc_id] TEXT  NOT NULL,
[doc_key] TEXT  NOT NULL,
[url] TEXT  NOT NULL,
[expires] TEXT  NOT NULL
);
CREATE TABLE [user] (
[id] INTEGER  PRIMARY KEY NOT NULL,
[username] TEXT  UNIQUE NOT NULL,
[password] TEXT  NOT NULL,
[public_key] TEXT  UNIQUE NOT NULL,
[private_key] TEXT  UNIQUE NOT NULL,
[token] TEXT  NULL
);
