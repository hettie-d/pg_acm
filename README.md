# pg_acm

## Description

`pg_acm` is a tools for access control management.

I encorage everyone interested to try it, and if you find it useful, please help me to advocated to add this functionality to Postgres!

## acm tools quick installation guide

* If you are creating a new database:

```
create role mydb_owner; ---or any other name
create database my_db; -- or any other name
alter database my_db owner to mydb_owner;
```

* Clone this repo.

* Connect to mydb as a superuser (postgres) and switch to the pg_acm directory

* run \_load\_all.sql

* invoke pg_acm by running as a superuser:

```
select * from pg_acm.enable_security();

```
**For detailed functionality description, please refer to the User Manual.**
