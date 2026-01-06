# pg_acm

## Description

`pg_acm` is a collection of tools for access control management.

I encourage everyone interested to try it, and if you find it useful, please help me to advocated to add this functionality to Postgres!

## acm tools quick installation guide

* If you are creating a new database:

```sql
create role mydb_owner; ---or any other name
create database mydb; -- or any other name
alter database mydb owner to mydb_owner;
```

* Clone this repo

* Connect to `mydb` as a superuser (postgres) and switch to the `pg_acm` directory

* Run `_load_all.sql`

* Invoke `pg_acm` by running as a superuser:

```sql
SELECT * FROM acm_tools.enable_security();
```

**For detailed functionality description, please refer to the [User Manual](./acm_tools_user_guide.md).**
