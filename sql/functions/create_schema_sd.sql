create or replace function pg_acm.create_schema_sd (
   p_schema_name text,
   p_schema_admin text,
   p_schema_owner_setting boolean)
--setting up the roles together with creating schemas
RETURNS text
AS
$create_schema$
DECLARE
   v_sql text;
   v_sql_role text;
   v_current_schema_owner text;
   v_create_schema_sql text;
   v_schema_owner text=p_schema_name||'_owner';
   v_read_only_role text:=p_schema_name||'_read_only';
   v_read_write_role text:=p_schema_name||'_read_write';
BEGIN
  if not pg_acm.check_stack('pg_acm.create_schema') then
    raise exception 'You are not allowed to create schemas: please connect as a database/account owner';
  end if;
  if length(p_schema_name)>54 then
     raise exception 'The length of the schema name should be less than 54, please choose another name for your schema. Schema:%', p_schema_name;
   end if;
   v_current_schema_owner=
      (select pg_catalog.pg_get_userbyid(nspowner)
       from pg_namespace
       where nspname=p_schema_name
      );
     v_create_schema_sql:=format($sql$
        create role %s;
        alter schema %s owner to  %s;
        grant %s to %s;
        grant all on schema %s to %s;
        revoke all on schema %s from %s; $sql$,
        v_schema_owner,
        p_schema_name,
        v_schema_owner,
        v_schema_owner,
        p_schema_admin,
        p_schema_name,
        v_schema_owner,
        p_schema_name,
        v_current_schema_owner);
     v_sql:=v_create_schema_sql||
       format($sql$
         create role %s;
         create role %s;
         grant usage on schema %s to %s;
         grant usage on schema %s to %s;
         alter default privileges for role %s in schema %s
         grant select on tables to %s;
         alter default privileges for role %s in schema %s
         grant select, insert, update, delete, truncate on tables to %s;
         alter default privileges for role %s in schema %s
         grant usage on sequences to %s;
       $sql$,
       v_read_only_role,
       v_read_write_role,
       p_schema_name,
       v_read_only_role,
       p_schema_name,
       v_read_write_role,
       v_schema_owner,
       p_schema_name,
       v_read_only_role,
       v_schema_owner,
       p_schema_name,
       v_read_write_role,
       v_schema_owner,
       p_schema_name,
       v_read_write_role);
   -- raise notice '%', v_sql;
   execute v_sql;
   RETURN v_sql;
END;
$create_schema$
language plpgsql security definer;
revoke execute on function pg_acm.create_schema_sd from public;
