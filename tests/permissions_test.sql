set client_min_messages to warning;

create role test_db_owner;
create role acct2_sub_role;
create database test_db;
alter database test_db owner to test_db_owner;
create user test_db_admin password 'admin1';
grant test_db_owner to test_db_admin;
\connect test_db

set client_min_messages to warning;

\i pg_acm/_load_all.sql

create extension pgtap;

select * from acm_tools.enable_security();

begin;
	
alter event trigger fix_owner_grants disable;

select plan(86);

alter event trigger fix_owner_grants enable;


set role test_db_admin;
---create account---

select lives_ok($$
select * from acm_tools.create_cust_account ('acct1');
$$,'create customer account acct1');

select has_role ('acct1_owner', 'role acct1_owner was created');

select function_privs_are ('acm_tools', 'create_schema_sd', array['text', 'text','boolean'], 'acct1_owner', array['execute'], 'acct1_owner should execute acm_tools.create_schema_roles_sd');
select function_privs_are ('acm_tools','check_schema_perm' , array['text'], 'acct1_owner', array['execute'], 'acct1_owner should execute acm_tools.create_schema_roles');
select function_privs_are ('acm_tools','check_stack' , array['text'], 'acct1_owner', array['execute'], 'acct1_owner should execute acm_tools.check_stack');
select function_privs_are ('acm_tools','drop_schema_roles_sd' , array['text'], 'acct1_owner', array['execute'], 'acct1_owner should execute acm_tools.drop_schema_roles_sd');
select function_privs_are ('acm_tools','assign_schema_role' , array['text','text','text','text','boolean', 'integer'], 'acct1_owner', array['execute'], 'acct1_owner should execute acm_tools.assign_schema_role');
select function_privs_are ('acm_tools','assign_schema_role_sd' , array['text','text','text','text','boolean', 'integer'], 'acct1_owner', array['execute'], 'acct1_owner should execute acm_tools.assign_schema_role_sd');
select function_privs_are ('acm_tools','revoke_role' , array['text','text','text'], 'acct1_owner', array['execute'], 'acct1_owner should execute acm_tools.revoke_role');
select function_privs_are ('acm_tools','revoke_role_sd' , array['text','text','text'], 'acct1_owner', array['execute'], 'acct1_owner should execute acm_tools.revoke_role_sd');
select function_privs_are ('acm_tools','assign_schema_app_role' , array['text','text','text','boolean'], 'acct1_owner', array['execute'], 'acct1_owner should execute acm_tools.assign_schema_app_role');
select function_privs_are ('acm_tools','assign_schema_schema_owner_role' , array['text','text','text','boolean'], 'acct1_owner', array['execute'], 'acct1_owner should execute acm_tools.assign_schema_schema_owner_role');
select function_privs_are ('acm_tools','assign_schema_ro_role' , array['text','text','text','boolean'], 'acct1_owner', array['execute'], 'acct1_owner should execute acm_tools.assign_schema_ro_role');
select function_privs_are ('acm_tools','revoke_schema_app_role' , array['text','text'], 'acct1_owner', array['execute'], 'acct1_owner should execute acm_tools.revoke_schema_app_role');
select function_privs_are ('acm_tools','revoke_schema_schema_owner_role' , array['text','text'], 'acct1_owner', array['execute'], 'acct1_owner should execute acm_tools.revoke_schema_schema_owner_role');
select function_privs_are ('acm_tools','revoke_schema_ro_role' , array['text','text'], 'acct1_owner', array['execute'], 'acct1_owner should execute acm_tools.revoke_schema_ro_role');
select function_privs_are ('acm_tools','create_role_for_schema' , array['text','boolean','boolean','boolean','boolean','boolean'], 'acct1_owner', array['execute'], 'acct1_owner should execute acm_tools.create_role_for_schema');

select lives_ok($$
select * from acm_tools.assign_account_role('acct1', 'acct_user1', 'acct1');
$$, 'create acct_user1 for acct1');

select is(count(*)::int,1,$$alter trigger exists$$)
from  pg_event_trigger
             where evtname='rename_roles_for_schema' and evtenabled='o';

select lives_ok($$
select * from acm_tools.assign_account_role('acct1', 'acct_user1', 'acct2');
$$, 'change password for acct_user1');

select is_member_of ('acct1_owner','acct_user1', 'user acct_user1 has acct1_owner role');

select lives_ok($$
select * from acm_tools.create_cust_account ('acct2');
$$,'create customer account acct2');
select lives_ok($$
select * from acm_tools.assign_account_role('acct2', 'acct_user2', 'acct2');
$$, 'create acct_user2 for acct2');

select lives_ok($$set role acct1_owner;$$,'role set to acct1_owner');

select lives_ok($$create schema acct1_schema1;$$,
'create schema acct1_schema1 for acct1 with all matching roles using nologin role');

select schema_owner_is ('acct1_schema1', 'acct1_schema1_owner', 'owner of acct1_schema1 is acct1_schema1_owner');
select lives_ok($$create schema if not exists acct1_schema1$$,
'create schema if not exists works');

select lives_ok($$create schema acct1_schema_old_name;$$, $$create schema for renaming$$);

alter schema acct1_schema_old_name rename to acct1_schema_new_name;

select schema_owner_is ('acct1_schema_new_name', 'acct1_schema_new_name_owner', 'owner of acct1_schema_new_name is acct1_schema_new_name_owner');

select is(count(*)::int,0,$$no roles with old schema name$$)
from pg_roles where rolname = 'acct1_schema_old_name_read_only';


select isnt(count(*)::int,0,$$roles with new schema name were created$$)
  from pg_roles where rolname ='acct1_schema_new_name_read_only';

select lives_ok($$set role acct_user1;$$,'role set to acct_user1');

select lives_ok($$create schema acct1_schema2;$$,
'create schema acct1_schema2 for acct1 with all matching roles using login role');

select lives_ok($$set role acct_user2;$$,'role set to acct_user2');

select lives_ok($$create schema acct2_schema1;$$,
'create schema acct2_schema1 for acct2 with all matching roles');
select lives_ok($$create schema acct2_schema2;$$,
'create schema acct2_schema2 for acct2 with all matching roles');

select lives_ok($$drop schema acct2_schema2;$$, 'drop acct2_schema2 schema with associated roles');

select lives_ok($$create schema acct2_schema3;$$, 'create schema acct2_schema3 schema without using sd-function');

select lives_ok($$select * from acm_tools.assign_schema_schema_owner_role('acct2_schema3', 'owner23_user', 'pwd')$$,
'create schema owner user for schema acct2_schema3');

set role test_db_owner;

select lives_ok($$select * from acm_tools.assign_schema_app_role('acct2_schema3', 'app23_user', 'pwd')$$,
'create schema app user for schema acct2_schema3 using db_owner');

set role acct_user2;

select isnt (-1,(select rolconnlimit from pg_roles where rolname='app23_user') , 'user conneciton limit set' );

select lives_ok ($$select * from acm_tools.assign_schema_ro_role('acct2_schema3', 'ro23_user', 'pwd');$$, 'create ro user ro23_user for schema acct2_schema3');

select throws_ok($$drop schema acct1_schema2);$$,'42501', 'must be owner of schema acct1_schema2', 'you are not allowed to drop schema acct1_schema2') ;

select throws_ok($$select * from acm_tools.assign_schema_app_role('acct2_schema1', 'app21_user');$$, 'p0001','null password for new user: app21_user',
$e$null password for new user: app21_user$e$);

select lives_ok($$select * from acm_tools.assign_schema_app_role
('acct2_schema1', 'app21_user', 'passwd2');$$, $$create app user app21_user for acct2_schema1$$);

set role postgres;

create temporary table acct_password as select rolpassword from pg_authid where rolname ='app21_user';

set role acct_user2;

select lives_ok($$select * from acm_tools.assign_schema_app_role
('acct2_schema1', 'app21_user', 'passwd3');$$, $$change password for user app21_user$$);

set role postgres;

select isnt( rolpassword, (select rolpassword from acct_password), 'password changed')
  from pg_authid where rolname ='app21_user';

create temporary table acct_search_path as select substr (settings,13) as search_path
  from (select usename, unnest(useconfig) as settings from pg_shadow) a
  where substr (settings, 1, 12) ='search_path=' and usename ='ro23_user';

select is( 'acct2_schema3, public', (select search_path from acct_search_path), 'search_path was set up correctly');

set role acct_user2;
select lives_ok ($$select * from acm_tools.assign_schema_ro_role('acct2_schema1', 'ro23_user', null, false );$$, 'assign acct2_schema1 read role to ro23_user with no path change');

set role postgres;

select is(substr (settings,13), (select search_path from acct_search_path), $$search_path didn't change$$)
  from (select usename, unnest(useconfig) as settings from pg_shadow) a
  where substr (settings, 1, 12) ='search_path=' and usename ='ro23_user';

select lives_ok($$set role acct_user1$$,'role set to acct_user1');

select lives_ok($$select * from acm_tools.assign_schema_schema_owner_role
('acct1_schema1', 'acc_owner_user11', 'passwd1');$$, $$create owner user acc_owner_user11 for acct1_schema1$$);

select throws_ok($$select * from acm_tools.revoke_schema_app_role
('acct2_schema1', 'app21_user');$$, 'p0001','you are not allowed to manage roles in schema acct2_schema1', $$you are not allowed to manage roles in schema acct2_schema1$$);

select lives_ok($$set role acct_user2;$$,'role set to acct_user2');

select lives_ok($$select * from acm_tools.revoke_schema_app_role
('acct2_schema1', 'app21_user');$$, $$revoke read_write role on schema acct2_schema1 from app21_user$$);

select lives_ok($$select * from acm_tools.assign_schema_app_role
('acct2_schema1', 'app21_user');$$, $$assign app user role  to user app21_user for acct2_schema1$$);

select lives_ok($$set role owner23_user;$$,'role set to owner23_user');

select lives_ok($$create table acct2_schema3.table231 (
a int primary key,
b int
);$$, 'user owner23_user can create tables in schema acct2_schema3');

select lives_ok($$create temp table t_table231 (
a int,
b int
);$$, 'user owner23_user can create temporary tables');

select lives_ok($$set role app23_user;$$,'role set to app23_user');

select lives_ok($$insert into acct2_schema3.table231 values (1,2);$$,
 'user app23_user can insert into tables in schema acct2_schema3');

select lives_ok($$truncate table acct2_schema3.table231;$$,
 'user app23_user can truncate tables in schema acct2_schema3');

select lives_ok($$set role ro23_user;$$,'role set to ro23_user');

select lives_ok($$select * from acct2_schema3.table231;
$$, 'user ro23_user can select from tables in schema acct2_schema3');

set role acct_user2;

select lives_ok($$drop schema acct2_schema3 cascade;$$, 'drop schema acct2_schema3 schema without using sd-function');

select hasnt_role ('acct2_schema3_owner', 'role acct2_schema3_owner was dropped');
select hasnt_role ('acct2_schema3_read_write', 'role acct2_schema3_read_write was dropped');
select hasnt_role ('acct2_schema3_read_only', 'role acct2_schema3_read_only was dropped');

set role test_db_owner;

create table acct2_schema1.table121 (
a int primary key,
b int
);

create type  acct2_schema1.type1_record as (
aa text,
i int
);

set role postgres;

select lives_ok($$call acm_tools.reset_schema_owner ('acct2_schema1','acct2_sub_role')$$, 'reset_schema_owner works');
select lives_ok($$select jsonb_pretty(to_jsonb(acm_tools.list_schemas_roles ()))$$, 'list_schema_roles in jsonb format works');
select lives_ok($$select * from acm_tools.list_acct_schemas_roles_flat ()$$, 'list_schema_roles in flat format works');

set role  test_db_owner;
select * from acm_tools.create_cust_account ('acct4');
select lives_ok($$select * from acm_tools.drop_cust_account('acct4')$$, 'empty account dropped');
select throws_ok ($$select * from acm_tools.drop_cust_account('acct1')$$, 'p0001',
'account acct1 still owns schemas. use option p_force=true to cascade drop', $$can't drop non-empty account without force$$);
select lives_ok ($$select * from acm_tools.drop_cust_account('acct1', true)$$, 'drop non-empty account with force');

select is(count(*)::int,0,$$no more schemas for acct3$$) from acm_tools.list_account_schemas('acct3');

select throws_ok($$create extension postgres_fdw;$$,'p0001', 'only superuser can create extension; error: must be owner of event trigger create_roles_for_schema', 'you are not allowed to create extensions') ;

set role postgres; --only superuser can create extensions

select lives_ok($$create extension postgis_tiger_geocoder cascade;$$,
                'create extension succeeds;');

-- the extension's own schema was created (by the extension, not by
-- create_roles_for_schema), so its objects have somewhere to live.
select has_schema('tiger'::name, 'the extension created its own "tiger" schema');

-- the extension owns its own objects in the "tiger" schema; fix_after did
-- not grant them to schema roles that do not exist, and create_roles_for_schema
-- did not create roles for the extension's own schema.
select is(count(*)::int, 0, 'no bogus schema roles were created for the extension')
  from pg_roles where rolname in ('tiger_read_only', 'tiger_read_write');

select lives_ok($$alter extension postgis_tiger_geocoder update;$$,
                'alter extension succeeds');
set role acct2_owner;

select lives_ok($$create schema test_trigger;$$,
                'creating schema after extention creation');

select has_role('test_trigger_read_only', 'event trigger enabled');
select lives_ok($$select * from acm_tools.create_role_for_schema (
  p_schema_name => 'test_trigger',
  p_select => true,
  p_insert=> true);$$, 'select_insert role created');
create table test_trigger.test_table (a int);
set role test_trigger_si;
select lives_ok($$insert into test_trigger.test_table values (1);$$, ' test_trigger_si can insert');
select lives_ok($$select * from test_trigger.test_table;$$, ' test_trigger_si can select');


set role postgres;

select lives_ok($$drop extension postgis_tiger_geocoder;$$,
                'drop extension succeeds');


select * from finish();
set role postgres;
rollback;

\connect postgres
drop user test_db_admin;
drop database test_db;
drop role test_db_owner;
