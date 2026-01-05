SET client_min_messages TO WARNING;

CREATE ROLE test_db_owner;
CREATE DATABASE test_db;
ALTER DATABASE test_db OWNER TO test_db_owner;
CREATE USER test_db_admin PASSWORD 'admin1';
GRANT test_db_owner TO test_db_admin;
\connect test_db

SET client_min_messages TO WARNING;

\i _load_all.sql

CREATE EXTENSION pgtap;

SELECT * FROM pg_acm.enable_security();

BEGIN;
alter event trigger fix_owner_grants disable;
SELECT plan(61);
alter event trigger fix_owner_grants enable;
set role test_db_admin;
---create account---

select lives_ok($$
select * from pg_acm.create_cust_account ('acct1');
$$,'create customer account acct1');

select has_role ('acct1_owner', 'Role acct1_owner was created');

select function_privs_are ('pg_acm', 'create_schema_sd', array['text', 'text','boolean'], 'acct1_owner', array['EXECUTE'], 'acct1_owner should execute pg_acm.create_schema_roles_sd');
select function_privs_are ('pg_acm','check_schema_perm' , array['text'], 'acct1_owner', array['EXECUTE'], 'acct1_owner should execute pg_acm.create_schema_roles');
select function_privs_are ('pg_acm','check_stack' , array['text'], 'acct1_owner', array['EXECUTE'], 'acct1_owner should execute pg_acm.check_stack');
select function_privs_are ('pg_acm','creat_role_for_schema' , array['text','boolean','boolean','boolean','boolean','boolean'], 'acct1_owner', array['EXECUTE'], 'acct1_owner should execute pg_acm.drop_schema_roles');
select function_privs_are ('pg_acm','drop_schema_roles_sd' , array['text'], 'acct1_owner', array['EXECUTE'], 'acct1_owner should execute pg_acm.drop_schema_roles_sd');
select function_privs_are ('pg_acm','assign_schema_role' , array['text','text','text','text','boolean'], 'acct1_owner', array['EXECUTE'], 'acct1_owner should execute pg_acm.assign_schema_role');
select function_privs_are ('pg_acm','assign_schema_role_sd' , array['text','text','text','text','boolean'], 'acct1_owner', array['EXECUTE'], 'acct1_owner should execute pg_acm.assign_schema_role_sd');
select function_privs_are ('pg_acm','revoke_role' , array['text','text','text'], 'acct1_owner', array['EXECUTE'], 'acct1_owner should execute pg_acm.revoke_role');
select function_privs_are ('pg_acm','revoke_role_sd' , array['text','text','text'], 'acct1_owner', array['EXECUTE'], 'acct1_owner should execute pg_acm.revoke_role_sd');
select function_privs_are ('pg_acm','assign_schema_app_role' , array['text','text','text','boolean'], 'acct1_owner', array['EXECUTE'], 'acct1_owner should execute pg_acm.assign_schema_app_role');
select function_privs_are ('pg_acm','assign_schema_schema_owner_role' , array['text','text','text','boolean'], 'acct1_owner', array['EXECUTE'], 'acct1_owner should execute pg_acm.assign_schema_schema_owner_role');
select function_privs_are ('pg_acm','assign_schema_ro_role' , array['text','text','text','boolean'], 'acct1_owner', array['EXECUTE'], 'acct1_owner should execute pg_acm.assign_schema_ro_role');
select function_privs_are ('pg_acm','revoke_schema_app_role' , array['text','text'], 'acct1_owner', array['EXECUTE'], 'acct1_owner should execute pg_acm.revoke_schema_app_role');
select function_privs_are ('pg_acm','revoke_schema_schema_owner_role' , array['text','text'], 'acct1_owner', array['EXECUTE'], 'acct1_owner should execute pg_acm.revoke_schema_schema_owner_role');
select function_privs_are ('pg_acm','revoke_schema_ro_role' , array['text','text'], 'acct1_owner', array['EXECUTE'], 'acct1_owner should execute pg_acm.revoke_schema_ro_role');

select lives_ok($$
select * from pg_acm.assign_account_role('acct1', 'acct_user1', 'acct1');
$$, 'create acct_user1 for acct1');

select lives_ok($$
select * from pg_acm.assign_account_role('acct1', 'acct_user1', 'acct2');
$$, 'change password for acct_user1');

select is_member_of ('acct1_owner','acct_user1', 'User acct_user1 has acct1_owner role');

select lives_ok($$
select * from pg_acm.create_cust_account ('acct2');
$$,'create customer account acct2');
select lives_ok($$
select * from pg_acm.assign_account_role('acct2', 'acct_user2', 'acct2');
$$, 'create acct_user2 for acct2');

select lives_ok($$set role acct1_owner;$$,'role set to acct1_owner');

select lives_ok($$create schema acct1_schema1$$,
'create schema acct1_schema1 for acct1 with all matching roles using nologin role');

select schema_owner_is ('acct1_schema1', 'acct1_schema1_owner', 'Owner of acct1_schema1 is acct1_schema1_owner');

select lives_ok($$set role acct_user1;$$,'role set to acct_user1');

select lives_ok($$create schema acct1_schema2$$,
'create schema acct1_schema2 for acct1 with all matching roles using login role');

select lives_ok($$set role acct_user2;$$,'role set to acct_user2');

select lives_ok($$create schema acct2_schema1$$,
'create schema acct2_schema1 for acct2 with all matching roles');
select lives_ok($$create schema acct2_schema2$$,
'create schema acct2_schema2 for acct2 with all matching roles');

select lives_ok($$drop schema acct2_schema2;$$, 'drop acct2_schema2 schema with associated roles');

select lives_ok($$create schema acct2_schema3;$$, 'create schema acct2_schema3 schema without using sd-function');

select lives_ok($$select * from pg_acm.assign_schema_schema_owner_role('acct2_schema3', 'owner23_user', 'pwd')$$,
'create schema owner user for schema acct2_schema3');

select lives_ok($$select * from pg_acm.assign_schema_app_role('acct2_schema3', 'app23_user', 'pwd')$$,
'create schema app user for schema acct2_schema3');

select lives_ok ($$select * from pg_acm.assign_schema_ro_role('acct2_schema3', 'ro23_user', 'pwd');$$, 'create ro user ro23_user for schema acct2_schema3');

select throws_ok($$drop schema acct1_schema2;$$,'42501', 'must be owner of schema acct1_schema2', 'You are not allowed to drop schema acct1_schema2') ;

select throws_ok($$select * from pg_acm.assign_schema_app_role('acct2_schema1', 'app21_user');$$, 'P0001','NULL password for new user: app21_user',
$e$NULL password for new user: app21_user$e$);

select lives_ok($$select * from pg_acm.assign_schema_app_role
('acct2_schema1', 'app21_user', 'passwd2');$$, $$create app user app21_user for acct2_schema1$$);

set role postgres;

create temporary table acct_password as select rolpassword from pg_authid where rolname ='app21_user';

set role acct_user2;

select lives_ok($$select * from pg_acm.assign_schema_app_role
('acct2_schema1', 'app21_user', 'passwd3');$$, $$Change password for user app21_user$$);

set role postgres;

SELECT isnt( rolpassword, (select rolpassword from acct_password), 'Password changed')
  FROM pg_authid where rolname ='app21_user';

create temporary table acct_search_path as select substr (settings,13) as search_path
  from (select usename, unnest(useconfig) as settings from pg_shadow) a
  where substr (settings, 1, 12) ='search_path=' and usename ='ro23_user';


SELECT is( 'acct2_schema3, public', (select search_path from acct_search_path), 'Search_path was set up correctly');

set role acct_user2;
select lives_ok ($$select * from pg_acm.assign_schema_ro_role('acct2_schema1', 'ro23_user', null, false );$$, 'assign acct2_schema1 read role to ro23_user with no path change');

set role postgres;

select is(substr (settings,13), (select search_path from acct_search_path), $$Search_path didn't change$$)
  from (select usename, unnest(useconfig) as settings from pg_shadow) a
  where substr (settings, 1, 12) ='search_path=' and usename ='ro23_user';

select lives_ok($$set role acct_user1$$,'role set to acct_user1');

select lives_ok($$select * from pg_acm.assign_schema_schema_owner_role
('acct1_schema1', 'acc_owner_user11', 'passwd1');$$, $$create owner user acc_owner_user11 for acct1_schema1$$);

select throws_ok($$select * from pg_acm.revoke_schema_app_role
('acct2_schema1', 'app21_user');$$, 'P0001','You are not allowed to manage roles in schema acct2_schema1', $$You are not allowed to manage roles in schema acct2_schema1$$);

select lives_ok($$set role acct_user2;$$,'role set to acct_user2');

select lives_ok($$select * from pg_acm.revoke_schema_app_role
('acct2_schema1', 'app21_user');$$, $$revoke read_write role on schema acct2_schema1 from app21_user$$);

select lives_ok($$select * from pg_acm.assign_schema_app_role
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

select hasnt_role ('acct2_schema3_owner', 'Role acct2_schema3_owner was dropped');
select hasnt_role ('acct2_schema3_read_write', 'Role acct2_schema3_read_write was dropped');
select hasnt_role ('acct2_schema3_read_only', 'Role acct2_schema3_read_only was dropped');


SELECT * FROM finish();
set role postgres;
ROLLBACK;

\connect postgres
DROP USER test_db_admin;
DROP DATABASE test_db;
DROP ROLE test_db_owner;
