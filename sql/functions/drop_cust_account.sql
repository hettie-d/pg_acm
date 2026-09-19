create or replace function acm_tools.drop_cust_account (p_acct_name text,
p_force boolean default false)
returns text
language plpgsql
as $body$
declare
v_sql text;
v_sql_schemas text:=' ';
v_sql_role text;
v_cnt int;
v_rec record;
begin
  v_sql_role :=p_acct_name||'_owner';
  select count(*) into v_cnt from pg_roles where rolname=v_sql_role;
  if v_cnt=0 then
    raise exception 'Account % does not exist', p_acct_name;
  else
    select count(*) into v_cnt from acm_tools.list_account_schemas(p_acct_name);
  end if;
  if v_cnt>0 and not p_force then
   raise exception 'Account % still owns schemas. Use option p_force=true to cascade drop', p_acct_name;
  else
   if v_cnt>0 then
       for v_rec in (select * from acm_tools.list_account_schemas(p_acct_name)) loop
           v_sql_schemas:= v_sql_schemas||' drop schema '||v_rec.list_account_schemas|| ' cascade;';
       end loop;
       execute v_sql_schemas;
    end if;
	select acm_tools.drop_cust_account_sd (p_acct_name) into v_sql;
end if;
return v_sql_schemas||v_sql;
end;
$body$;

revoke execute on function acm_tools.drop_cust_account from public;


