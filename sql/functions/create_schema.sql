create or replace function acm_tools.create_schema(
   p_schema_name text)
--security invoker
returns text
language plpgsql  as
$create_schema$
declare
  v_sql text;
  v_account text;
  v_db_owner text;
  v_schema_admin text;
  v_account_owner_setting boolean;
  v_schema_owner_setting boolean;
  v_cnt int;
begin
   with recursive x as
      (
        select member::regrole,
               roleid::regrole as role
          from pg_auth_members as m
        union all
        select x.member::regrole,
               m.roleid::regrole
          from pg_auth_members as m
        join x on m.member = x.role
      )
      select count(distinct role) into v_cnt
      from (
            select member::text, role::text
              from x
              where member::text=current_user
                and role::text in (select account_role_name from acm_tools.account_role)
            union
            select account_role_name, account_role_name
              from acm_tools.account_role
              where account_role_name=current_user
           ) a;
    case (v_cnt)
      when 0 then
        raise exception 'You are not allowed to create schema for  account % or account does not exist', p_account;
      when 1 then
        with recursive x as
          (
            select member::regrole,
                  roleid::regrole as role
              from pg_auth_members as m
            union all
            select x.member::regrole,
                  m.roleid::regrole
              from pg_auth_members as m
            join x on m.member = x.role)
            select distinct substr(role::text,1, length(role::text)-6) into v_account
              from  (select member::text, role::text from x
              where member::text=current_user
                and role::text in (select account_role_name from acm_tools.account_role)
            union
            select account_role_name, account_role_name
              from acm_tools.account_role
              where account_role_name=current_user
          ) a;
      else
        raise exception 'Please switch to account onwer role to create schema %', p_schema_name;
    end case;
    v_schema_admin :=v_account||'_owner';
  return (select acm_tools.create_schema_sd(
              p_schema_name,
              v_schema_admin,
              v_schema_owner_setting));
  end;
$create_schema$;

