drop type if exists acm_tools.users cascade;
create type acm_tools.users as (
user_name text,
max_connections integer
);

drop type if exists acm_tools.schema_roles_record cascade;
create type acm_tools.schema_roles_record as(
schema_name text,
schema_owner text,
owner_users acm_tools.users[],
read_only_role text,
read_users acm_tools.users[],
read_write_role text,
app_users acm_tools.users[]
);


drop type if exists acm_tools.account_schemas_record cascade;

create type acm_tools.account_schemas_record as(
account_name text,
account_owner text,
account_users acm_tools.users[],
schemas acm_tools.schema_roles_record[]
);

--select jsonb_pretty(to_jsonb(acm_tools.list_schemas_roles ()))
drop function if exists acm_tools.list_schemas_roles;
create or replace function acm_tools.list_schemas_roles ()
returns  acm_tools.account_schemas_record[]
language plpgsql security definer
as
$body$
declare
v_sql text;
v_result acm_tools.account_schemas_record[];
begin
v_sql:= $$select array_agg(row(account,
       a.account_owner::text,
	   (WITH RECURSIVE x AS
(
  SELECT member::regrole,
         roleid::regrole AS role,
         member::regrole || ' -> ' || roleid::regrole AS path
  FROM pg_auth_members AS m
  UNION ALL
  SELECT x.member::regrole,
         m.roleid::regrole,
         x.path || ' -> ' || m.roleid::regrole
 FROM pg_auth_members AS m
    JOIN x ON m.member = x.role
  )
  SELECT array_agg(row(member,
  rolconnlimit )::acm_tools.users) as account_users
  FROM x
   join pg_roles pr on
   x.member::text=pr.rolname::text
  WHERE  x.role::text= a.account_owner
  and pr.rolcanlogin is true
  ),
	   schemas)::acm_tools.account_schemas_record)
	   from
(select substr(account_role_name, 1,
                  length(account_role_name)-position (reverse('_owner') in reverse(account_role_name))-(length('_owner')-1)) as account,
        account_role_name as account_owner
   from acm_tools.account_role  )a
left outer join
(select account_owner,
array_agg(row(schema_name,
               schema_owner,
			   owner_users,
			   read_only_role,
			   read_users,
			   read_write_role,
			   write_users)::acm_tools.schema_roles_record) schemas
	from
(select
s.nspname::text as schema_name,
r.rolname::text as schema_owner,
(WITH RECURSIVE x AS
(
  SELECT member::regrole,
         roleid::regrole AS role,
         member::regrole || ' -> ' || roleid::regrole AS path
  FROM pg_auth_members AS m
  UNION ALL
  SELECT x.member::regrole,
         m.roleid::regrole,
         x.path || ' -> ' || m.roleid::regrole
 FROM pg_auth_members AS m
    JOIN x ON m.member = x.role
  )
  SELECT distinct member
  FROM x
   join pg_roles pr on
   x.member::text=pr.rolname::text
  WHERE  x.role::text= r.rolname
  and pr.rolcanlogin is false
  and pr.rolname not in (select
                pg_catalog.pg_get_userbyid(d.datdba)
             FROM pg_catalog.pg_database d
             WHERE d.datname =current_database())
  ) as account_owner,
(WITH RECURSIVE x AS
(
  SELECT member::regrole,
         roleid::regrole AS role,
         member::regrole || ' -> ' || roleid::regrole AS path
  FROM pg_auth_members AS m
  UNION ALL
  SELECT x.member::regrole,
         m.roleid::regrole,
         x.path || ' -> ' || m.roleid::regrole
 FROM pg_auth_members AS m
    JOIN x ON m.member = x.role
  )
  SELECT array_agg(row(member,
  rolconnlimit )::acm_tools.users)
  FROM x
   join pg_roles pr on
   x.member::text=pr.rolname::text
  WHERE  x.role::text= r.rolname
  and pr.rolcanlogin is true
  ) as owner_users,
case (nspacl @> (s.nspname||'_read_only=U/'||r.rolname)::aclitem )
when true then s.nspname||'_read_only'
else 'no read-only role'
end as read_only_role,
(WITH RECURSIVE x AS
(
  SELECT member::regrole,
         roleid::regrole AS role,
         member::regrole || ' -> ' || roleid::regrole AS path
  FROM pg_auth_members AS m
  UNION ALL
  SELECT x.member::regrole,
         m.roleid::regrole,
         x.path || ' -> ' || m.roleid::regrole
 FROM pg_auth_members AS m
    JOIN x ON m.member = x.role
  )
  SELECT array_agg(row(member,
  rolconnlimit )::acm_tools.users)
  FROM x
   join pg_roles pr on
   x.member::text=pr.rolname::text
  WHERE  x.role::text= s.nspname||'_read_only'
  and pr.rolcanlogin is true
  ) as read_users,
case (nspacl @> (s.nspname||'_read_write=U/'||r.rolname)::aclitem )
when true then s.nspname||'_read_write'
else 'no read-write role'
end as read_write_role,
(WITH RECURSIVE x AS
(
  SELECT member::regrole,
         roleid::regrole AS role,
         member::regrole || ' -> ' || roleid::regrole AS path
  FROM pg_auth_members AS m
  UNION ALL
  SELECT x.member::regrole,
         m.roleid::regrole,
         x.path || ' -> ' || m.roleid::regrole
 FROM pg_auth_members AS m
    JOIN x ON m.member = x.role
  )
  SELECT array_agg(row(member,
  rolconnlimit )::acm_tools.users)
  FROM x
   join pg_roles pr on
   x.member::text=pr.rolname::text
  WHERE  x.role::text= s.nspname||'_read_write'
  and pr.rolcanlogin is true
  ) as write_users
from pg_namespace s
join pg_roles r
on r.oid=s.nspowner
where nspacl is not null
and  nspname not in ('pg_catalog', 'information_schema', 'acm_tools', 'public'))s
group by account_owner ) ss
on a.account_owner =ss.account_owner::text$$;
execute v_sql into v_result;
return  v_result;
end;
$body$;


drop type if exists acm_tools.account_schema_roles_flat_record cascade;

create type acm_tools.account_schema_roles_flat_record  as(
account text,
account_owner text,
account_users acm_tools.users[],
schema_name text,
schema_owner text,
owner_users acm_tools.users[],
read_only_role text,
read_users acm_tools.users[],
read_write_role text,
app_users acm_tools.users[]
);

create or replace function acm_tools.list_acct_schemas_roles_flat ()
returns setof acm_tools.account_schema_roles_flat_record
language plpgsql security definer
as
$body$
begin
return query 
select account, 
       a.account_owner ,
	   (WITH RECURSIVE x AS
(
  SELECT member::regrole,
         roleid::regrole AS role,
         member::regrole || ' -> ' || roleid::regrole AS path
  FROM pg_auth_members AS m
  UNION ALL
  SELECT x.member::regrole,
         m.roleid::regrole,
         x.path || ' -> ' || m.roleid::regrole
 FROM pg_auth_members AS m
    JOIN x ON m.member = x.role
  )
  SELECT array_agg(row(member,
  rolconnlimit )::acm_tools.users) as account_users
  FROM x
   join pg_roles pr on
   x.member::text=pr.rolname::text
  WHERE  x.role::text= a.account_owner
  and pr.rolcanlogin is true
  ),
	 schema_name, 
	 schema_owner,
	 owner_users,
	 read_only_role,
	 read_users,
	 read_write_role,
	 write_users
	   from 
(select substr(account_role_name, 1, 
                  length(account_role_name)-position (reverse('_owner') in reverse(account_role_name))-(length('_owner')-1)) as account,
        account_role_name as account_owner
   from acm_tools.account_role  )a
left outer join 
(select account_owner,
        schema_name,
        schema_owner,
			  owner_users,
			  read_only_role,
			  read_users,
			  read_write_role,
			  write_users
	from   
(select  
s.nspname::text as schema_name,
r.rolname::text as schema_owner,
(WITH RECURSIVE x AS
(
  SELECT member::regrole,
         roleid::regrole AS role,
         member::regrole || ' -> ' || roleid::regrole AS path
  FROM pg_auth_members AS m
  UNION ALL
  SELECT x.member::regrole,
         m.roleid::regrole,
         x.path || ' -> ' || m.roleid::regrole
 FROM pg_auth_members AS m
    JOIN x ON m.member = x.role
  )
  SELECT distinct member
  FROM x
   join pg_roles pr on
   x.member::text=pr.rolname::text
  WHERE  x.role::text= r.rolname
  and pr.rolcanlogin is false
  and pr.rolname not in (select
                pg_catalog.pg_get_userbyid(d.datdba)
             FROM pg_catalog.pg_database d
             WHERE d.datname =current_database())
  ) as account_owner,
(WITH RECURSIVE x AS
(
  SELECT member::regrole,
         roleid::regrole AS role,
         member::regrole || ' -> ' || roleid::regrole AS path
  FROM pg_auth_members AS m
  UNION ALL
  SELECT x.member::regrole,
         m.roleid::regrole,
         x.path || ' -> ' || m.roleid::regrole
 FROM pg_auth_members AS m
    JOIN x ON m.member = x.role
  )
  SELECT array_agg(row(member,
  rolconnlimit )::acm_tools.users)
  FROM x
   join pg_roles pr on
   x.member::text=pr.rolname::text
  WHERE  x.role::text= r.rolname
  and pr.rolcanlogin is true
  ) as owner_users,
case (nspacl @> (s.nspname||'_read_only=U/'||r.rolname)::aclitem )
when true then s.nspname||'_read_only'
else 'no read-only role'
end as read_only_role,
(WITH RECURSIVE x AS
(
  SELECT member::regrole,
         roleid::regrole AS role,
         member::regrole || ' -> ' || roleid::regrole AS path
  FROM pg_auth_members AS m
  UNION ALL
  SELECT x.member::regrole,
         m.roleid::regrole,
         x.path || ' -> ' || m.roleid::regrole
 FROM pg_auth_members AS m
    JOIN x ON m.member = x.role
  )
  SELECT array_agg(row(member,
  rolconnlimit )::acm_tools.users)
  FROM x
   join pg_roles pr on
   x.member::text=pr.rolname::text
  WHERE  x.role::text= s.nspname||'_read_only'
  and pr.rolcanlogin is true
  ) as read_users,
case (nspacl @> (s.nspname||'_read_write=U/'||r.rolname)::aclitem )
when true then s.nspname||'_read_write'
else 'no read-write role'
end as read_write_role,
(WITH RECURSIVE x AS
(
  SELECT member::regrole,
         roleid::regrole AS role,
         member::regrole || ' -> ' || roleid::regrole AS path
  FROM pg_auth_members AS m
  UNION ALL
  SELECT x.member::regrole,
         m.roleid::regrole,
         x.path || ' -> ' || m.roleid::regrole
 FROM pg_auth_members AS m
    JOIN x ON m.member = x.role
  )
  SELECT array_agg(row(member,
  rolconnlimit )::acm_tools.users)
  FROM x
   join pg_roles pr on
   x.member::text=pr.rolname::text
  WHERE  x.role::text= s.nspname||'_read_write'
  and pr.rolcanlogin is true
  ) as write_users
from pg_namespace s
join pg_roles r
on r.oid=s.nspowner
where nspacl is not null
and  nspname not in ('pg_catalog', 'information_schema', 'acm_tools', 'public'))s
) ss
on a.account_owner =ss.account_owner::text;
end;
$body$;
