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

--select * from acm_tools.list_schemas_roles_flat ()
create or replace function acm_tools.list_schemas_roles_flat ()
returns setof acm_tools.schema_roles_record
language plpgsql
as
$body$
begin
return query select
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
and  nspname not in ('pg_catalog', 'information_schema', 'acm_tools', 'public')
order by nspname;
end;
$body$;
