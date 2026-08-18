--
--helper procedure
--Moves all user-defined objects from public schema top private schema defined by p_schema_name parameter
-- Leaves all extension objects in the public schema
--
create or replace procedure pg_acm.public_to_private (p_schema_name text)
language plpgsql as
$func$
declare 
 v_schema_owner text;
 v_rec record;
 v_sql text;
 begin
 v_schema_owner :=(SELECT
   pg_catalog.pg_get_userbyid(d.datdba)
   FROM pg_catalog.pg_database d
   WHERE d.datname =current_database());
 execute $$create schema $$||p_schema_name || $$ authorization $$||v_schema_owner;
 v_sql := (SELECT 
 array_to_string(array_agg ('alter default privileges for role '||grantor||' in schema '||
     schema_name||
   ' grant '||privilege_type||
   ' on '||case (object_type)
    when 'r' then 'tables'
    when 'S' then 'sequences'
   end||' to '||
    grantee||
 case (is_grantable)
  when true then ' with grant option '
   else ''
    end),';')
   from (SELECT 
             nspname as schema_name,
             defaclobjtype as object_type,
             ((aclexplode(defaclacl)).grantor)::regrole as grantor,
             (aclexplode(defaclacl)).grantee::regrole as grantee,
             (aclexplode(defaclacl)).privilege_type as privilege_type,
             (aclexplode(defaclacl)).is_grantable as is_grantable
   -- default access privileges
         FROM pg_default_acl a JOIN pg_namespace b ON a.defaclnamespace=b.oid
         where nspname=p_schema_name) a
         where grantee !=grantor);
 if v_sql is not null then execute v_sql;
 end if;
 --move tables
 for v_rec in (
   select
 	  $$ alter table "$$||relname||
      $$" set schema $$||p_schema_name as stmt
        from  pg_class as tbl
        join pg_namespace as ns on ns.oid = tbl.relnamespace
        where nspname='public' and relkind in ('r','p', 'v', 'm')
 	      and tbl.oid not in (
 	        select d.objid
            from pg_depend d
            join pg_extension e on d.refobjid=e.oid
            and d.deptype='e'
            join pg_namespace s on s.oid=e.extnamespace
            and nspname='public'
           )	  
   )
   loop
     raise notice '%', v_rec.stmt;
     execute v_rec.stmt;
   end loop;
 --move sequences
 for v_rec in (select
 	 $$ alter sequence "$$||relname||
     $$" set schema $$||p_schema_name as stmt
       from  pg_class as tbl
       join pg_namespace as ns on ns.oid = tbl.relnamespace
       where nspname='public' and relkind in ('S')
 	     and tbl.oid not in (
 	       select d.objid
           from pg_depend d
           join pg_extension e on d.refobjid=e.oid
           and d.deptype='e'
           join pg_namespace s on s.oid=e.extnamespace
           and nspname='public'
           )
 	 )
   loop
     raise notice '%', v_rec.stmt;
     execute v_rec.stmt;
   end loop;
 --move types
 for v_rec in (select
 	 $$ alter type "$$||typname||
     $$" set schema $$||p_schema_name as stmt
       from  pg_type as t
       join pg_namespace as ns on ns.oid = t.typnamespace
       where nspname='public' 
       and typcategory !='A'
 	     and t.oid not in (
 	       select d.objid
           from pg_depend d
           join pg_extension e on d.refobjid=e.oid
           and d.deptype='e'
           join pg_namespace s on s.oid=e.extnamespace
 			     and nspname='public'
         union
          select
                l.objid
             from pg_depend t
             join pg_depend l on l.refobjid = t.objid
              where t.deptype='e'  )
   )
   loop
     raise notice '%', v_rec.stmt;
     execute v_rec.stmt;
   end loop;
 --move functions   
for v_rec in (
  select  $$ alter function "$$||proname||$$"($$||coalesce(args, '')||')set schema '||p_schema_name as stmt
    from (select 
            poid, 
            proname, 
            array_to_string(array_agg(typname), ',') as args
          from  
          (select 
             p.oid as poid, 
             proname, 
			       unnest(string_to_array (case proargtypes::text 
			                                when '' then '0'
			                                else 
			                                  proargtypes::text
			                                  end,  ' ')
			       ) argtype 
           from pg_proc p
           join pg_namespace as ns on ns.oid = p.pronamespace
           where nspname='public' and prokind in ('f')
 	         and p.oid not in (
 	            select d.objid
                from pg_depend d
                join pg_extension e on d.refobjid=e.oid
                and d.deptype='e'
                join pg_namespace s on s.oid=e.extnamespace
                and nspname='public')
          ) a
		     left outer join pg_type t
           on a.argtype =t.oid::text
         group by poid, proname
         ) b
    order by 1) loop
      raise notice '%', v_rec.stmt;
      execute v_rec.stmt;
  end loop;
 --move procedures
for v_rec in (
  select  $$ alter procedure "$$||proname||$$"($$||coalesce(args, '')||')set schema '||p_schema_name as stmt
    from (select 
            poid, 
            proname, 
            array_to_string(array_agg(typname), ',') as args
          from  
          (select 
             p.oid as poid, 
             proname, 
			       unnest(string_to_array (case proargtypes::text 
			                                when '' then '0'
			                                else 
			                                  proargtypes::text
			                                  end,  ' ')
			       ) argtype 
           from pg_proc p
           join pg_namespace as ns on ns.oid = p.pronamespace
           where nspname='public' and prokind in ('p')
 	         and p.oid not in (
 	            select d.objid
                from pg_depend d
                join pg_extension e on d.refobjid=e.oid
                and d.deptype='e'
                join pg_namespace s on s.oid=e.extnamespace
                and nspname='public')
          ) a
		     left outer join pg_type t
           on a.argtype =t.oid::text
         group by poid, proname
         ) b
    order by 1) loop
 raise notice '%', v_rec.stmt;
 execute v_rec.stmt;
end loop;
end;
$func$;

revoke execute on procedure pg_acm.public_to_private from public;