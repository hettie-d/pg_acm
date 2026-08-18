drop procedure if exists acm_tools.perm_reset_schema_owner(text, text, text);

drop procedure if exists acm_tools.perm_reset_schema_owner(text, text, text, text);

create or replace procedure acm_tools.perm_reset_schema_owner(p_schema_name text,
 p_owner text,
 p_prev_api text default null)
 language plpgsql 
 as
 $body$
 declare
 v_sql text;
 v_rec record;
 v_cnt int;
 v_prev_owner text;
 begin
 select count(*) into v_cnt from pg_authid where rolname=p_owner;
 if v_cnt=0 then --new user
   execute $$create role $$||p_owner;
 end if;
 select pg_get_userbyid(nspowner) into v_prev_owner from pg_namespace where nspname =p_schema_name;    
 v_sql:=$$ alter schema $$||p_schema_name||$$ owner to $$||p_owner ||$$;
    alter default privileges for user $$||v_prev_owner||$$ in schema $$||
       p_schema_name||$$
      revoke select, insert, update, delete,truncate on tables from  $$
     ||p_schema_name||$$_read_write;
    alter default privileges for user $$||v_prev_owner||$$ in schema $$||
      p_schema_name||$$ revoke select on tables from  $$
     ||p_schema_name||$$_read_only;
    alter default privileges for user $$||v_prev_owner||$$ in schema $$
    ||p_schema_name||$$ revoke usage on sequences from $$
     ||p_schema_name||$$_read_write;
      alter default privileges for user $$||p_owner||$$ in schema $$||
       p_schema_name||$$
      grant select, insert, update, delete,truncate on tables to  $$
     ||p_schema_name||$$_read_write;
    alter default privileges for user $$||p_owner||$$ in schema $$||
      p_schema_name||$$ grant select on tables to  $$
     ||p_schema_name||$$_read_only;
    alter default privileges  for user $$||p_owner||$$ in schema $$
    ||p_schema_name||$$ grant usage on sequences to $$
     ||p_schema_name||$$_read_write$$;
      raise notice '%', v_sql;
execute v_sql;
 for v_rec in (
 select  $$alter table $$||p_schema_name||$$."$$||tbl.relname||
    $$"  owner to $$||p_owner  ||$$;
    revoke all on table $$||p_schema_name||$$."$$||tbl.relname||
    $$" from $$||v_prev_owner||$$;$$||
   case when p_prev_api is not null then
   $$revoke all on table $$ ||p_schema_name||$$."$$||tbl.relname||
   $$" from $$||p_prev_api
   else $$ $$
  end
   as stmt
      from  pg_class as tbl
      join pg_namespace as ns on ns.oid = tbl.relnamespace
      where nspname=p_schema_name and relkind in ('r','p','m')
      order by 1)
  loop
    raise notice '%', v_rec.stmt;
    execute v_rec.stmt;
    end loop;

  for v_rec in (
  select  'alter sequence '||p_schema_name||$$."$$||tbl.relname||$$"  owner to $$||p_owner  ||$$;
    revoke all on sequence $$||p_schema_name||$$."$$||tbl.relname||$$" from $$||v_prev_owner||$$;$$||
   case when p_prev_api is not null then
   $$revoke all on sequence $$ ||p_schema_name||'.'||tbl.relname||
   $$ from $$||p_prev_api
   else ' '
  end
   as stmt
      from  pg_class as tbl
      join pg_namespace as ns on ns.oid = tbl.relnamespace
      where nspname=p_schema_name and relkind in ('S')
      order by 1)
  loop
  raise notice '%', v_rec.stmt;
  execute v_rec.stmt;
  end loop;
  
 for v_rec in (
 select  $$alter type $$||p_schema_name||$$."$$||tbl.relname||
    $$"  owner to $$||p_owner 
   as stmt
      from  pg_class as tbl
      join pg_namespace as ns on ns.oid = tbl.relnamespace
      where nspname=p_schema_name and relkind ='c'
      order by 1)
  loop
    raise notice '%', v_rec.stmt;
    execute v_rec.stmt;
    end loop;  
  
for v_rec in (
  select  'alter type '||p_schema_name||'.'||t.typname||
    $$  owner to $$||p_owner 
   as stmt
       from  pg_type as t
       join pg_namespace as ns on ns.oid = t.typnamespace
       where nspname=p_schema_name  and typcategory not in ('A', 'C')
      order by 1)
  loop
  raise notice '%', v_rec.stmt;
execute v_rec.stmt;
end loop;

for v_rec in (
  select  ' alter function '||p_schema_name||$$."$$||proname||$$"($$||coalesce(args, '')||') owner to '||p_owner as stmt
    from (select 
            poid, 
            proname, 
            array_to_string(array_agg(typname), ',') as args
          from pg_type t
          join 
          (select 
             p.oid as poid, 
             proname,  
             unnest (string_to_array (proargtypes::text,  ' ')) argtype 
           from pg_proc p
           join pg_namespace as ns on ns.oid = p.pronamespace
           where nspname=p_schema_name and prokind in ('f')
           ) a
         on a.argtype =t.oid::text
         group by poid, proname
         ) b
    order by 1
    ) loop
  raise notice '%', v_rec.stmt;
  execute v_rec.stmt;
end loop;

for v_rec in (
  select  'alter procedure '||p_schema_name||$$."$$||proname||$$"($$||coalesce(args, '')||') owner to '||p_owner as stmt
   from (select 
            poid, 
            proname, 
            array_to_string(array_agg(typname), ',') as args
          from pg_type t
          join 
          (select 
             p.oid as poid, 
             proname,  
             unnest (string_to_array (proargtypes::text,  ' ')) argtype 
           from pg_proc p
           join pg_namespace as ns on ns.oid = p.pronamespace
           where nspname=p_schema_name and prokind in ('p')
           ) a
         on a.argtype =t.oid::text
         group by poid, proname
         ) b
    order by 1
    ) loop
  raise notice '%', v_rec.stmt;
  execute v_rec.stmt;
end loop;

---revoke extra:
execute $$revoke all on schema  $$||p_schema_name||$$ from $$||v_prev_owner;
end;$body$;

revoke execute on procedure acm_tools.perm_reset_schema_owner from public;
