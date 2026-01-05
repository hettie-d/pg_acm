create or replace function pg_acm.check_stack(p_outer_function text)
returns boolean
as $func$
declare
 v_stack text;
begin
 get diagnostics v_stack = pg_context;
 return  (position (p_outer_function in v_stack)>0);
end;
$func$ language plpgsql security definer;
revoke execute on function pg_acm.check_stack from public;
