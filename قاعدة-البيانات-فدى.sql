-- ============================================================
-- نظام مناوبات الحافلات المدرسية – قاعدة بيانات Supabase
-- الدخول باسم مستخدم وكلمة مرور (بدون إيميل)
-- قاعدة بيانات مدرسة فدى الجاهزة: انسخ الملف كامل والصقه في SQL Editor ← New query ← Run
-- ============================================================

create schema if not exists extensions;
create extension if not exists pgcrypto with schema extensions;

-- تنظيف النسخة السابقة اللي كانت تعتمد على الإيميل
drop table if exists public.profiles cascade;
drop function if exists public.can_bootstrap();

-- ---------- المستخدمون والجلسات ----------
create table if not exists public.staff (
  id            uuid primary key default gen_random_uuid(),
  username      text not null,
  password_hash text not null,
  name          text,
  role          text not null default 'supervisor' check (role in ('admin', 'supervisor')),
  created_at    timestamptz not null default now()
);
create unique index if not exists staff_username_idx on public.staff (lower(username));

create table if not exists public.sessions (
  token      text primary key,
  staff_id   uuid not null references public.staff (id) on delete cascade,
  expires_at timestamptz not null
);

-- ---------- بيانات النظام ----------
create table if not exists public.settings (
  id   text primary key,
  data jsonb not null
);

create table if not exists public.drivers (
  id            text primary key,
  name          text not null,
  area          text,
  phone         text,
  phone2        text,
  bus_no        text,
  plate         text,
  capacity      text,
  license_exp   text,
  insurance_exp text,
  active        boolean not null default true,
  notes         text
);

create table if not exists public.duties (
  id          text primary key,
  type        text not null check (type in ('going', 'school')),
  date        text not null,
  driver_id   text,
  dest        text,
  note        text,
  done        boolean not null default false,
  reminded_at text
);
create index if not exists duties_date_idx on public.duties (date);

create table if not exists public.leaves (
  id        text primary key,
  driver_id text,
  date_from text,
  date_to   text,
  reason    text
);

create table if not exists public.log (
  id      text primary key,
  t       text,
  msg     text,
  by_name text
);
create index if not exists log_t_idx on public.log (t desc);

-- ---------- الجلسة الحالية (من ترويسة x-session يرسلها الموقع) ----------
create or replace function public.current_staff_id() returns uuid
language sql security definer stable set search_path = public as $$
  select s.staff_id from public.sessions s
  where s.token = nullif(current_setting('request.headers', true)::json ->> 'x-session', '')
    and s.expires_at > now();
$$;

create or replace function public.is_staff() returns boolean
language sql security definer stable set search_path = public as $$
  select public.current_staff_id() is not null;
$$;

create or replace function public.is_admin() returns boolean
language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.staff where id = public.current_staff_id() and role = 'admin');
$$;

create or replace function public.needs_setup() returns boolean
language sql security definer stable set search_path = public as $$
  select not exists (select 1 from public.staff where role = 'admin');
$$;

-- ---------- دوال الدخول وإدارة المستخدمين ----------
create or replace function public.new_session(p_staff uuid) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare t text := encode(gen_random_bytes(32), 'hex'); s public.staff;
begin
  delete from public.sessions where expires_at < now();
  insert into public.sessions (token, staff_id, expires_at) values (t, p_staff, now() + interval '30 days');
  select * into s from public.staff where id = p_staff;
  return json_build_object('token', t, 'id', s.id, 'name', s.name, 'username', s.username, 'role', s.role);
end $$;
revoke execute on function public.new_session(uuid) from public, anon, authenticated;

create or replace function public.app_login(p_username text, p_password text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare s public.staff;
begin
  select * into s from public.staff where lower(username) = lower(trim(p_username));
  if s.id is null or s.password_hash <> crypt(p_password, s.password_hash) then
    perform pg_sleep(0.5);
    return null;
  end if;
  return public.new_session(s.id);
end $$;

create or replace function public.app_me() returns json
language sql security definer stable set search_path = public as $$
  select json_build_object('id', id, 'name', name, 'username', username, 'role', role)
  from public.staff where id = public.current_staff_id();
$$;

create or replace function public.app_logout() returns void
language sql security definer set search_path = public as $$
  delete from public.sessions where token = nullif(current_setting('request.headers', true)::json ->> 'x-session', '');
$$;

-- الإعداد الأول: ينشئ المدير، ويعمل فقط إذا لم يوجد مدير
create or replace function public.app_setup(p_name text, p_username text, p_password text) returns json
language plpgsql security definer set search_path = public, extensions as $$
declare new_id uuid;
begin
  if not public.needs_setup() then raise exception 'already_setup'; end if;
  if length(trim(p_username)) < 3 then raise exception 'short_username'; end if;
  if length(p_password) < 6 then raise exception 'weak_password'; end if;
  insert into public.staff (username, password_hash, name, role)
  values (trim(p_username), crypt(p_password, gen_salt('bf')), p_name, 'admin') returning id into new_id;
  return public.new_session(new_id);
end $$;

create or replace function public.app_list_users() returns json
language plpgsql security definer stable set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'not_allowed'; end if;
  return coalesce((select json_agg(json_build_object('id', id, 'name', name, 'username', username, 'role', role) order by created_at)
                   from public.staff), '[]'::json);
end $$;

create or replace function public.app_add_user(p_name text, p_username text, p_password text, p_role text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.is_admin() then raise exception 'not_allowed'; end if;
  if length(trim(p_username)) < 3 then raise exception 'short_username'; end if;
  if length(p_password) < 6 then raise exception 'weak_password'; end if;
  if exists (select 1 from public.staff where lower(username) = lower(trim(p_username))) then raise exception 'username_taken'; end if;
  insert into public.staff (username, password_hash, name, role)
  values (trim(p_username), crypt(p_password, gen_salt('bf')), p_name, case when p_role = 'admin' then 'admin' else 'supervisor' end);
end $$;

create or replace function public.app_set_role(p_id uuid, p_role text) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'not_allowed'; end if;
  if p_id = public.current_staff_id() then raise exception 'not_allowed'; end if;
  update public.staff set role = case when p_role = 'admin' then 'admin' else 'supervisor' end where id = p_id;
end $$;

create or replace function public.app_remove_user(p_id uuid) returns void
language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'not_allowed'; end if;
  if p_id = public.current_staff_id() then raise exception 'not_allowed'; end if;
  delete from public.staff where id = p_id;
end $$;

-- المدير يعيّن كلمة مرور جديدة لأي مستخدم
create or replace function public.app_set_password(p_id uuid, p_password text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.is_admin() then raise exception 'not_allowed'; end if;
  if length(p_password) < 6 then raise exception 'weak_password'; end if;
  update public.staff set password_hash = crypt(p_password, gen_salt('bf')) where id = p_id;
  delete from public.sessions where staff_id = p_id;
end $$;

-- المستخدم يغيّر كلمة مروره
create or replace function public.app_change_password(p_password text) returns void
language plpgsql security definer set search_path = public, extensions as $$
begin
  if not public.is_staff() then raise exception 'not_allowed'; end if;
  if length(p_password) < 6 then raise exception 'weak_password'; end if;
  update public.staff set password_hash = crypt(p_password, gen_salt('bf')) where id = public.current_staff_id();
end $$;

-- ---------- تفعيل الحماية ----------
alter table public.staff    enable row level security;  -- بدون سياسات: لا يُقرأ إلا عبر الدوال
alter table public.sessions enable row level security;  -- بدون سياسات: لا يُقرأ إلا عبر الدوال
alter table public.settings enable row level security;
alter table public.drivers  enable row level security;
alter table public.duties   enable row level security;
alter table public.leaves   enable row level security;
alter table public.log      enable row level security;
revoke all on public.staff, public.sessions from anon, authenticated;

-- الإعدادات: يقرأها الجميع، ويعدّلها المدير
drop policy if exists settings_read  on public.settings;
drop policy if exists settings_write on public.settings;
create policy settings_read  on public.settings for select using (true);
create policy settings_write on public.settings for all using (public.is_admin()) with check (public.is_admin());

-- المناوبات: يقرأها الجميع، ويعدّلها المشرفون والمدير
drop policy if exists duties_read  on public.duties;
drop policy if exists duties_write on public.duties;
create policy duties_read  on public.duties for select using (true);
create policy duties_write on public.duties for all using (public.is_staff()) with check (public.is_staff());

-- السائقون والإجازات: للمشرفين والمدير فقط (فيها أرقام الهواتف)
drop policy if exists drivers_all on public.drivers;
drop policy if exists leaves_all  on public.leaves;
create policy drivers_all on public.drivers for all using (public.is_staff()) with check (public.is_staff());
create policy leaves_all  on public.leaves  for all using (public.is_staff()) with check (public.is_staff());

-- سجل العمليات
drop policy if exists log_read   on public.log;
drop policy if exists log_insert on public.log;
drop policy if exists log_delete on public.log;
create policy log_read   on public.log for select using (public.is_staff());
create policy log_insert on public.log for insert with check (public.is_staff());
create policy log_delete on public.log for delete using (public.is_admin());

-- ---------- عرض عام للسائقين بدون أرقام الهواتف ----------
create or replace view public.public_drivers as
  select id, name, area, bus_no, active from public.drivers;
grant select on public.public_drivers to anon, authenticated;

-- ---------- التحديث اللحظي للصفحة العامة ----------
do $$
declare t text;
begin
  foreach t in array array['settings', 'duties'] loop
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;

-- ============================================================
-- بيانات مدرسة فدى للتعليم الأساسي
-- حساب المدير تسويه من الموقع نفسه: افتح admin.html بعد التشغيل
-- ============================================================

-- إعدادات المدرسة (الاسم، الشعار، الوجهات، العطلة: الجمعة والسبت)
insert into public.settings (id, data) values ('main', '{"school": "مدرسة فدى للتعليم الأساسي", "logo": "data:image/jpeg;base64,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", "destinations": ["عبري", "ضنك", "ينقل"], "weekend": [5, 6], "goingPerDay": 1, "schoolPerDay": 1, "alertDays": 30}'::jsonb)
on conflict (id) do update set data = excluded.data;

-- السائقون (13 سائق)
insert into public.drivers (id, name, area, phone, phone2, active) values
  ('d01', 'حمد بن محمد الزيدي', 'المويزين', '99215963', null, true),
  ('d02', 'هلال بن محمد العلياني', 'وادي خوس', '92557731', null, true),
  ('d03', 'ناصر بن علي العلياني', 'خطو', '99592832', null, true),
  ('d04', 'عبدالله بن محمد الزيدي (المنجم)', 'مرتفعات فدى', '95600544', null, true),
  ('d05', 'أحمد بن حميد الزيدي', 'العمد', '96003072', null, true),
  ('d06', 'أسعد بن سعيد الزيدي', 'البرج', '96757096', '97733832', true),
  ('d07', 'راشد بن عبدالله العلوي', 'الجبل', '95069368', null, true),
  ('d08', 'عبدالله ذيبان', 'وادي خوس', '95311859', null, true),
  ('d09', 'سلطان بن سالم العلياني', 'الشعبة', '93336817', null, true),
  ('d10', 'راشد بن سيف العلياني', 'العمد', '92988500', null, true),
  ('d11', 'فهد بن عبدالله الزيدي (المنجم)', 'خطو', '92233883', null, true),
  ('d12', 'خميس بن سالم العلياني', 'الشعبة', '99347416', null, true),
  ('d13', 'عبدالله بن نصيب الزيدي', 'خطو', '91204709', null, true)
on conflict (id) do update set name = excluded.name, area = excluded.area, phone = excluded.phone, phone2 = excluded.phone2;
