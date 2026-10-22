-- ============================================================
-- نظام مناوبات الحافلات المدرسية – قاعدة بيانات Supabase
-- انسخ هذا الملف كامل والصقه في: SQL Editor ← New query ← Run
-- ============================================================

-- ---------- الجداول ----------
create table if not exists public.profiles (
  id    uuid primary key references auth.users (id) on delete cascade,
  name  text,
  email text,
  role  text not null default 'supervisor' check (role in ('admin', 'supervisor'))
);

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

-- ---------- دوال الصلاحيات ----------
create or replace function public.is_staff() returns boolean
language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid());
$$;

create or replace function public.is_admin() returns boolean
language sql security definer stable set search_path = public as $$
  select exists (select 1 from public.profiles where id = auth.uid() and role = 'admin');
$$;

-- يسمح بإنشاء أول مدير فقط قبل إعداد النظام
create or replace function public.can_bootstrap() returns boolean
language sql security definer stable set search_path = public as $$
  select not exists (select 1 from public.profiles)
     and not exists (select 1 from public.settings where id = 'main');
$$;

-- ---------- تفعيل الحماية ----------
alter table public.profiles enable row level security;
alter table public.settings enable row level security;
alter table public.drivers  enable row level security;
alter table public.duties   enable row level security;
alter table public.leaves   enable row level security;
alter table public.log      enable row level security;

-- المستخدمون
drop policy if exists profiles_read   on public.profiles;
drop policy if exists profiles_insert on public.profiles;
drop policy if exists profiles_update on public.profiles;
drop policy if exists profiles_delete on public.profiles;
create policy profiles_read   on public.profiles for select using (id = auth.uid() or public.is_admin());
create policy profiles_insert on public.profiles for insert with check (
  public.is_admin() or (id = auth.uid() and role = 'admin' and public.can_bootstrap()));
create policy profiles_update on public.profiles for update using (public.is_admin()) with check (public.is_admin());
create policy profiles_delete on public.profiles for delete using (public.is_admin() and id <> auth.uid());

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

-- ---------- التحديث اللحظي ----------
do $$
declare t text;
begin
  foreach t in array array['settings', 'drivers', 'duties', 'leaves', 'log', 'profiles'] loop
    if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and schemaname = 'public' and tablename = t) then
      execute format('alter publication supabase_realtime add table public.%I', t);
    end if;
  end loop;
end $$;
