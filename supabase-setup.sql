-- =====================================================================
--  LE PETIT BOOTH — Configuration Supabase (à exécuter UNE fois)
--  Ouvrez Supabase → SQL Editor → collez TOUT ce script → RUN.
--  Sécurité : les tables ne sont jamais lues directement par le public.
--  Tout passe par des fonctions contrôlées (mot de passe admin / token).
-- =====================================================================

-- 1) TABLES ------------------------------------------------------------
create table if not exists public.clients (
  id         text primary key,
  token      text unique not null,
  payload    jsonb not null,
  updated_at timestamptz not null default now()
);

create table if not exists public.prestataires (
  id         text primary key,
  token      text unique not null,
  payload    jsonb not null,
  updated_at timestamptz not null default now()
);

-- 2) SÉCURITÉ : on active RLS SANS policy => accès direct interdit.
--    (Seules les fonctions ci-dessous, en SECURITY DEFINER, accèdent aux tables.)
alter table public.clients      enable row level security;
alter table public.prestataires enable row level security;

-- 3) MOT DE PASSE ADMINISTRATEUR  ⬇️ CHANGEZ-LE ICI (une seule ligne) ---
create or replace function public._admin_pw()
returns text language sql immutable
set search_path = public
as $$ select 'KevinObscur974'::text $$;
revoke all on function public._admin_pw() from public;
-- (personne ne peut lire ce mot de passe ; seules les fonctions internes l'utilisent)

-- 4) LECTURE ADMIN (toutes les données) --------------------------------
create or replace function public.admin_data(p_pw text)
returns jsonb language plpgsql security definer stable
set search_path = public
as $$
begin
  if p_pw is distinct from public._admin_pw() then
    raise exception 'unauthorized';
  end if;
  return jsonb_build_object(
    'clients',      coalesce((select jsonb_agg(payload order by updated_at) from public.clients), '[]'::jsonb),
    'prestataires', coalesce((select jsonb_agg(payload order by updated_at) from public.prestataires), '[]'::jsonb)
  );
end $$;

-- 5) ENREGISTREMENT (upsert) ADMIN -------------------------------------
create or replace function public.admin_save(p_pw text, p_kind text, p_id text, p_token text, p_payload jsonb)
returns void language plpgsql security definer
set search_path = public
as $$
begin
  if p_pw is distinct from public._admin_pw() then raise exception 'unauthorized'; end if;
  if p_kind = 'client' then
    insert into public.clients(id, token, payload, updated_at)
      values (p_id, p_token, p_payload, now())
      on conflict (id) do update set token=excluded.token, payload=excluded.payload, updated_at=now();
  elsif p_kind = 'prestataire' then
    insert into public.prestataires(id, token, payload, updated_at)
      values (p_id, p_token, p_payload, now())
      on conflict (id) do update set token=excluded.token, payload=excluded.payload, updated_at=now();
  else
    raise exception 'bad kind';
  end if;
end $$;

-- 6) SUPPRESSION ADMIN -------------------------------------------------
create or replace function public.admin_delete(p_pw text, p_kind text, p_id text)
returns void language plpgsql security definer
set search_path = public
as $$
begin
  if p_pw is distinct from public._admin_pw() then raise exception 'unauthorized'; end if;
  if p_kind = 'client'       then delete from public.clients      where id = p_id;
  elsif p_kind = 'prestataire' then delete from public.prestataires where id = p_id;
  else raise exception 'bad kind';
  end if;
end $$;

-- 7) LECTURE PUBLIQUE PAR LIEN — CLIENT --------------------------------
create or replace function public.client_by_token(p_token text)
returns jsonb language sql security definer stable
set search_path = public
as $$ select payload from public.clients where token = p_token limit 1 $$;

-- 8) LECTURE PUBLIQUE PAR LIEN — PRESTATAIRE
--    Renvoie SES missions, avec SES horaires et SA rémunération.
--    NE renvoie JAMAIS le prix client, les options, ni la formule.
create or replace function public.prestataire_by_token(p_token text)
returns jsonb language plpgsql security definer stable
set search_path = public
as $$
declare pr jsonb; missions jsonb;
begin
  select payload into pr from public.prestataires where token = p_token limit 1;
  if pr is null then return null; end if;
  select coalesce(jsonb_agg(m order by m->>'datePrestation'), '[]'::jsonb) into missions
  from (
    select jsonb_build_object(
      'prenom',        c.payload->>'prenom',
      'nom',           c.payload->>'nom',
      'telephone',     c.payload->>'telephone',
      'typeEvenement', c.payload->>'typeEvenement',
      'datePrestation',c.payload->>'datePrestation',
      'adresse',       c.payload->>'adresse',
      'lieu',          c.payload->>'lieu',
      'notes',         c.payload->>'notes',
      'status',        c.payload->>'status',
      'heureDebut',    coalesce(nullif(asg.a->>'heureDebut',''), c.payload->>'heureDebut'),
      'heureFin',      coalesce(nullif(asg.a->>'heureFin',''),   c.payload->>'heureFin'),
      'montant',       coalesce(asg.a->>'montant','0')     -- rémunération versée à CE prestataire
    ) as m
    from public.clients c
    left join lateral (
      select el.value as a
      from jsonb_array_elements(coalesce(c.payload->'assignments','[]'::jsonb)) el
      where el.value->>'nom' = pr->>'nom'
      limit 1
    ) asg on true
    where (c.payload->>'prestataire' = pr->>'nom') or (asg.a is not null)
  ) sub;
  return jsonb_build_object('prestataire', pr, 'missions', missions);
end $$;

-- 9) DROITS D'EXÉCUTION -------------------------------------------------
grant execute on function public.admin_data(text)                          to anon, authenticated;
grant execute on function public.admin_save(text,text,text,text,jsonb)     to anon, authenticated;
grant execute on function public.admin_delete(text,text,text)              to anon, authenticated;
grant execute on function public.client_by_token(text)                     to anon, authenticated;
grant execute on function public.prestataire_by_token(text)                to anon, authenticated;

-- Terminé. Revenez dans l'application, renseignez SUPABASE_URL et
-- SUPABASE_ANON_KEY, rechargez : le bandeau passe au vert.
