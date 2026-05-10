
create table vault_files (
  id uuid default gen_random_uuid() primary key,
  owner_id uuid references auth.users(id), 
  file_name text,
  mime_type text,
  encrypted_data text,
  wrapped_key text,    
  iv text,             
  created_at timestamp with time zone default now()
);


alter table vault_files enable row level security;


create policy "Users can only access their own files" 
on vault_files for all 
using (auth.uid() = owner_id);


create table user_identities (
  user_id uuid references auth.users(id) primary key,
  encrypted_priv_key text, 
  pub_key text,           
  salt text,              
  iv text                 
);


alter table user_identities enable row level security;


create policy "Users can manage own identity" on user_identities
  for all using (auth.uid() = user_id);


create table shared_files (
    id uuid default gen_random_uuid() primary key,
    file_id uuid references vault_files(id) on delete cascade,
    shared_by_user_id uuid references auth.users(id),
    shared_with_user_id uuid references auth.users(id),
    wrapped_key text not null, 
    created_at timestamp with time zone default now(),
    unique(file_id, shared_with_user_id) 
);


alter table shared_files enable row level security;


create policy "Users can see files shared with them" 
    on shared_files for select using (auth.uid() = shared_with_user_id);

create policy "Owners can manage sharing" 
    on shared_files for all using (auth.uid() = shared_by_user_id);


create policy "Recipients can view shared file data" 
    on vault_files for select using (
        exists (
            select 1 from shared_files 
            where shared_files.file_id = vault_files.id 
            and shared_files.shared_with_user_id = auth.uid()
        )
    );


create or replace function get_pubkey_by_email(search_email text)
returns table(user_id uuid, pub_key text)
security definer
as $$
begin
  return query
  select u.id, ui.pub_key
  from auth.users u
  join user_identities ui on ui.user_id = u.id
  where u.email = search_email;
end;
$$ language plpgsql;

create or replace function get_pubkey_by_email(search_email text)
returns table(user_id uuid, pub_key text)
language plpgsql
security definer 
as $$
begin
  return query
  select u.id, i.pub_key
  from auth.users u
  join public.user_identities i on u.id = i.user_id
  where u.email = search_email;
end;
$$;

alter table public.user_identities enable row level security;
alter table public.vault_files enable row level security;
