-- krijimi
create table vault_files (
  id uuid default gen_random_uuid() primary key,
  owner_id uuid references auth.users(id), -- Ben lidhjen e file me ni user specifik
  file_name text,
  mime_type text,
  encrypted_data text, -- Contenti i enkriptuar i file
  wrapped_key text,    -- AES key i enkriptuar me RSA public key
  iv text,             -- Vektori i inicializimiz per AES
  created_at timestamp with time zone default now()
);

-- Turn on Row Level Security (RLS)
alter table vault_files enable row level security;

-- Create a policy so users can only see their own files
create policy "Users can only access their own files" 
on vault_files for all 
using (auth.uid() = owner_id);

-- This creates the new identity table for password-syncing
create table user_identities (
  user_id uuid references auth.users(id) primary key,
  encrypted_priv_key text, 
  pub_key text,           
  salt text,              
  iv text                 
);

-- Turn on security
alter table user_identities enable row level security;

-- Allow users to manage their own key bundle
create policy "Users can manage own identity" on user_identities
  for all using (auth.uid() = user_id);
