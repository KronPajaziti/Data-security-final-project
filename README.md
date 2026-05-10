# Data-security-final-project

# SecuraVault - E2EE Cloud Storage

A zero-knowledge file vault using **AES-GCM** and **RSA-OAEP** encryption.

## Database Structure
The backend is powered by **Supabase**. You can find the table definitions in `schema.sql`.

### Tables:
- **user_identities**: Stores encrypted RSA private keys (PBKDF2 derived).
- **vault_files**: Stores encrypted file data and wrapped AES keys.

## Security Features
- **End-to-End Encryption**: Files are encrypted in the browser.
- **Zero-Knowledge**: The server never sees the user's password or unencrypted keys.
- **Identity Sync**: RSA keys are recovered using the login password.

  **IN ORDER FOR THE PROJECT TO WORK YOU HAVE TO USE YOUR OWN KEYS FOR THE DATABASE**
 ### If you want to try the project use this link:
- https://data-security-univeristy-of-pristina.netlify.app/

  
  




  
