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

  <img width="1919" height="914" alt="image" src="https://github.com/user-attachments/assets/b5bf0fb3-bcd5-4430-8bf4-c550070bce69" />

  <img width="1907" height="897" alt="image" src="https://github.com/user-attachments/assets/1cf72657-4c7b-4040-b83e-bcad72e86c34" />

  <img width="1527" height="714" alt="image" src="https://github.com/user-attachments/assets/94358e1c-c3cb-4007-b75d-49dc2d73b8ce" />




  
