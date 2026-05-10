
// --- konfigurimi ---
const SUPABASE_URL = 'https://xcfwnvhtqupshyideuko.supabase.co';
const SUPABASE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InhjZndudmh0cXVwc2h5aWRldWtvIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzgyNTA0MTYsImV4cCI6MjA5MzgyNjQxNn0.HTV63yGU4EH7QvubJFY52Vwv2s04z6-GVmKiD0DnRtM';
const supabaseClient = supabase.createClient(SUPABASE_URL, SUPABASE_KEY);

let userKeyPair = null;
let currentUser = null;
let currentPassword = null;

// --- BASE64 HELPERS ---
async function b64(buffer) {
    const blob = new Blob([buffer]);
    return new Promise((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve(reader.result.split(',')[1]);
        reader.readAsDataURL(blob);
    });
}

function d64(base64) {
    const binString = atob(base64);
    const len = binString.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) {
        bytes[i] = binString.charCodeAt(i);
    }
    return bytes.buffer;
}

// --- Authentikimi ---
async function handleAuth(type) {
    currentPassword = document.getElementById('password').value;
    const email = document.getElementById('email').value;
    
    if (!email || !currentPassword) return alert("Please fill in all fields.");

    const { data, error } = type === 'login' 
        ? await supabaseClient.auth.signInWithPassword({ email, password: currentPassword })
        : await supabaseClient.auth.signUp({ email, password: currentPassword });

    if (error) return alert(error.message);
    currentUser = data.user;
    showApp();
}

async function showApp() {
    document.getElementById('authSection').classList.add('hidden');
    document.getElementById('mainApp').classList.remove('hidden');
    
    // Explicitly check for the CURRENT user's identity only (Fixes the missing button issue)
    const { data, error } = await supabaseClient
        .from('user_identities')
        .select('*')
        .eq('user_id', currentUser.id) 
        .single();
    
    if (data) {
        await recoverIdentity(data);
    } else {
        document.getElementById('statusTitle').innerText = "Identity Setup Required";
        document.getElementById('setupKeys').classList.remove('hidden');
        document.getElementById('keysActive').classList.add('hidden'); 
    }
    
    refreshFiles();
    refreshSharedFiles();
    refreshSentFiles();
}

function logout() {
    supabaseClient.auth.signOut();
    location.reload();
}

// --- identity dhe key derivation ---
async function getMasterKey(password, salt) {
    const enc = new TextEncoder();
    const baseKey = await window.crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveKey"]);
    return window.crypto.subtle.deriveKey(
        { name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256" },
        baseKey, { name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]
    );
}

async function createNewIdentity() {
    try {
        userKeyPair = await window.crypto.subtle.generateKey(
            { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
            true, ["encrypt", "decrypt"]
        );

        const salt = window.crypto.getRandomValues(new Uint8Array(16));
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const masterKey = await getMasterKey(currentPassword, salt);
        
        const privateKeyRaw = await window.crypto.subtle.exportKey("jwk", userKeyPair.privateKey);
        const encryptedPrivKey = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv }, masterKey, new TextEncoder().encode(JSON.stringify(privateKeyRaw))
        );

        const publicKeyRaw = await window.crypto.subtle.exportKey("jwk", userKeyPair.publicKey);

        // Upload keys and check for database errors BEFORE updating UI
        const { error } = await supabaseClient.from('user_identities').insert([{
            user_id: currentUser.id,
            encrypted_priv_key: await b64(encryptedPrivKey),
            pub_key: JSON.stringify(publicKeyRaw),
            salt: await b64(salt),
            iv: await b64(iv)
        }]);

        if (error) {
            console.error("Database Error:", error);
            alert("Failed to save identity to the cloud: " + error.message + "\nDid you paste your real API key in script.js?");
            return; 
        }

        identityReady();
    } catch (err) {
        alert("Encryption Error: " + err.message);
    }
}
async function recoverIdentity(data) {
    try {
        const masterKey = await getMasterKey(currentPassword, d64(data.salt));
        const decryptedRaw = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: d64(data.iv) }, masterKey, d64(data.encrypted_priv_key)
        );
        
        const privJWK = JSON.parse(new TextDecoder().decode(decryptedRaw));
        userKeyPair = {
            privateKey: await window.crypto.subtle.importKey("jwk", privJWK, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]),
            publicKey: await window.crypto.subtle.importKey("jwk", JSON.parse(data.pub_key), { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"])
        };
        identityReady();
    } catch (e) {
        alert("Identity recovery failed. Password might be wrong.");
    }
}

function identityReady() {
    document.getElementById('statusTitle').innerText = "Identity Synchronized";
    document.getElementById('setupKeys').classList.add('hidden');
    document.getElementById('keysActive').classList.remove('hidden');
    document.getElementById('uploadBtn').disabled = false;
}

// --- File operations ---
async function encryptAndUpload() {
    const fileInput = document.getElementById('fileInput');
    const file = fileInput.files[0];
    if(!file) return;
    
    const status = document.getElementById('uploadStatus');
    status.innerText = "Encrypting...";

    try {
        const aesKey = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));
        const encryptedContent = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, await file.arrayBuffer());
        
        const rawAes = await window.crypto.subtle.exportKey("raw", aesKey);
        const wrappedKey = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, userKeyPair.publicKey, rawAes);

        status.innerText = "Uploading to cloud...";
        
        const { error } = await supabaseClient.from('vault_files').insert([{
            owner_id: currentUser.id,
            file_name: file.name,
            mime_type: file.type,
            encrypted_data: await b64(encryptedContent),
            wrapped_key: await b64(wrappedKey),
            iv: await b64(iv)
        }]);

        if (error) throw error;

        status.innerText = "Upload Complete!";
        fileInput.value = ""; 
        setTimeout(() => { status.innerText = ""; }, 3000); 
        
        await refreshFiles();
    } catch (err) {
        console.error("Upload failed:", err);
        status.innerText = "Error uploading file!";
        alert("Upload Error: " + err.message);
    }
}

async function refreshFiles() {
    try {
        const { data, error } = await supabaseClient
            .from('vault_files')
            .select('*')
            .eq('owner_id', currentUser.id)
            .order('id', { ascending: false }); 
            
        if (error) throw error;
        if (!data) return;
        
        const list = document.getElementById('fileList');
        if(data.length === 0) {
            list.innerHTML = "<p>No files uploaded yet.</p>";
        } else {
            list.innerHTML = data.map(f => `
                <div class="file-item">
                    <span>${f.file_name}</span>
                    <div style="display:flex; gap: 8px;">
                        <button style="width:auto; background:#10b981; padding: 6px 12px;" onclick="shareFile('${f.id}')">Share</button>
                        <button style="width:auto; background:#475569; padding: 6px 12px;" onclick="downloadFile('${f.id}')">Unlock</button>
                    </div>
                </div>
            `).join('');
        }
    } catch (err) {
        console.error("Failed to refresh files:", err);
