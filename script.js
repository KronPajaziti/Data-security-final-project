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
