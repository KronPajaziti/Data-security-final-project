identityReady(); 
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
    const file = document.getElementById('fileInput').files[0];
    if(!file) return;
    
    const status = document.getElementById('uploadStatus');
    status.innerText = "Encrypting...";

    const aesKey = await window.crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const encryptedContent = await window.crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, await file.arrayBuffer());
    
    const rawAes = await window.crypto.subtle.exportKey("raw", aesKey);
    const wrappedKey = await window.crypto.subtle.encrypt({ name: "RSA-OAEP" }, userKeyPair.publicKey, rawAes);

    status.innerText = "Uploading to cloud...";
    await supabaseClient.from('vault_files').insert([{
        owner_id: currentUser.id,
        file_name: file.name,
        mime_type: file.type,
        encrypted_data: await b64(encryptedContent),
        wrapped_key: await b64(wrappedKey),
        iv: await b64(iv)
    }]);

    status.innerText = "Done!";
    refreshFiles();
}

async function refreshFiles() {
    const { data } = await supabaseClient.from('vault_files').select('*');
    if (!data) return;
    
    const list = document.getElementById('fileList');
    list.innerHTML = data.map(f => `
        <div class="file-item">
            <span>${f.file_name}</span>
            <button style="width:auto; background:#475569" onclick="downloadFile('${f.id}')">Unlock</button>
        </div>
    `).join('');
}

window.downloadFile = async (id) => {
    const { data } = await supabaseClient.from('vault_files').select('*').eq('id', id).single();
    const unwrapped = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, userKeyPair.privateKey, d64(data.wrapped_key));
    const aesKey = await window.crypto.subtle.importKey("raw", unwrapped, "AES-GCM", true, ["decrypt"]);
    const dec = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: d64(data.iv) }, aesKey, d64(data.encrypted_data));
    
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([dec]));
    a.download = "DECRYPTED_" + data.file_name;
    a.click();
}

