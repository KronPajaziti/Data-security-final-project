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
    }
}
