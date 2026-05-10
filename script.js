// --- SHARING LOGIC ---
window.shareFile = async (fileId) => {
    let recipientEmail = prompt("Enter the email of the user to share with:");
    if (!recipientEmail) return;

    // Clean email input to prevent mismatches
    recipientEmail = recipientEmail.trim().toLowerCase(); 

    try {
        const { data: userData, error: rpcError } = await supabaseClient.rpc('get_pubkey_by_email', { search_email: recipientEmail });
        if (rpcError || !userData || userData.length === 0) throw new Error("User not found or hasn't setup their vault yet.");
        
        const recipientId = userData[0].user_id;
        const recipientPubKeyJwk = JSON.parse(userData[0].pub_key);

        const { data: fileData } = await supabaseClient.from('vault_files').select('wrapped_key').eq('id', fileId).single();

        const rawAes = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" }, 
            userKeyPair.privateKey, 
            d64(fileData.wrapped_key)
        );

        const recipientPubKey = await window.crypto.subtle.importKey(
            "jwk", recipientPubKeyJwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]
        );

        const newWrappedKey = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" }, recipientPubKey, rawAes
        );

        const { error: shareError } = await supabaseClient.from('shared_files').insert([{
            file_id: fileId,
            shared_by_user_id: currentUser.id,
            shared_with_user_id: recipientId,
            wrapped_key: await b64(newWrappedKey)
        }]);

        if (shareError) throw shareError;
        alert("File shared securely!");
        refreshSentFiles(); 

    } catch (err) {
        alert("Error sharing file: " + err.message);
        console.error(err);
    }
}

async function refreshSharedFiles() {
    const list = document.getElementById('sharedFileList');
    if (!list) return;

    const { data, error } = await supabaseClient
        .from('shared_files')
        .select(`
            id,
            wrapped_key,
            vault_files ( id, file_name, iv, encrypted_data )
        `)
        .eq('shared_with_user_id', currentUser.id); 
        
    if (!data || error) return;

    if(data.length === 0) list.innerHTML = "<p>No shared files.</p>";
    else {
        list.innerHTML = data.map(share => `
            <div class="file-item" style="border-left: 4px solid #10b981;">
                <span>${share.vault_files.file_name}</span>
                <button style="width:auto; background:#475569; padding: 6px 12px;" onclick="downloadSharedFile('${share.id}')">Unlock</button>
            </div>
        `).join('');
    }
}

async function refreshSentFiles() {
    const list = document.getElementById('sentFileList');
    if (!list) return;

    const { data, error } = await supabaseClient
        .from('shared_files')
        .select(`
            id,
            vault_files ( file_name )
        `)
        .eq('shared_by_user_id', currentUser.id); 
        
    if (!data || error) return;

    if(data.length === 0) {
        list.innerHTML = "<p>You haven't shared any files yet.</p>";
    } else {
        list.innerHTML = data.map(share => `
            <div class="file-item" style="border-left: 4px solid #6366f1;">
                <span>${share.vault_files.file_name}</span>
                <span style="font-size: 0.8rem; color: #94a3b8;">Sent</span>
            </div>
        `).join('');
    }
}

// --- DOWNLOADING ---
window.downloadFile = async (id) => {
    try {
        const { data } = await supabaseClient.from('vault_files').select('*').eq('id', id).single();
        const unwrapped = await window.crypto.subtle.decrypt({ name: "RSA-OAEP" }, userKeyPair.privateKey, d64(data.wrapped_key));
        const aesKey = await window.crypto.subtle.importKey("raw", unwrapped, "AES-GCM", true, ["decrypt"]);
        const dec = await window.crypto.subtle.decrypt({ name: "AES-GCM", iv: d64(data.iv) }, aesKey, d64(data.encrypted_data));
        
        triggerDownload(dec, data.file_name);
    } catch(e) {
        alert("Decryption failed.");
        console.error(e);
    }
}

window.downloadSharedFile = async (sharedId) => {
    try {
        const { data: shareData } = await supabaseClient.from('shared_files')
            .select('wrapped_key, vault_files (file_name, iv, encrypted_data)')
            .eq('id', sharedId).single();

        const fileInfo = shareData.vault_files;

        const unwrapped = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" }, userKeyPair.privateKey, d64(shareData.wrapped_key)
        );
        
        const aesKey = await window.crypto.subtle.importKey("raw", unwrapped, "AES-GCM", true, ["decrypt"]);
        
        const dec = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: d64(fileInfo.iv) }, aesKey, d64(fileInfo.encrypted_data)
        );
        
        triggerDownload(dec, "SHARED_" + fileInfo.file_name);
    } catch(e) {
        alert("Failed to decrypt shared file.");
        console.error(e);
    }
}

function triggerDownload(buffer, fileName) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([buffer]));
    a.download = fileName;
    a.click();
}