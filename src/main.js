const { invoke } = window.__TAURI__.tauri;

let master_key;
let enterMessageDisplay;
let createMessageDisplay;

window.addEventListener('DOMContentLoaded', () => {
    // Check which form exists on the current page
    const enterForm = document.getElementById('enter-form');
    const createForm = document.getElementById('create-form');
    const createVaultLink = document.getElementById("create-vault-link")
    enterMessageDisplay = document.getElementById('enter-form-message-display');
    createMessageDisplay = document.getElementById('create-form-message-display');

    createVaultLink.addEventListener('click', (event) => {
        event.preventDefault();
        navigateTo("create-vault-view");
    });

    enterForm.addEventListener('submit', (event) => {
        event.preventDefault();
        enterVault();
    });

    createForm.addEventListener('submit', (event) => {
        event.preventDefault();
        createVault();
    });

    navigateTo('enter-vault-view');

});

function navigateTo(viewId) {
    // Hide all views
    document.querySelectorAll('#app > div').forEach(view => {
        view.style.display = 'none';
    });

    // Show the selected view
    const selectedView = document.getElementById(viewId);
    if (selectedView) {
        selectedView.style.display = 'block';
    }
}

async function createVault(){
    master_key = document.getElementById('create-mkey-input').value.trim();
    try {
        const result = await invoke("initialize_app", { masterKey: master_key });
        createMessageDisplay.textContent = result;
        
        // Check if the vault was created successfully
        if (result === "Vault created successfully") {
            // Wait for a short time to allow the user to see the success message
            setTimeout(() => {
                // Redirect to enter-vault-view
                navigateTo('enter-vault-view');
            }, 2000); // 2000 milliseconds = 2 seconds
        }
    } catch (error) {
        createMessageDisplay.textContent = `Error: ${error}`;
    }
}

async function enterVault() {
    master_key = document.getElementById('enter-mkey-input').value.trim();
    try {
        const result = await invoke("login_hash_comparison", { masterKey: master_key });
        if (result === true) {
            enterMessageDisplay.textContent = "Login successful";
            // Add logic here for what happens after successful login
            setTimeout(() => {
                // Redirect to enter-vault-view
                navigateTo('main-vault-view');
            }, 2000); // 2000 milliseconds = 2 seconds
        } else {
            enterMessageDisplay.textContent = "Invalid master key";
        }
    } catch (error) {
        enterMessageDisplay.textContent = `Error: ${error}`;
    }
}

