document.addEventListener('DOMContentLoaded', () => {
    // DOM elements
    const websiteInput = document.getElementById('website');
    const lengthInput = document.getElementById('length');
    const passphraseInput = document.getElementById('passphrase');
    const disableLeakCheckInput = document.getElementById('disable-leak-check');
    const generateBtn = document.getElementById('generate-btn');
    const resultSection = document.getElementById('result');
    const passwordText = document.getElementById('password-text');
    const copyBtn = document.getElementById('copy-btn');
    const leakStatus = document.getElementById('leak-status');
    const resultWebsite = document.getElementById('result-website');
    const resultFilename = document.getElementById('result-filename');

    // Set default values
    lengthInput.value = 16;

    // Generate password
    generateBtn.addEventListener('click', async () => {
        // Validate inputs
        const website = websiteInput.value.trim();
        let length = parseInt(lengthInput.value);
        const passphrase = passphraseInput.value.trim();
        const disableLeakCheck = disableLeakCheckInput.checked;

        // Ensure length is within bounds
        if (isNaN(length) || length < 12) {
            length = 12;
            lengthInput.value = 12;
        } else if (length > 255) {
            length = 255;
            lengthInput.value = 255;
        }

        // Show loading state
        generateBtn.textContent = 'Generating...';
        generateBtn.disabled = true;

        try {
            // Make API request
            const response = await fetch('/api/generate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    website,
                    length,
                    passphrase,
                    disableLeakCheck
                })
            });

            if (!response.ok) {
                throw new Error('Failed to generate password');
            }

            const data = await response.json();

            // Update UI with results
            passwordText.textContent = data.password;
            resultWebsite.textContent = data.website || 'Not specified';
            resultFilename.textContent = data.fileName;

            // Update leak status
            if (disableLeakCheck) {
                leakStatus.classList.remove('leaked');
                leakStatus.querySelector('.status-icon').textContent = 'ℹ️';
                leakStatus.querySelector('.status-text').textContent = 'Leak check was disabled';
            } else if (data.isLeaked) {
                leakStatus.classList.add('leaked');
                leakStatus.querySelector('.status-icon').textContent = '✗';
                leakStatus.querySelector('.status-text').textContent = 'Found in data breaches! Consider a different password.';
            } else {
                leakStatus.classList.remove('leaked');
                leakStatus.querySelector('.status-icon').textContent = '✓';
                leakStatus.querySelector('.status-text').textContent = 'Not found in any data breaches';
            }

            // Show results
            resultSection.classList.remove('hidden');
        } catch (error) {
            console.error('Error generating password:', error);
            alert('Failed to generate password. Please try again.');
        } finally {
            // Reset button state
            generateBtn.textContent = 'Generate Password';
            generateBtn.disabled = false;
        }
    });

    // Copy password to clipboard
    copyBtn.addEventListener('click', () => {
        const password = passwordText.textContent;
        
        if (password) {
            navigator.clipboard.writeText(password)
                .then(() => {
                    // Show copied feedback
                    const originalText = copyBtn.textContent;
                    copyBtn.textContent = 'Copied!';
                    
                    setTimeout(() => {
                        copyBtn.textContent = originalText;
                    }, 2000);
                })
                .catch(err => {
                    console.error('Failed to copy password:', err);
                    alert('Failed to copy password. Please try manually selecting and copying.');
                });
        }
    });
}); 