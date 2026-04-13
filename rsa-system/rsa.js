/**
 * RSA System - Core Logic
 */

// Math Utilities
function isPrime(num) {
    if (num <= 1) return false;
    if (num <= 3) return true;
    if (num % 2 === 0 || num % 3 === 0) return false;
    for (let i = 5; i * i <= num; i += 6) {
        if (num % i === 0 || num % (i + 2) === 0) return false;
    }
    return true;
}

function gcd(a, b) {
    while (b !== 0) {
        let temp = b;
        b = a % b;
        a = temp;
    }
    return Math.abs(a);
}

function extendedGCD(a, b) {
    let old_r = a;
    let r = b;
    let old_s = 1;
    let s = 0;
    let old_t = 0;
    let t = 1;

    while (r !== 0) {
        let quotient = Math.floor(old_r / r);

        let temp_r = r;
        r = old_r - quotient * r;
        old_r = temp_r;

        let temp_s = s;
        s = old_s - quotient * s;
        old_s = temp_s;

        let temp_t = t;
        t = old_t - quotient * t;
        old_t = temp_t;
    }

    return [old_r, old_s, old_t];
}

function modInverse(e, phi) {
    const [g, x] = extendedGCD(e, phi);
    if (g !== 1) {
        throw new Error("Inverse does not exist, e and phi are not coprime");
    }
    // Ensures x is positive
    return (x % phi + phi) % phi;
}

function modPow(base, exp, mod) {
    let result = 1n;
    let b = BigInt(base) % BigInt(mod);
    let e = BigInt(exp);
    const m = BigInt(mod);

    while (e > 0n) {
        if (e % 2n === 1n) {
            result = (result * b) % m;
        }
        b = (b * b) % m;
        e = e / 2n;
    }
    return result;
}

function calculateRSA(p, q) {
    const n = p * q;
    const phi = (p - 1) * (q - 1);

    // Always prefer e = 3 as the starting candidate, walk up by 2s (odd only)
    let e = 3;
    while (e < phi) {
        if (gcd(e, phi) === 1) {
            break;
        }
        e += 2;
    }

    if (e >= phi) {
        throw new Error("Could not find a valid public exponent e. Try different primes.");
    }

    const d = modInverse(e, phi);

    return { n, phi, e, d };
}

function encrypt(text, e, n) {
    const ciphertext = [];
    for (let i = 0; i < text.length; i++) {
        const charCode = text.charCodeAt(i);
        if (charCode >= n) {
            throw new Error(
                `Character '${text[i]}' (ASCII ${charCode}) is mathematically larger than or equal to n (${n}). ` +
                `RSA modulo arithmetic requires n > character value. Please use larger primes!`
            );
        }
        ciphertext.push(modPow(charCode, e, n));
    }
    return ciphertext;
}

function decrypt(cipherArray, d, n) {
    let plaintext = "";
    for (let i = 0; i < cipherArray.length; i++) {
        const charCodeBigInt = modPow(cipherArray[i], d, n);
        const charCode = Number(charCodeBigInt);
        plaintext += String.fromCharCode(charCode);
    }
    return plaintext;
}

function factorN(n, e) {
    let p = null;
    let q = null;

    // Trial division up to sqrt(n)
    const limit = Math.floor(Math.sqrt(n));
    for (let i = 2; i <= limit; i++) {
        if (n % i === 0) {
            p = i;
            q = n / i;
            break;
        }
    }

    if (p !== null && q !== null) {
        const phi = (p - 1) * (q - 1);
        const d = modInverse(e, phi);
        return { p, q, phi, d };
    }

    throw new Error("Could not factor n");
}

function saveToFile(cipherArray, e, n) {
    const data = {
        ciphertext: cipherArray.map(c => c.toString()),
        publicKey: {
            e: e.toString(),
            n: n.toString()
        }
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'encrypted.json';
    a.click();
    URL.revokeObjectURL(url);
}

function loadFromFile(file) {
    const reader = new FileReader();
    reader.onload = (event) => {
        try {
            const parsed = JSON.parse(event.target.result);
            if (parsed.ciphertext && parsed.publicKey) {
                document.getElementById('ciphertext').value = parsed.ciphertext.join(' ');

                // Set the global public key context
                window.rsaKeys = {
                    e: Number(parsed.publicKey.e),
                    n: Number(parsed.publicKey.n)
                };

                // Populate the UI fields
                const valN   = document.getElementById('val-n');
                const valE   = document.getElementById('val-e');
                const valPhi = document.getElementById('val-phi');
                const valD   = document.getElementById('val-d');

                if (valN)   valN.textContent   = parsed.publicKey.n;
                if (valE)   valE.textContent   = parsed.publicKey.e;
                if (valPhi) valPhi.textContent = "? (Load from public key only)";
                if (valD)   valD.textContent   = "? (Unknown, pending crack)";

                alert(`Loaded encrypted JSON with Public Key:\ne = ${parsed.publicKey.e}\nn = ${parsed.publicKey.n}`);
            } else {
                document.getElementById('ciphertext').value = event.target.result;
            }
        } catch (err) {
            // Not JSON, assume raw space-separated text
            document.getElementById('ciphertext').value = event.target.result;
        }
    };
    reader.readAsText(file);
}

document.addEventListener('DOMContentLoaded', () => {
    // Buttons
    const btnCalcParams = document.getElementById('btn-calc-params');
    const btnEncrypt    = document.getElementById('btn-encrypt');
    const btnDecrypt    = document.getElementById('btn-decrypt');
    const btnSaveFile   = document.getElementById('btn-save-file');
    const btnLoadFile   = document.getElementById('btn-load-file');
    const fileInput     = document.getElementById('file-input');

    // Display elements
    const valN   = document.getElementById('val-n');
    const valPhi = document.getElementById('val-phi');
    const valE   = document.getElementById('val-e');
    const valD   = document.getElementById('val-d');

    // Calculate RSA parameters
    btnCalcParams.addEventListener('click', () => {
        const p = parseInt(document.getElementById('prime-p').value);
        const q = parseInt(document.getElementById('prime-q').value);

        if (isNaN(p) || isNaN(q)) {
            alert('Please enter valid prime numbers for p and q.');
            return;
        }

        if (!isPrime(p) || !isPrime(q)) {
            alert('Error: Both p and q MUST be valid prime numbers! RSA math will collapse otherwise.');
            return;
        }

        if (p === q) {
            alert('Error: p and q MUST be strictly distinct! If p = q, the Euler totient formula fails.');
            return;
        }

        try {
            const result = calculateRSA(p, q);

            // Store globally for encryption/decryption
            window.rsaKeys = result;

            valN.textContent   = result.n.toString();
            valPhi.textContent = result.phi.toString();
            valE.textContent   = result.e.toString();
            valD.textContent   = result.d.toString();
        } catch (error) {
            alert("Error calculating RSA params: " + error.message);
            return;
        }

        [valN, valPhi, valE, valD].forEach(el => el.style.color = '#10b981');
    });

    // Encrypt plaintext
    btnEncrypt.addEventListener('click', () => {
        const pText = document.getElementById('plaintext').value;
        if (!pText) return;

        if (!window.rsaKeys || !window.rsaKeys.e || !window.rsaKeys.n) {
            alert("Please calculate RSA parameters first!");
            return;
        }

        try {
            const encryptedArray = encrypt(pText, window.rsaKeys.e, window.rsaKeys.n);
            const outBox = document.getElementById('ciphertext-out');

            // Join the BigInt array with spaces to easily read/save to file
            outBox.textContent = encryptedArray.join(' ');
            outBox.style.color = '#10b981';
        } catch (error) {
            alert("Encryption error: " + error.message);
        }
    });

    // Decrypt ciphertext (cracks n via trial division, recomputes d)
    btnDecrypt.addEventListener('click', () => {
        const cText = document.getElementById('ciphertext').value;
        if (!cText) return;

        if (!window.rsaKeys || !window.rsaKeys.e || !window.rsaKeys.n) {
            alert("Missing Public Key (e, n). Please Calculate Params or Load a valid JSON file first!");
            return;
        }

        try {
            // 1) Use factorN to recover p, q and recompute d
            const factored = factorN(window.rsaKeys.n, window.rsaKeys.e);
            console.log("Factored keys:", factored);

            // 2) Parse space-separated string back to an array of BigInts
            const cipherArray = cText.trim().split(/\s+/).map(str => BigInt(str));

            // 3) Decrypt using the recomputed d
            const plaintext = decrypt(cipherArray, factored.d, window.rsaKeys.n);

            const outBox = document.getElementById('plaintext-out');
            outBox.textContent = plaintext;
            outBox.style.color = '#10b981';

            alert(
                `Decryption using factorN successful!\n` +
                `Found p=${factored.p}, q=${factored.q}\n` +
                `Recomputed private key d=${factored.d}`
            );
        } catch (error) {
            alert("Decryption/Factoring error. Details: " + error.message);
        }
    });

    // Save ciphertext to JSON file
    btnSaveFile.addEventListener('click', () => {
        const cText = document.getElementById('ciphertext-out').textContent;
        if (!cText || cText.includes('Not implemented') || cText.includes('will appear here')) {
            alert("No valid ciphertext to save.");
            return;
        }

        if (!window.rsaKeys || !window.rsaKeys.e || !window.rsaKeys.n) {
            alert("RSA keys missing. Please recalculate.");
            return;
        }

        const cipherArray = cText.trim().split(/\s+/).map(str => BigInt(str));
        saveToFile(cipherArray, window.rsaKeys.e, window.rsaKeys.n);
    });

    // Load ciphertext from JSON file
    btnLoadFile.addEventListener('click', () => {
        fileInput.click();
    });

    fileInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (!file) return;

        loadFromFile(file);

        // Clear value so the same file can be selected again
        event.target.value = "";
    });
});