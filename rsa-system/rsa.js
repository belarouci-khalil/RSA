// ============================================================
// VARIABLES GLOBALES — initialisées à null au départ
// Remplies uniquement quand Alice choisit p et q
// ============================================================

let n   = null;
let phi = null;
let e   = null;
let d   = null;


// ============================================================
// UTILITAIRES MATHÉMATIQUES
// ============================================================

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
    let old_r = a, r = b;
    let old_s = 1, s = 0;
    let old_t = 0, t = 1;

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

function modInverse(a, m) {
    const [g, x] = extendedGCD(a, m);
    if (g !== 1) {
        throw new Error("L'inverse n'existe pas");
    }
    return (x % m + m) % m;
}

function modPow(base, exp, mod) {
    let result = 1n;
    let b = BigInt(base) % BigInt(mod);
    let ex = BigInt(exp);
    const m = BigInt(mod);

    while (ex > 0n) {
        if (ex % 2n === 1n) {
            result = (result * b) % m;
        }
        b = (b * b) % m;
        ex = ex / 2n;
    }
    return result;
}


// ============================================================
// CHIFFREMENT / DÉCHIFFREMENT
// ============================================================

function encrypt(text) {
    const ciphertext = [];
    for (let i = 0; i < text.length; i++) {
        const charCode = text.charCodeAt(i);
        if (charCode >= n) {
            throw new Error(
                `Le caractère '${text[i]}' (ASCII ${charCode}) est >= n (${n}). Utilisez de plus grands nombres premiers !`
            );
        }
        ciphertext.push(modPow(charCode, e, n));
    }
    return ciphertext;
}

function decrypt(cipherArray) {
    let plaintext = "";
    for (let i = 0; i < cipherArray.length; i++) {
        const charCodeBigInt = modPow(cipherArray[i], d, n);
        plaintext += String.fromCharCode(Number(charCodeBigInt));
    }
    return plaintext;
}


// ============================================================
// GESTION DES FICHIERS
// ============================================================

function saveToFile(cipherArray) {
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
                // On met le ciphertext dans le champ — c'est tout
                document.getElementById('ciphertext').value = parsed.ciphertext.join(' ');

                // Affichage informatif seulement, on ne touche PAS les variables globales
                document.getElementById('val-n').textContent   = parsed.publicKey.n;
                document.getElementById('val-e').textContent   = parsed.publicKey.e;
                document.getElementById('val-phi').textContent = "? (non disponible)";
                document.getElementById('val-d').textContent   = "? (non disponible)";

                alert(
                    "Fichier chargé !\n\n" +
                    "⚠️ Pour déchiffrer, vous devez avoir calculé les clés dans cette session."
                );
            } else {
                document.getElementById('ciphertext').value = event.target.result;
            }
        } catch (err) {
            document.getElementById('ciphertext').value = event.target.result;
        }
    };
    reader.readAsText(file);
}


// ============================================================
// INTERFACE — BOUTONS
// ============================================================

document.addEventListener('DOMContentLoaded', () => {

    // ----------------------------------------------------------
    // BOUTON : Calculer les paramètres RSA
    // C'est ICI que les variables globales sont remplies
    // ----------------------------------------------------------
    document.getElementById('btn-calc-params').addEventListener('click', () => {
        const p = parseInt(document.getElementById('prime-p').value);
        const q = parseInt(document.getElementById('prime-q').value);

        if (isNaN(p) || isNaN(q)) {
            alert('Veuillez entrer des nombres valides pour p et q.');
            return;
        }
        if (!isPrime(p) || !isPrime(q)) {
            alert('Erreur : p et q doivent être des nombres premiers !');
            return;
        }
        if (p === q) {
            alert('Erreur : p et q doivent être différents !');
            return;
        }

        // Calcul et stockage dans les variables globales
        n   = p * q;
        phi = (p - 1) * (q - 1);

        // Chercher e coprime avec phi
        e = null;
        for (const candidate of [3, 5, 17, 257, 65537]) {
            if (candidate < phi && gcd(candidate, phi) === 1) {
                e = candidate;
                break;
            }
        }
        if (e === null) {
            let candidat = 3;
            while (candidat < phi) {
                if (gcd(candidat, phi) === 1) { e = candidat; break; }
                candidat += 2;
            }
        }
        if (e === null) {
            alert("Impossible de trouver e. Essayez d'autres nombres premiers.");
            return;
        }

        d = modInverse(e, phi);

        // Affichage
        document.getElementById('val-n').textContent   = n;
        document.getElementById('val-phi').textContent = phi;
        document.getElementById('val-e').textContent   = e;
        document.getElementById('val-d').textContent   = d;

        ['val-n', 'val-phi', 'val-e', 'val-d'].forEach(id => {
            document.getElementById(id).style.color = '#10b981';
        });
    });

    // ----------------------------------------------------------
    // BOUTON : Chiffrer
    // Utilise les variables globales e et n
    // ----------------------------------------------------------
    document.getElementById('btn-encrypt').addEventListener('click', () => {
        const texte = document.getElementById('plaintext').value;
        if (!texte) return;

        if (e === null || n === null) {
            alert("Veuillez d'abord calculer les paramètres RSA !");
            return;
        }

        try {
            const encryptedArray = encrypt(texte);
            const outBox = document.getElementById('ciphertext-out');
            outBox.textContent = encryptedArray.join(' ');
            outBox.style.color = '#10b981';
        } catch (error) {
            alert("Erreur de chiffrement : " + error.message);
        }
    });

    // ----------------------------------------------------------
    // BOUTON : Déchiffrer
    // Utilise la variable globale d — si elle est null, on refuse
    // ----------------------------------------------------------
    document.getElementById('btn-decrypt').addEventListener('click', () => {
        const cText = document.getElementById('ciphertext').value;
        if (!cText) return;

        // Si d est null c'est que les clés n'ont pas été calculées dans cette session
        if (d === null) {
            alert(
                "Clé privée (d) introuvable !\n\n" +
                "Vous devez choisir p et q dans cette session pour calculer d.\n" +
                "Si vous avez rafraîchi la page, d a été perdu — c'est normal."
            );
            return;
        }

        try {
            const cipherArray = cText.trim().split(/\s+/).map(str => BigInt(str));
            const plaintext = decrypt(cipherArray);

            const outBox = document.getElementById('plaintext-out');
            outBox.textContent = plaintext;
            outBox.style.color = '#10b981';
        } catch (error) {
            alert("Erreur de déchiffrement : " + error.message);
        }
    });

    // ----------------------------------------------------------
    // BOUTON : Sauvegarder
    // ----------------------------------------------------------
    document.getElementById('btn-save-file').addEventListener('click', () => {
        const cText = document.getElementById('ciphertext-out').textContent;

        if (!cText || cText.includes('will appear here')) {
            alert("Aucun texte chiffré à sauvegarder.");
            return;
        }
        if (e === null || n === null) {
            alert("Clés manquantes. Veuillez calculer les paramètres.");
            return;
        }

        const cipherArray = cText.trim().split(/\s+/).map(str => BigInt(str));
        saveToFile(cipherArray);
    });

    // ----------------------------------------------------------
    // BOUTON : Charger un fichier
    // ----------------------------------------------------------
    document.getElementById('btn-load-file').addEventListener('click', () => {
        document.getElementById('file-input').click();
    });

    document.getElementById('file-input').addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (!file) return;
        loadFromFile(file);
        event.target.value = "";
    });

});