/**
 * ============================================================
 * SYSTÈME RSA — Logique principale
 * ============================================================
 *
 * RSA (Rivest–Shamir–Adleman, 1977) est un algorithme de chiffrement
 * ASYMÉTRIQUE : il utilise deux clés distinctes (contrairement à AES
 * qui utilise la même clé pour chiffrer et déchiffrer).
 *
 * PRINCIPE MATHÉMATIQUE FONDAMENTAL :
 *   Il est facile de multiplier deux grands nombres premiers p et q,
 *   mais il est EXTRÊMEMENT difficile de retrouver p et q à partir de
 *   leur produit n = p×q. C'est ce "problème de factorisation" qui
 *   garantit la sécurité de RSA.
 *
 * DEUX CLÉS :
 *   → Clé publique  (e, n) : partagée avec tout le monde, sert à CHIFFRER
 *   → Clé privée    (d, n) : gardée secrète, sert à DÉCHIFFRER
 *
 * POURQUOI ASYMÉTRIQUE ?
 *   Alice peut publier sa clé publique. Bob chiffre un message avec.
 *   Seule Alice (qui possède d) peut le déchiffrer. Même Bob ne peut
 *   pas déchiffrer ce qu'il vient de chiffrer !
 */


// ============================================================
// UTILITAIRES MATHÉMATIQUES
// ============================================================

/**
 * isPrime(num) — Teste si un nombre est premier.
 *
 * POURQUOI EN AVOIR BESOIN ?
 *   RSA exige que p et q soient premiers. Si ce n'est pas le cas,
 *   la factorisation de n devient triviale et la clé privée d
 *   peut être retrouvée instantanément.
 *
 * COMMENT ÇA MARCHE ?
 *   Tout entier > 3 qui n'est pas premier s'écrit sous la forme 6k±1.
 *   On teste donc uniquement les diviseurs de cette forme jusqu'à √num.
 *   → Pourquoi √num ? Si num = a×b et a ≤ b, alors a ≤ √num.
 *     Inutile d'aller plus loin.
 *
 * COMPLEXITÉ : O(√n) — acceptable pour de petits nombres.
 *   Pour RSA réel (2048 bits), on utilise des tests probabilistes
 *   (Miller-Rabin) car tester jusqu'à √n serait impossible.
 */
function isPrime(num) {
    if (num <= 1) return false;
    if (num <= 3) return true;
    if (num % 2 === 0 || num % 3 === 0) return false;
    for (let i = 5; i * i <= num; i += 6) {
        if (num % i === 0 || num % (i + 2) === 0) return false;
    }
    return true;
}

/**
 * gcd(a, b) — Plus Grand Commun Diviseur (PGCD) par l'algorithme d'Euclide.
 *
 * POURQUOI EN AVOIR BESOIN ?
 *   Pour trouver e, on vérifie que pgcd(e, phi) = 1 (e et phi sont
 *   "premiers entre eux" / "coprimes"). Si leur PGCD vaut 1, il
 *   n'existe pas de facteur commun, ce qui garantit l'existence de
 *   l'inverse modulaire d = e⁻¹ mod phi (la clé privée).
 *
 * ALGORITHME D'EUCLIDE :
 *   pgcd(a, b) = pgcd(b, a mod b), jusqu'à ce que b = 0.
 *   Exemple : pgcd(48, 18) → pgcd(18,12) → pgcd(12,6) → pgcd(6,0) = 6
 */
function gcd(a, b) {
    while (b !== 0) {
        let temp = b;
        b = a % b;
        a = temp;
    }
    return Math.abs(a);
}

/**
 * extendedGCD(a, b) — Algorithme d'Euclide ÉTENDU.
 *
 * POURQUOI EN AVOIR BESOIN ?
 *   La version simple de gcd() nous donne juste le PGCD.
 *   La version étendue nous donne aussi x et y tels que :
 *     a×x + b×y = pgcd(a, b)
 *   C'est essentiel pour calculer l'inverse modulaire :
 *     si pgcd(e, phi) = 1, alors e×x ≡ 1 (mod phi)
 *     → x est l'inverse de e modulo phi, c'est-à-dire notre clé privée d !
 *
 * RETOURNE : [pgcd, x, y] où a×x + b×y = pgcd
 */
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

/**
 * modInverse(e, phi) — Inverse modulaire de e modulo phi.
 *
 * POURQUOI EN AVOIR BESOIN ?
 *   On cherche d tel que : e × d ≡ 1 (mod phi)
 *   Autrement dit : (e × d) divisé par phi laisse un reste de 1.
 *   → d est la clé privée RSA !
 *
 * LE RÉSULTAT x PEUT ÊTRE NÉGATIF :
 *   (x % phi + phi) % phi ramène toujours dans l'intervalle [0, phi-1].
 */
function modInverse(e, phi) {
    const [g, x] = extendedGCD(e, phi);
    if (g !== 1) {
        throw new Error("L'inverse n'existe pas : e et phi ne sont pas premiers entre eux");
    }
    return (x % phi + phi) % phi;
}

/**
 * modPow(base, exp, mod) — Exponentiation modulaire rapide.
 *
 * POURQUOI EN AVOIR BESOIN ?
 *   RSA repose sur des calculs du type : base^exp mod mod
 *   Ex : chiffrement → m^e mod n, déchiffrement → c^d mod n
 *
 * POURQUOI "RAPIDE" ?
 *   L'algorithme "square-and-multiply" le fait en O(log exp) opérations
 *   en exploitant la représentation binaire de exp.
 *
 * POURQUOI BigInt ?
 *   JavaScript représente les nombres en virgule flottante 64 bits
 *   (précision maximale : 2^53). RSA implique des valeurs bien plus grandes.
 *   BigInt garantit une arithmétique exacte sans aucune perte de précision.
 */
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


// ============================================================
// GÉNÉRATION DES CLÉS RSA
// ============================================================

/**
 * calculateRSA(p, q) — Génère l'ensemble des paramètres RSA.
 *
 * ÉTAPE 1 : n = p × q
 *   → "Module" public. Connu de tous.
 *
 * ÉTAPE 2 : phi = (p-1) × (q-1)
 *   → Indicatrice d'Euler φ(n). DOIT rester secret.
 *
 * ÉTAPE 3 : Choisir e (exposant public)
 *   → CORRECTION : e n'est plus fixé à 3.
 *   → On teste d'abord les candidats standards (3, 5, 17, 257, 65537)
 *     car ce sont des nombres premiers avec peu de bits à 1, donc rapides.
 *   → Si aucun candidat ne convient (pgcd(candidate, phi) ≠ 1),
 *     on balaie exhaustivement tous les impairs à partir de 3.
 *   → Exemple de cas où e=3 échoue : p=7, q=13 → phi=72 → pgcd(3,72)=3 ≠ 1.
 *     Dans ce cas on essaie 5 → pgcd(5,72)=1 ✓ → e=5.
 *
 * ÉTAPE 4 : d = e⁻¹ mod phi (exposant privé)
 *   → La clé privée ! Calculée via l'algorithme d'Euclide étendu.
 */
function calculateRSA(p, q) {
    const n = p * q;
    const phi = (p - 1) * (q - 1);

    // Candidats classiques testés en priorité (du plus petit au standard industriel).
    // Tous premiers → souvent coprimes avec phi. Valeur petite = chiffrement rapide.
    const candidates = [3, 5, 17, 257, 65537];
    let e = null;

    for (const candidate of candidates) {
        if (candidate < phi && gcd(candidate, phi) === 1) {
            e = candidate;
            break;
        }
    }

    // Fallback : balayage exhaustif des impairs si aucun candidat standard ne convient.
    // phi est toujours pair (car p, q > 2 sont impairs) → e pair invalide → on saute les pairs.
    if (e === null) {
        e = 3;
        while (e < phi) {
            if (gcd(e, phi) === 1) break;
            e += 2;
        }
        if (e >= phi) {
            throw new Error("Impossible de trouver un exposant public valide. Essayez d'autres nombres premiers.");
        }
    }

    const d = modInverse(e, phi);

    return { n, phi, e, d };
    // → (e, n) = clé publique à partager
    // → (d, n) = clé privée à garder secrète
    // → phi   = à détruire après génération
}


// ============================================================
// CHIFFREMENT / DÉCHIFFREMENT
// ============================================================

/**
 * encrypt(text, e, n) — Chiffre un texte caractère par caractère.
 *
 * FORMULE : c = m^e mod n
 *   → m = code ASCII du caractère (ex: 'A' = 65)
 *   → c = valeur chiffrée (un grand entier opaque)
 *
 * CONTRAINTE MATHÉMATIQUE : m < n
 *   L'arithmétique modulaire exige que le message soit strictement
 *   inférieur au module n. Sinon le chiffrement perd de l'information.
 *
 * RETOURNE : tableau de BigInt (un par caractère)
 */
function encrypt(text, e, n) {
    const ciphertext = [];
    for (let i = 0; i < text.length; i++) {
        const charCode = text.charCodeAt(i);

        if (charCode >= n) {
            throw new Error(
                `Le caractère '${text[i]}' (ASCII ${charCode}) est >= n (${n}). ` +
                `L'arithmétique RSA exige n > valeur du caractère. Utilisez de plus grands nombres premiers !`
            );
        }

        ciphertext.push(modPow(charCode, e, n));
    }
    return ciphertext;
}

/**
 * decrypt(cipherArray, d, n) — Déchiffre un tableau de valeurs chiffrées.
 *
 * FORMULE : m = c^d mod n
 *   → c = valeur chiffrée (BigInt reçu de encrypt)
 *   → d = clé privée (exposant secret)
 *   → m = code ASCII retrouvé → converti en caractère via fromCharCode
 *
 * POURQUOI ÇA MARCHE MATHÉMATIQUEMENT ?
 *   Par le théorème de Fermat/Euler : (m^e)^d ≡ m (mod n)
 *   Cette propriété est vraie UNIQUEMENT si e×d ≡ 1 (mod phi(n)).
 */
function decrypt(cipherArray, d, n) {
    let plaintext = "";
    for (let i = 0; i < cipherArray.length; i++) {
        const charCodeBigInt = modPow(cipherArray[i], d, n);
        const charCode = Number(charCodeBigInt);
        plaintext += String.fromCharCode(charCode);
    }
    return plaintext;
}


// ============================================================
// ATTAQUE PAR FACTORISATION (démonstratif)
// ============================================================

/**
 * factorN(n, e) — Casse RSA par factorisation brute de n.
 *
 * POURQUOI CETTE FONCTION EXISTE-T-ELLE ?
 *   Elle illustre l'attaque fondamentale contre RSA :
 *   si on peut factoriser n = p×q, on retrouve phi = (p-1)(q-1),
 *   puis d = e⁻¹ mod phi → clé privée retrouvée → déchiffrement possible.
 *
 * MÉTHODE : Division par essai jusqu'à √n
 *   → Complexité : O(√n) — faisable pour n < 10^12, impraticable pour n > 10^30.
 *
 * AVERTISSEMENT SÉCURITÉ :
 *   RSA 2048 bits → n ≈ 10^617. Impraticable à factoriser.
 *   Cette fonction est uniquement démonstrative avec de petits nombres.
 */
function factorN(n, e) {
    let p = null, q = null;

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

    throw new Error("Impossible de factoriser n");
}


// ============================================================
// GESTION DES FICHIERS
// ============================================================

/**
 * saveToFile(cipherArray, e, n) — Exporte le message chiffré en JSON.
 *
 * POURQUOI .toString() SUR LES BigInt ?
 *   JSON.stringify() ne sait pas sérialiser des BigInt nativement.
 *   On convertit donc chaque valeur en chaîne de chiffres décimaux.
 */
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

/**
 * loadFromFile(file) — Importe un fichier chiffré (JSON ou texte brut).
 *
 * DEUX CAS POSSIBLES :
 *   1. Fichier JSON valide produit par saveToFile :
 *      → Contient { ciphertext: [...], publicKey: { e, n } }
 *      → phi et d sont inconnus (non sauvegardés) → affichés comme "?"
 *
 *   2. Fichier texte brut (valeurs séparées par des espaces) :
 *      → Chargé directement dans le champ "ciphertext"
 */
function loadFromFile(file) {
    const reader = new FileReader();
    reader.onload = (event) => {
        try {
            const parsed = JSON.parse(event.target.result);

            if (parsed.ciphertext && parsed.publicKey) {
                document.getElementById('ciphertext').value = parsed.ciphertext.join(' ');

                window.rsaKeys = {
                    e: Number(parsed.publicKey.e),
                    n: Number(parsed.publicKey.n)
                };

                const valN   = document.getElementById('val-n');
                const valE   = document.getElementById('val-e');
                const valPhi = document.getElementById('val-phi');
                const valD   = document.getElementById('val-d');

                if (valN)   valN.textContent   = parsed.publicKey.n;
                if (valE)   valE.textContent   = parsed.publicKey.e;
                if (valPhi) valPhi.textContent = "? (chargé depuis clé publique uniquement)";
                if (valD)   valD.textContent   = "? (inconnu, en attente de factorisation)";

                alert(`Fichier JSON chargé avec succès !\nClé publique :\ne = ${parsed.publicKey.e}\nn = ${parsed.publicKey.n}`);
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
// INITIALISATION DE L'INTERFACE (DOM)
// ============================================================

/**
 * DOMContentLoaded — Point d'entrée de l'interface.
 *
 * POURQUOI ATTENDRE DOMContentLoaded ?
 *   Sans cet événement, getElementById() retournerait null pour tous
 *   les éléments car le script peut être chargé avant le HTML.
 */
document.addEventListener('DOMContentLoaded', () => {

    const btnCalcParams = document.getElementById('btn-calc-params');
    const btnEncrypt    = document.getElementById('btn-encrypt');
    const btnDecrypt    = document.getElementById('btn-decrypt');
    const btnSaveFile   = document.getElementById('btn-save-file');
    const btnLoadFile   = document.getElementById('btn-load-file');
    const fileInput     = document.getElementById('file-input');

    const valN   = document.getElementById('val-n');
    const valPhi = document.getElementById('val-phi');
    const valE   = document.getElementById('val-e');
    const valD   = document.getElementById('val-d');

    // ----------------------------------------------------------
    // BOUTON : Calculer les paramètres RSA
    //
    // VALIDATIONS DANS L'ORDRE :
    //   1. p et q sont des entiers valides
    //   2. p et q sont premiers
    //   3. p ≠ q
    // ----------------------------------------------------------
    btnCalcParams.addEventListener('click', () => {
        const p = parseInt(document.getElementById('prime-p').value);
        const q = parseInt(document.getElementById('prime-q').value);

        if (isNaN(p) || isNaN(q)) {
            alert('Veuillez entrer des nombres premiers valides pour p et q.');
            return;
        }

        if (!isPrime(p) || !isPrime(q)) {
            alert('Erreur : p et q doivent OBLIGATOIREMENT être des nombres premiers !');
            return;
        }

        if (p === q) {
            alert('Erreur : p et q doivent être STRICTEMENT différents !');
            return;
        }

        try {
            const result = calculateRSA(p, q);

            window.rsaKeys = result;

            valN.textContent   = result.n.toString();
            valPhi.textContent = result.phi.toString();
            valE.textContent   = result.e.toString();
            valD.textContent   = result.d.toString();
        } catch (error) {
            alert("Erreur lors du calcul des paramètres RSA : " + error.message);
            return;
        }

        [valN, valPhi, valE, valD].forEach(el => el.style.color = '#10b981');
    });

    // ----------------------------------------------------------
    // BOUTON : Chiffrer
    //
    // Applique encrypt() sur le texte clair avec la clé publique (e, n).
    // ----------------------------------------------------------
    btnEncrypt.addEventListener('click', () => {
        const pText = document.getElementById('plaintext').value;
        if (!pText) return;

        if (!window.rsaKeys || !window.rsaKeys.e || !window.rsaKeys.n) {
            alert("Veuillez d'abord calculer les paramètres RSA !");
            return;
        }

        try {
            const encryptedArray = encrypt(pText, window.rsaKeys.e, window.rsaKeys.n);
            const outBox = document.getElementById('ciphertext-out');

            outBox.textContent = encryptedArray.join(' ');
            outBox.style.color = '#10b981';
        } catch (error) {
            alert("Erreur de chiffrement : " + error.message);
        }
    });

    // ----------------------------------------------------------
    // BOUTON : Déchiffrer
    //
    // Retrouve d par factorisation de n, puis déchiffre le tableau.
    //
    // FLUX :
    //   1. factorN(n, e)         → retrouve p, q, phi, d
    //   2. split + BigInt(str)   → parse les valeurs chiffrées
    //   3. decrypt(array, d, n)  → reconstruit le texte clair
    // ----------------------------------------------------------
    btnDecrypt.addEventListener('click', () => {
        const cText = document.getElementById('ciphertext').value;
        if (!cText) return;

        if (!window.rsaKeys || !window.rsaKeys.e || !window.rsaKeys.n) {
            alert("Clé publique (e, n) manquante. Calculez les paramètres ou chargez un fichier JSON valide !");
            return;
        }

        try {
            const factored = factorN(window.rsaKeys.n, window.rsaKeys.e);
            console.log("Clés retrouvées par factorisation :", factored);

            const cipherArray = cText.trim().split(/\s+/).map(str => BigInt(str));

            const plaintext = decrypt(cipherArray, factored.d, window.rsaKeys.n);

            const outBox = document.getElementById('plaintext-out');
            outBox.textContent = plaintext;
            outBox.style.color = '#10b981';

            alert(
                `Déchiffrement réussi par factorisation !\n` +
                `Facteurs trouvés : p=${factored.p}, q=${factored.q}\n` +
                `Clé privée recalculée : d=${factored.d}`
            );
        } catch (error) {
            alert("Erreur de déchiffrement/factorisation : " + error.message);
        }
    });

    // ----------------------------------------------------------
    // BOUTON : Sauvegarder dans un fichier JSON
    //
    // NOTE : La clé PRIVÉE (d) n'est jamais sauvegardée dans le fichier.
    // ----------------------------------------------------------
    btnSaveFile.addEventListener('click', () => {
        const cText = document.getElementById('ciphertext-out').textContent;

        if (!cText || cText.includes('Not implemented') || cText.includes('will appear here')) {
            alert("Aucun texte chiffré valide à sauvegarder.");
            return;
        }

        if (!window.rsaKeys || !window.rsaKeys.e || !window.rsaKeys.n) {
            alert("Clés RSA manquantes. Veuillez recalculer les paramètres.");
            return;
        }

        const cipherArray = cText.trim().split(/\s+/).map(str => BigInt(str));
        saveToFile(cipherArray, window.rsaKeys.e, window.rsaKeys.n);
    });

    // ----------------------------------------------------------
    // BOUTON : Charger un fichier chiffré
    //
    // POURQUOI fileInput.click() ?
    //   Pour des raisons de sécurité, le navigateur n'autorise l'ouverture
    //   de la boîte de dialogue fichier QUE depuis un clic utilisateur.
    // ----------------------------------------------------------
    btnLoadFile.addEventListener('click', () => {
        fileInput.click();
    });

    fileInput.addEventListener('change', (event) => {
        const file = event.target.files[0];
        if (!file) return;

        loadFromFile(file);

        // Réinitialisation : sans ça, re-sélectionner le même fichier
        // ne déclencherait pas l'événement 'change'.
        event.target.value = "";
    });
});