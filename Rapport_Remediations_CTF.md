# Rapport de Remédiation - Vulnérabilités Identifiées

**Date:** 19 décembre 2025  
**Cible:** Machine vulnérable 192.168.0.116  
**Niveau de criticité:** CRITIQUE

---

## Synthèse Exécutive

L'audit de sécurité a révélé 4 vulnérabilités critiques exploitables sur l'application web permettant l'exfiltration de données sensibles (hashes de mots de passe, schémas de base de données) et l'injection de code malveillant. Ces failles nécessitent une correction immédiate avant toute mise en production.

## Vulnérabilités Identifiées

### 1. Injection SQL Union-Based (Search Image)

**Sévérité:** CRITIQUE (CVSS 9.8)  
**Impact:** Extraction complète de la base de données, lecture de fichiers système

#### Description Technique
La page "Search image" accepte directement les paramètres utilisateur dans les requêtes SQL sans validation ni échappement. L'attaquant peut extraire l'intégralité des données via des requêtes UNION SELECT.

#### Remédiations Obligatoires

**1. Utiliser des Requêtes Préparées (Prepared Statements)**

Les requêtes paramétrées empêchent l'interprétation du code SQL malveillant en séparant la structure de la requête des données.

```php
// ❌ Code vulnérable
$query = "SELECT id, title, url FROM list_images WHERE id = " . $_GET['id'];
$result = mysqli_query($conn, $query);

// ✅ Code sécurisé avec requête préparée
$stmt = $conn->prepare("SELECT id, title, url FROM list_images WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
$result = $stmt->get_result();
```

**2. Validation et Sanitisation des Entrées**

```php
// Validation stricte du type de données
$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
if ($id === false || $id < 1) {
    die("Invalid input");
}
```

**3. Principe du Moindre Privilège**

- Créer un utilisateur SQL dédié avec droits en lecture seule sur les tables nécessaires
- Révoquer les permissions sur `information_schema` et tables système
- Interdire l'exécution de requêtes multiples (multi-queries)

```sql
CREATE USER 'webapp_readonly'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT ON Member_images.list_images TO 'webapp_readonly'@'localhost';
REVOKE ALL ON information_schema.* FROM 'webapp_readonly'@'localhost';
```

**4. Désactiver les Messages d'Erreur Détaillés**

```php
// En production, masquer les erreurs SQL
mysqli_report(MYSQLI_REPORT_OFF);
ini_set('display_errors', 0);
```

---

### 2. Injection SQL Error-Based (Search Member)

**Sévérité:** CRITIQUE (CVSS 9.8)  
**Impact:** Extraction de données sensibles incluant des hashes de mots de passe

#### Description Technique
Identique à la vulnérabilité #1, avec extraction réussie de la table `users` contenant des données d'authentification.

#### Remédiations Spécifiques

**1. Hachage Sécurisé des Mots de Passe**

Les mots de passe étaient stockés en MD5, un algorithme obsolète et cassé.

```php
// ❌ MD5 est vulnérable aux attaques par rainbow tables
$hash = md5($password);

// ✅ Utiliser Argon2id (recommandation OWASP 2025)
$hash = password_hash($password, PASSWORD_ARGON2ID, [
    'memory_cost' => 65536,
    'time_cost' => 4,
    'threads' => 3
]);

// Vérification
if (password_verify($input_password, $hash)) {
    // Authentification réussie
}
```

**2. ORM (Object-Relational Mapping)**

Utiliser un framework qui gère automatiquement l'échappement:

```php
// Exemple avec Doctrine ORM
$user = $entityManager->getRepository(User::class)->find($_GET['id']);

// Exemple avec Laravel Eloquent
$user = User::where('id', $request->id)->first();
```

**3. WAF (Web Application Firewall)**

Déployer un WAF avec règles anti-injection SQL (ModSecurity Core Rule Set) en complément des corrections code.

---

### 3. XSS Reflected (Media Page)

**Sévérité:** HAUTE (CVSS 7.5)  
**Impact:** Vol de sessions, redirections malveillantes, phishing

#### Description Technique
Le paramètre `src` est directement injecté dans la balise `<object>` sans encodage, permettant l'exécution de JavaScript via data URIs.

#### Remédiations

**1. Encodage Contextuel des Sorties**

```php
// ❌ Code vulnérable
echo '<object data="' . $_GET['src'] . '"></object>';

// ✅ Encodage HTML
echo '<object data="' . htmlspecialchars($_GET['src'], ENT_QUOTES, 'UTF-8') . '"></object>';
```

**2. Content Security Policy (CSP)**

Implémenter une politique CSP stricte pour bloquer l'exécution de scripts inline:

```http
Content-Security-Policy: 
    default-src 'self'; 
    script-src 'self' 'nonce-{random}'; 
    object-src 'none'; 
    base-uri 'self'; 
    frame-ancestors 'none';
```

Configuration serveur Apache:

```apache
<IfModule mod_headers.c>
    Header always set Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'"
</IfModule>
```

**3. Validation de l'URL Source**

```php
// Whitelist des sources autorisées
$allowed_domains = ['youtube.com', 'vimeo.com', 'yourdomain.com'];
$parsed_url = parse_url($_GET['src']);

if (!in_array($parsed_url['host'], $allowed_domains)) {
    die("Source non autorisée");
}

// Interdire les data URIs
if (strpos($_GET['src'], 'data:') === 0) {
    die("Data URIs interdits");
}
```

**4. Headers de Sécurité**

```http
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
```

---

### 4. XSS Stored (Feedback Form)

**Sévérité:** CRITIQUE (CVSS 9.0)  
**Impact:** Compromission permanente de tous les utilisateurs consultant la page

#### Description Technique
Le filtre sur les balises `<script>` est contournable. Le XSS stocké est plus dangereux car il affecte tous les visiteurs de la page.

#### Remédiations

**1. Encodage des Données Stockées**

```php
// À l'enregistrement en base de données
$name = htmlspecialchars($_POST['name'], ENT_QUOTES, 'UTF-8');
$message = htmlspecialchars($_POST['message'], ENT_QUOTES, 'UTF-8');

// OU à l'affichage (préférable)
echo '<div class="comment">';
echo '<strong>' . htmlspecialchars($row['name'], ENT_QUOTES, 'UTF-8') . '</strong>';
echo '<p>' . htmlspecialchars($row['message'], ENT_QUOTES, 'UTF-8') . '</p>';
echo '</div>';
```

**2. Bibliothèque de Sanitisation Avancée**

```php
// Utiliser HTML Purifier pour du HTML riche sécurisé
require_once 'HTMLPurifier.auto.php';

$config = HTMLPurifier_Config::createDefault();
$purifier = new HTMLPurifier($config);

$clean_message = $purifier->purify($_POST['message']);
```

**3. CSP avec Nonces pour Scripts Dynamiques**

```php
// Générer un nonce unique par requête
$nonce = base64_encode(random_bytes(16));
header("Content-Security-Policy: script-src 'nonce-$nonce'");

// Dans le HTML
echo "<script nonce='$nonce'>/* code légitime */</script>";
```

**4. Protection CSRF**

Ajouter des tokens anti-CSRF pour empêcher la soumission malveillante de formulaires:

```php
// Génération du token
session_start();
$_SESSION['csrf_token'] = bin2hex(random_bytes(32));

// Dans le formulaire
echo '<input type="hidden" name="csrf_token" value="' . $_SESSION['csrf_token'] . '">';

// Validation
if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
    die("Token CSRF invalide");
}
```

---

## Plan d'Action Prioritaire

### Phase 1: Correctifs Immédiats (J+0 à J+3)

1. **Migration vers requêtes préparées** pour toutes les interactions SQL
2. **Activation de l'encodage HTML** sur toutes les sorties utilisateur
3. **Blocage d'urgence des data URIs** dans le paramètre media
4. **Désactivation des messages d'erreur détaillés** en production

### Phase 2: Durcissement (J+4 à J+14)

5. **Implémentation CSP** avec mode report-only puis enforcement
6. **Audit complet du code** avec SAST (Semgrep, SonarQube)
7. **Remplacement MD5** par Argon2id pour tous les hashes
8. **Configuration moindre privilège** pour les comptes SQL
9. **Ajout tokens CSRF** sur tous les formulaires

### Phase 3: Contrôles Continus (J+15+)

10. **Tests de pénétration automatisés** (OWASP ZAP, Burp Suite)
11. **WAF avec règles OWASP ModSecurity CRS**
12. **Formation équipe** aux pratiques OWASP Top 10 2025
13. **Bug bounty program** pour détection externe

---

## Outils de Vérification

### Tests Automatisés

```bash
# Scan SQLi avec sqlmap
sqlmap -u "http://192.168.0.116/?page=member&id=1" --batch --level=5

# Scan XSS avec XSStrike
python3 xsstrike.py -u "http://192.168.0.116/?page=media&src=test"

# Audit complet avec OWASP ZAP
zap-cli quick-scan -s all http://192.168.0.116
```

### Code Review Checklist

- [ ] Aucune concaténation directe dans les requêtes SQL
- [ ] Tous les outputs utilisent `htmlspecialchars()` ou équivalent
- [ ] Headers CSP configurés sur toutes les pages
- [ ] Validation stricte des types de données en entrée
- [ ] Pas de secrets hardcodés dans le code
- [ ] Logs ne contiennent pas de données sensibles
- [ ] Gestion d'erreurs sans stack traces en production

---

## Références et Standards

- OWASP Top 10 2025
- OWASP SQL Injection Prevention Cheat Sheet
- OWASP XSS Prevention Cheat Sheet
- CWE-89: Improper Neutralization of SQL Commands
- CWE-79: Cross-site Scripting (XSS)
- PCI-DSS 4.0 Requirement 6.5.1 (Injection flaws)

---

## Contact Support Sécurité

Pour toute question sur l'implémentation de ces remédiations:  
**Équipe Cybersécurité** - security@zeenergy.local
