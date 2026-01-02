# Rules Reference

Complete reference for all security rules in Zecurx CodeGuard.

## Overview

| Rule ID                   | Name                         | Severity | CWE      |
| ------------------------- | ---------------------------- | -------- | -------- |
| [ZCG-JS-001](#zcg-js-001) | dangerous-eval               | High     | CWE-95   |
| [ZCG-JS-002](#zcg-js-002) | dynamic-function-constructor | High     | CWE-95   |
| [ZCG-JS-003](#zcg-js-003) | command-injection            | High     | CWE-78   |
| [ZCG-JS-004](#zcg-js-004) | hardcoded-secrets            | High     | CWE-798  |
| [ZCG-JS-005](#zcg-js-005) | insecure-crypto              | Medium   | CWE-328  |
| [ZCG-JS-006](#zcg-js-006) | unsanitized-html             | Medium   | CWE-79   |
| [ZCG-JS-007](#zcg-js-007) | sql-injection                | High     | CWE-89   |
| [ZCG-JS-008](#zcg-js-008) | path-traversal               | High     | CWE-22   |
| [ZCG-JS-009](#zcg-js-009) | weak-randomness              | Medium   | CWE-330  |
| [ZCG-JS-010](#zcg-js-010) | prototype-pollution          | High     | CWE-1321 |

---

## ZCG-JS-001

### Dangerous eval() Usage

**Severity:** High  
**CWE:** [CWE-95](https://cwe.mitre.org/data/definitions/95.html) - Eval Injection

#### Description

Detects usage of `eval()` which can execute arbitrary code. This is one of the most dangerous JavaScript functions and is a common source of code injection vulnerabilities.

#### Vulnerable Code

```javascript
// ❌ Direct eval
const result = eval(userInput);

// ❌ Indirect eval via window
window.eval(userInput);
```

#### Secure Alternative

```javascript
// ✅ Use JSON.parse for JSON data
const data = JSON.parse(userInput);

// ✅ Use a safe expression parser for math
import { evaluate } from 'mathjs';
const result = evaluate(expression);
```

---

## ZCG-JS-002

### Dynamic Function Constructor

**Severity:** High  
**CWE:** [CWE-95](https://cwe.mitre.org/data/definitions/95.html) - Eval Injection

#### Description

Detects usage of `new Function()` which is similar to `eval()` and can execute arbitrary code.

#### Vulnerable Code

```javascript
// ❌ new Function with user input
const fn = new Function('return ' + userInput);

// ❌ Function without new
const fn = Function('a', 'b', 'return a + b');
```

#### Secure Alternative

```javascript
// ✅ Use predefined functions
const operations = {
  add: (a, b) => a + b,
  subtract: (a, b) => a - b,
};
const result = operations[operation](a, b);
```

---

## ZCG-JS-003

### Command Injection

**Severity:** High  
**CWE:** [CWE-78](https://cwe.mitre.org/data/definitions/78.html) - OS Command Injection

#### Description

Detects potential command injection via `child_process` methods like `exec`, `execSync`, and `spawn`.

#### Vulnerable Code

```javascript
// ❌ User input in shell command
exec(`grep ${userInput} file.txt`);

// ❌ Template literal with user input
execSync(`cat ${filename}`);
```

#### Secure Alternative

```javascript
// ✅ Use spawn with array arguments
spawn('grep', [userInput, 'file.txt']);

// ✅ Validate/sanitize input
const sanitized = filename.replace(/[^a-zA-Z0-9.-]/g, '');
```

---

## ZCG-JS-004

### Hardcoded Secrets

**Severity:** High  
**CWE:** [CWE-798](https://cwe.mitre.org/data/definitions/798.html) - Hardcoded Credentials

#### Description

Detects hardcoded passwords, API keys, tokens, and other secrets in source code.

#### Vulnerable Code

```javascript
// ❌ Hardcoded password
const password = 'admin123';

// ❌ Hardcoded API key
const API_KEY = 'sk-1234567890abcdef';

// ❌ Hardcoded in config object
const config = { apiKey: 'secret123' };
```

#### Secure Alternative

```javascript
// ✅ Use environment variables
const password = process.env.DB_PASSWORD;

// ✅ Use a secrets manager
const apiKey = await secretsManager.getSecret('api-key');
```

---

## ZCG-JS-005

### Insecure Cryptographic Algorithms

**Severity:** Medium  
**CWE:** [CWE-328](https://cwe.mitre.org/data/definitions/328.html) - Weak Hash

#### Description

Detects usage of weak/broken cryptographic algorithms like MD5 and SHA1.

#### Vulnerable Code

```javascript
// ❌ MD5 is broken
crypto.createHash('md5').update(data).digest('hex');

// ❌ SHA1 is deprecated
crypto.createHash('sha1').update(data).digest('hex');

// ❌ DES/RC4 are insecure
crypto.createCipheriv('des-cbc', key, iv);
```

#### Secure Alternative

```javascript
// ✅ Use SHA-256 or stronger
crypto.createHash('sha256').update(data).digest('hex');

// ✅ Use bcrypt for passwords
const hash = await bcrypt.hash(password, 10);

// ✅ Use AES-256-GCM for encryption
crypto.createCipheriv('aes-256-gcm', key, iv);
```

---

## ZCG-JS-006

### Unsanitized HTML (XSS)

**Severity:** Medium  
**CWE:** [CWE-79](https://cwe.mitre.org/data/definitions/79.html) - Cross-site Scripting

#### Description

Detects DOM XSS sinks like `innerHTML`, `outerHTML`, `document.write`, and `insertAdjacentHTML`.

#### Vulnerable Code

```javascript
// ❌ innerHTML with user content
element.innerHTML = userContent;

// ❌ document.write
document.write(userContent);

// ❌ React dangerouslySetInnerHTML
<div dangerouslySetInnerHTML={{ __html: userContent }} />;
```

#### Secure Alternative

```javascript
// ✅ Use textContent for plain text
element.textContent = userContent;

// ✅ Sanitize HTML with DOMPurify
element.innerHTML = DOMPurify.sanitize(userContent);

// ✅ Use framework escaping (React auto-escapes)
<div>{userContent}</div>;
```

---

## ZCG-JS-007

### SQL Injection

**Severity:** High  
**CWE:** [CWE-89](https://cwe.mitre.org/data/definitions/89.html) - SQL Injection

#### Description

Detects potential SQL injection via string concatenation or template literals in SQL queries.

#### Vulnerable Code

```javascript
// ❌ String concatenation
db.query('SELECT * FROM users WHERE id = ' + userId);

// ❌ Template literal
db.query(`SELECT * FROM users WHERE name = '${name}'`);
```

#### Secure Alternative

```javascript
// ✅ Parameterized query
db.query('SELECT * FROM users WHERE id = ?', [userId]);

// ✅ Named parameters
db.query('SELECT * FROM users WHERE id = :id', { id: userId });
```

---

## ZCG-JS-008

### Path Traversal

**Severity:** High  
**CWE:** [CWE-22](https://cwe.mitre.org/data/definitions/22.html) - Path Traversal

#### Description

Detects potential path traversal vulnerabilities in file system operations.

#### Vulnerable Code

```javascript
// ❌ User input in path
const file = path.join('/uploads', userFilename);
fs.readFileSync(file);

// ❌ Express sendFile with user path
res.sendFile(req.params.filename);
```

#### Secure Alternative

```javascript
// ✅ Validate path stays within directory
const safeName = path.basename(userFilename);
const filePath = path.resolve('/uploads', safeName);
if (!filePath.startsWith('/uploads/')) {
  throw new Error('Invalid path');
}
```

---

## ZCG-JS-009

### Weak Randomness

**Severity:** Medium  
**CWE:** [CWE-330](https://cwe.mitre.org/data/definitions/330.html) - Insufficient Random Values

#### Description

Detects usage of `Math.random()` for security-sensitive operations.

#### Vulnerable Code

```javascript
// ❌ Math.random for tokens
const token = Math.random().toString(36);

// ❌ Math.random for session IDs
const sessionId = Math.random().toString(16);
```

#### Secure Alternative

```javascript
// ✅ Use crypto.randomBytes
const token = crypto.randomBytes(32).toString('hex');

// ✅ Use crypto.randomUUID
const id = crypto.randomUUID();
```

---

## ZCG-JS-010

### Prototype Pollution

**Severity:** High  
**CWE:** [CWE-1321](https://cwe.mitre.org/data/definitions/1321.html) - Prototype Pollution

#### Description

Detects patterns that could lead to prototype pollution attacks.

#### Vulnerable Code

```javascript
// ❌ Direct __proto__ modification
obj.__proto__ = malicious;

// ❌ Unsafe object merge
Object.assign({}, userInput);

// ❌ Dynamic property assignment
obj[key] = value; // key could be "__proto__"
```

#### Secure Alternative

```javascript
// ✅ Create objects without prototype
const obj = Object.create(null);

// ✅ Filter dangerous keys
const safeKeys = Object.keys(input).filter(
  (k) => !['__proto__', 'constructor', 'prototype'].includes(k)
);

// ✅ Use Map for dynamic keys
const map = new Map();
map.set(key, value);
```
