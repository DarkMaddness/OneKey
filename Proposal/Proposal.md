# Onekey
Daniel Matthews | A01185843 | 23/04/2026

---

## Overview
Your passwords on your hardware.

Onekey is a self-hostable password manager written in go, deployable via docker, and accessed via a terminal client also written in go. 

## Executive Summary
Nowadays everyone has multiple online accounts, it's unavoidable, and there are two options to deal with all of the logins. Either you reuse a password or you use a password manager.

Reusing a password is easy but anytime one of your accounts gets leaked, all of your accounts are at risk until you change your password, which has to be done for all of your accounts.

A password manager is a service where you store your usernames and passwords for your different services and access them by using a master username and password, letting you have different password for each of your accounts, but only need to remember one. Now you may need to interact with the manager to login on some sites and that could be viewed as a negative, but most managers will integrate with your system or browser and provide auto-fill so you don't need to find the credentials yourself. The main downside is one of two, either the subscription cost for using the password manager, or it's the time cost of setting up a password manager yourself.

Onekey is a self-deployable password manager, and so requires you to set it up. The goal of Onekey is to be as easy to setup as conceivably possible. Most self-hosted password managers will require a domain, dns records, and router port-forwarding. Onekey would handle these needs with a public proxy server, making it so you don't need to worry about them; however, that won't be delivered in the this term, it is to much work to commit to at this point and the base system needs to be built first. 

What will be delivered is a local network zero knowledge password manager with a terminal client. Zero knowledge means that all of your passwords and usernames stored on the server are encrypted, your encryption key is never seen by the server, your master password is stored as a cryptographically secure hash, and the hashing happens before it leaves the client. This means that even with a full database leak, someone would still need to break either the encryption or the hash to read your passwords, both of which is computationally infeasible.

Setting up and using the delivered project should go like such. You deploy the server and database on a device via a docker image and docker compose, and then using the terminal client you specify the ip address and port number that the server is running on, then the terminal client will give options like logging in, or setting up a user, and once logged in, it will have options for adding, viewing, updating, or deleting entries.

The development will follow the following schedule.

Weeks 1-2: Implement SRP along with automated testing.

Weeks 3-4: Implement JWT along with automated testing.

Week 5: Implement user creation and deletion, along with automated testing for both.

Week 6: Implement entry creation and retrieval, along with automated testing for both.

Week 7: Implement entry updates and deletion, along with automated testing for both.

Week 8: Implement user password updates, along with automated testing.

Week 9: Implement user username updates, along with automated testing.

Weeks 10-12: This will be additional time for uncompleted tasks, or if everything has gone to schedule, this will be time for the stretch goal which is a web client.

## Biography
I am currently taking a cryptography course, have previously done work with password cracking, have had experience querying and designing SQL databases, and have built, in combination with other classmates, several web apps ranging from a video game database web app, to a trip planning web app. My previous experience and ongoing learning in the space of cryptography will allow me to complete this project. In particular the trip planning app had a presentation that followed a similar evaluation criteria of setting up an account and doing various tasks with the fresh account; that experience should be extremely relevant here.

## Introduction & Background
You have multiple online accounts. Between banking, work, social media, spotify, netflix, and others services, you can easily have several dozen accounts, and each requires a password.

You have two options, reuse your password or use a password manager. Reusing is bad because you increase the chance of your password getting leaked because it could happen from any of your services, and then all of your accounts are at risk until you change the password on them. A password manager either requires a subscription or it requires you spending time to setup the service, domain, dns, and router port forwarding.

## Goal & Proposed System
I will be delivering a local network password manager with a focus on ease of use. The evaluation of the project will be based on being able to complete a number of tasks which should generally go as follows:

- Deploy server from a single docker compose.yaml file
- Create an account -> Enter username and password -> Server response confirming success
- Log into the account -> Enter username and password -> Server response confirming success
- Add an entry -> Enter entry title, username, and password -> Server response confirming success
- Update an entry -> Enter new title/username/password for an entry -> Server response confirming success
- Delete an entry -> Select delete on an entry -> Server response confirming success
- Delete the account -> Selecting delete on account -> Server response confirming success or failure

## Methodology & Design
Onekey will have a server communicating with a database, and a terminal based client that will communicate with the server. The server and database only see encrypted data for password entries, and the master password is stored as a cryptographically secure hash. Encryption happens on the terminal client, and the encryption key is only stored in memory. Encryption will be done using AES (Advanced Encryption Standard), authentication will be done via SRP (Secure Remote Password) and session management will be handled via JWT (JSON Web Tokens).

Unit tests will be created to ensure that functionality stays consistent as development continues, and to verify that logic is working as expected. An example of a unit test, would be a SRP test, the test will act as a client and server, with predefined values, and try to have the client prove to the server that it knows the password, it would pass the test if it authenticates successfully.

## Scope
The design and tests are within the bounds of the scope defined here.

### In Scope
The scope consists of the server, database, and terminal client. They will support authentication, CRUD (Create, Read, Update, Delete) operations while having passwords encrypted anytime in storage or transit, and the master password and encryption key will never leave the client. Additionally there will be username and password histories restricting some operations on updating account information and providing audit trails.

All of this is here because it is what I think is a reasonable minimum functionality for a password manager, and for testing that it works, I will use unit tests.

### Out of Scope
Other clients like mobile, browser extensions, and other platforms, along with the public proxy server, are explicitly out of scope, and will not be worked on.

Other clients are excluded because I haven’t worked with their platforms before, or in the case of mobile, I haven’t worked with rest APIs in mobile, and I don’t want to place an unknown amount of work as a goal in the later part of my project.

The public proxy server is excluded because it would practically be a project to itself and would be way to much work.

### Stretch Goal
Neither in scope or out of scope is a web client which I am framing as a stretch goal. I don't know exactly how much time it will take to implement the defined scope and so I have put the web client here as something I will do if development is going according to schedule, but also something that I will drop if development is falling behind schedule. 

The web client would have the same functionality as the main terminal client and it has been chosen because it doesn't require additional work on the server, instead it is self contained.

## System Architecture & Design
The database schema is as follows:

![](Assets/Database_Schema.drawio.png)

Account Creation would go as follows:

![](Assets/Account_Creation.drawio.png)

Account Login would go as follows:

![](Assets/Account_Login.drawio.png)

Other operations would follow a similar structure.

## Success Metrics
Success will be defined by achieving the development of the server, database, and terminal client with the CRUD functionality and deployment via docker compose.
More specifically the functionality will be tested by completing the following tasks:

- Deploy the server
- Create a new account
- Login to the new account
- Add three new entries to the account
- Update an entry
- Delete an entry
- Update the account password
- Update the account username
- Delete the account

Falling short would be any functionality missing. Going beyond would be the development of the web client. Testing for each item will be done on a pass or fail basis.

Importantly, not having passwords encrypted in storage, not having passwords encrypted when going over the network, or having a weak authentication system, regardless of other progress would be considered a failure, and is why it will be developed first rather then being worked on and added in later.

## Innovation & Differentiation
Truthfully, there are not many differentiable features to draw towards in comparison to other password managers. The main differentiation was the future use of a public proxy server, but that isn’t going to be delivered. Now some of the possible differences I will have compared to other password managers, I will be using SRP while they may or may not be using nonce authentication, but similarly they might be using multi factor authentication while I am single factor authentication. I am using argon2 for hashing the master password, but others could be using the same, or they may be using a similarly effective algorithm like yescrypt.

Ultimately password managers are difficult to differentiate which is why price is often the deciding factor that providers advertise. That or their clean track record for data breaches.

With that said, a focus of my project is to make deployment easy with the public proxy server, but since I can’t deliver that, I will make my password manager easy to deploy in a different way. The server will be deployed via docker compose, with the only configurable settings being the port number. This means that the user doesn’t have to personally download anything, just a single compose.yaml to paste into their docker manager, and the image will be pulled automatically and configuration will only be necessary if the default port is not free.

## Risks & Mitigations
There are three main risks with this plan.

**First**, go which is what I will use for the server and terminal client has an interface for SQL based databases, but does not have implementations in the standard library, instead implementations are provided by 3rd parties and finding one that works for this project would be the first blocker.

Now there are several of what go calls drivers, which are implementations of the SQL interface, and around seven for SQLite alone, so I should be able to find one that works, and if I can’t, then I will look at other databases like Postgres, mySqlServer, or even non-relational databases.

**Second**, SRP is a protocol that I am unfamiliar with, though there are 3rd party libraries and would be what I consider the second blocker, as the whole system depends on strong authentication, and so figuring out SRP is a major importance.

With that said, while SRP is my desired authentication implementation, there are other though slightly less secure, simpler options, like one-time challenges that I could implement myself if needed.

**Third**, finding equal implementations of SRP, AES and other algorithms for the web client. If I can’t find implementations with the same output, then I would need to either wrap an existing implementation, or write my own implementation.

While this is a major possibility, with the algorithms being common and well documented, implementations shouldn’t differ very much, and I would likely find an implementation that will be compatible, even if it’s needs to be wrapped slightly to have the same functionality.

## Testing & Validation Plan
Testing will be done by unit tests with pass or fail evaluations. This is not an exhaustive list, but it is what I have thought of at this stage. The general idea is for the predefined requests used on the server side tests, to be the pass values used on the client side tests. Emulating a client to server test, but with each side actually being independent.

### Server:
1. SRP: Using a predefined password, salt, and verifier. It will test getting the verifier from the password and salt, as well as testing that a client and server can prove authenticity to each other. It will need to pass both to pass overall.

2. JWT: Issue a session token and an admin token, then test that the session token is accepted, then test that a predefined expired session token is rejected, then test that an request with a valid session token, but invalid admin token is rejected. All of these must pass for the test to pass overall.

3. User: Consists of 5 subtests:
   
   1. User Creation: Using a predefined http request, create a new user, and verify success response from the database.
   
   2. User Authentication: Using a predefined http request, query login information about newly created user, and check it against predefined expected output.
   
   3. User Password Updates: Using a predefined http request, update password, then retrieve data and check against predefined expected output.
   
   4. User Username Updates: Using a predefined http request, update username, then retrieve data and check against predefined expected output, then try updating the username again and verify it is rejected for being to close time wise to a prior username change.
   
   5. User Deletion: Using a predefined http request, delete user, then verify that user records are no longer present in the database.

4. Entry: Consists of 4 subtests on a predefined user:
   
   1. Entry Creation: Using a predefined http request, create new predefined entry under the predefined user, and verify success response from the database.
   
   2. Entry Retrieval: Using a predefined http request, query information about the new entry, and check it against predefined expected output.
   
   3. Entry Update: Using a predefined http request, update entry, and then query the entry and verify it has changed as expected.
   
   4. Entry Deletion: Using a predefined http request, delete entry, and then verify it is gone by trying to query it, and checking that it fails.

### Client:
1. Argon2: Using a predefined password and salt, hash the password, check it against a predefined hash, and verify they are identical.

2. HKDF: Using a predefined hash and salt, expand the hash into two new hashes, check them against predefined hashes, and verify they are identical to the predefined hashes, but also NOT each other.

3. AES: Using a predefined input, key, and encrypted input. It will test getting the encrypted input from the input and key, as well as getting the input from the encrypted input and key, testing both encryption and decryption. It must pass both to pass overall.

4. SRP: Using a predefined password, salt, and verifier. It will test getting the verifier from the password and salt, as well as testing that a client and server can prove authenticity to each other. It will need to pass both to pass overall.

5. Create User: Using a predefined username and SRP verifier, construct a http request, check it against a predefined request, and verify they are identical.

6. Get User: Using a predefined username, construct a http request, check it against a predefined request, and verify they are identical.

7. Update User Password: Using a predefined session token, admin token and new SRP verifier, construct a http request, check it against a predefined request, and verify they are identical.

8. Update User Username: Using a predefined session token, admin token and new username, construct a http request, check it against a predefined request, and verify they are identical.

9. Delete User: Using a predefined session token and admin token, construct a http request, check it against a predefined request, and verify they are identical.

10. Create Entry: Using a predefined session token, admin token, and encrypted entry, construct a http request, check it against a predefined request, and verify they are identical.

11. Get Entries: Using a predefined session token, construct a http request, check it against a predefined request, and verify they are identical.

12. Update Entry: Using a predefined session token, admin token, entry ID, and encrypted updated entry, construct a http request, check it against a predefined request, and verify they are identical.

13. Delete Entry: Using a predefined session token, admin token, and entry ID, construct a http request, check it against a predefined request, and verify they are identical.

## Schedule & Milestones
### Week 1
Setup user table, implement server SRP, and implement server SRP unit test.

### Week 2
Implement client SRP and client SRP unit test.

### Week 3
Setup token table, implement server JWT session token issuing and revoking. Implement server JWT admin token issuing and revoking. Implement server JWT unit test.

### Week 4
Implement client JWT token storage along with re-authenticate and retry workflow for when tokens are expired.

### Week 5
Implement user creation, user login, and user deletion for both the client and server. Implement server User Creation, User Authentication, and User Deletion unit tests. Implement client Argon2, HKDF, Create User, Get User, and Delete User unit tests.

### Week 6
Implement entry creation and retrieval for both the client and server. Implement server Entry Creation and Entry Retrieval unit tests. Implement client Create Entry and Get Entries unit tests.

### Week 7
Implement entry updates and deletion for both client and server. Implement server Entry Update and Entry Deletion unit tests. Implement client Update Entry and Delete Entry unit tests.

### Week 8
Setup password history table and implement user password updates for both client and server. This will also require all user entries to be updated because a new encryption key will be getting used, so the entries must be pulled, decrypted then encrypted using the new key, and then updated in the database. Implement server User Password Updates unit test. Implement client Update User Password unit test.

### Week 9
Setup username history table and implement user username updates for both client and server. Implement server User Username Updates unit test. Implement client Update User Username unit test.

### Weeks 10, 11, 12
Complete unfinished tasks, or if work has gone as scheduled, build web client and implement the same functionality that is in the terminal client.

## Assumptions
I am assuming that the local network is a trusted environment, and that if the project was used outside of a local network, then the server would be protected by something like a reverse proxy with https support, so it has end to end encryption.

## Ethics & Data Governance
Data will be located on users own devices, along with being encrypted, so privacy risks should be very low.

Accounts deleted will use the cascade database option, removing all records when deleting the account.

## Feasibility & Build Plan
The project starts with a SQLite database that will have a user table with ID, username, salt, and verifier fields. Connected to the database will be the server. Written in go, the server will read, write, update, and delete data from the database to complete requests sent to it. The first piece of functionality implemented on the server will be SRP, which will be used for user authentication. Sending the requests to the server will be the terminal client, also written in go, it will be the primary point of interaction for users and the first piece of functionality implemented will also be SRP. With SRP implemented on both sides, the means for authenticating a user has been setup.

The next piece will be setting up the system to manage sessions. To start, a new token table will be added to the database with ID, userid, and hash fields. Then JWT will be implemented on the server for issuing, storing on the database, and revoking the session tokens. Notably along with the long lived session tokens, a short lived admin token will also be need for higher risk operations like updating or deleting entries. These admin tokens will be managed by the server in memory in a data structure like a list or map. Next the client will have JWT implemented, and with that done, the framework for a user to hold an authenticated session has been created.

User creation is next, implementation will start with the server providing a way to check if a username is available. Then the client will accept a username and password, and if the username is not taken, then it will derive the SRP verifier by passing the password though Argon2, and HKDF. The verifier, salt used in Argon2, and the username will be passed to the server to create the user.

User login will be implemented next, and will use the SRP implementations to authenticate a user based on an entered username and password.

Then user deletion will be implemented. It will check for a valid session token and admin, and if both are present then it will remove the user and all dependent rows from the database.

Next is entries, and for that, an entries table with ID, userid, and data entries will be added to the database. These entries will be created on the client by accepting a title, username, and password, then encrypting it with AES 256 using a second key created when expanding the Argon2 hash through HKDF, this key will only exist on the client, and will never leave the client. The encrypted data will then be sent to the server, which will use the data to create a row in the entries table. Retrieving user entries will be done by pulling all entries with the users ID, passing them to the client, and having the client decrypt them all.

Entry updates and deletion will require both a session token and an admin taken, and will simply update the data field with a new encrypted data blob, or remove the row from the table in the case of deletion.

Master password updates will be the next feature implemented and will make use of another database table. A password history table will be added with ID, userid, and timestamp fields. While the table is not strictly necessary, it is very simple to implement and will provide an audit log for password rotations. Updating a master password will require both a session token and an admin token, will go through the process of deriving the SRP verifier, will derive a new AES key, will pull all of the user’s entries, decrypt them, encrypt them with the new key, and then pass the updated entries along with the new verifier and salt to the server to update the database and create a row in the password history table.

The last feature is username updates. This will require a new username history table with ID userid, old username, and timestamp. This will be used to provide a paper trail of username changes, and will also be used to prevent overly frequent username changes. Updating a username will require both a session token and an admin token, and will check that you haven’t changed your username in the last 3 hours. If these are all met, then a row will be created in the username history table, and your username will be updated in the users table.

The general flow can likely be assumed from the above descriptions, but I will go through a general usage of the project here. First the server and database will be deployed to a device via docker compose. Then when launching the terminal client, which could be from any device on the same network, you will specify the ip address and the port that the server is running on. You will then be given the option to create an account, or login. Selecting login, you will be prompted for a username and a password. You will then either be logged in, or you will be rejected. Assuming you logged in you have the options of looking at your entries, updating your password, updating your username, revoking all token, deleting your account, or logging out. Selecting your entries you will be shown a list of titles and the option to create a new entry. Selecting one of the titles will show you the details, along with the option of updating or deleting the entry.

Going into the resources that will be used in the development of the project. First SRP, there are several libraries available including one from 1Password which I plan to use. Next JWT, there is an extremely popular library that I plan to use. AES has an implementation in the standard library, so I plan to use that. Argon2 has an implementation in the golang.org/x/crypto repository which has supplementary cryptography packages maintained by the go team, but not a part of the standard library. And HKDF has an implementation in the standard library.

This is a realistic amount of work to accomplish, because it will have many parts that are reusable in the api endpoints, and doesn’t have any cloud services, meaning there are fewer uncontrollable points of failure. I have done other projects with databases, and so the largest undertaking here will be the usage and chaining of cryptographic algorithms, and security features, which by themselves, should be something I can accomplish.

## Security Model 
To start, this is a zero knowledge password manager which means that the server and database only receive encrypted or hashed records, and never have access to the encryption key. This means that even with a full database leak, no passwords are directly exposed, only the encrypted blobs for entries, and verifiers, which are cryptographically secure hashes.

Now the session token. The session token lasts 24 hours once issued, or until the user selects log out. With the session token you can request the encrypted blobs of the account that the token was authenticated for. So even with a leaked token, the extent of possible damage is simply an attacker getting access to encrypted blobs. To turn the encrypted blobs into readable data you will need the proper AES key. I will go over the process to get the AES key later. Session tokens are stored in the database server-side and stored in memory on the client side, so a client session abruptly ending will have the session token wiped from memory client-side, but will remain in the database server-side until it expires and naturally gets cleaned up. 

Next the admin token. The admin token lasts 5 minutes once issued and is tied to the session token that was issued at the same time. That way you can't use an admin token with a different session's session token, it has to be the session token that was issued alongside it. With the admin token and paired session token, you can create new entries, update entries, delete entries, update your password, update your username, and delete your account, basically everything except reading data requires the admin token. The idea here is that the majority of use for a password manager is filling in login forms, and a much smaller amount of time is spent on adding and updating passwords. When someone is making changes to their passwords, it is usually one thing they are doing, or they are doing a bunch all at once. Both of these are well served by the 5 minute admin token, and make it so these higher consequence actions are less available and require fairly immediate authentication. If these actions were available with just the session token, then a session token being leaked would be much more harmful. Admin tokens are stored in memory on both the server and the client, so they are not persistent. They will also get cleared if a user manually logs out.

Now for authentication. It is a multipart process which starts with the entered password. First a salt is retrieved from the server if logging in, or generated if creating a new account or updating a password. Then the salt along with the password gets hashed with Argon2 in the id hybrid mode using recommended settings from RFC 9106 Section 7.4 time=1 and memory=2GB. This will produce a 256bit key. The key will then be fed into HKDF with the same salt, and will produce two separate 256bit keys, one for authentication and one for AES. The produced authentication key will then be passed to SRP as x, the client secret. The SRP client will then either calculate v the verifier if creating an account or updating a password, or it will be used to authenticate with the server. The AES key is stored in memory on the client and will be used to encrypt new entries before sending them to the server and to decrypt entries pulled from the server. The AES key will be stored in the clients memory until the user manually logs out, the client is closed, or the device shuts down, whichever happens first. The authentication key will only live as long as the authentication process takes to complete.

When a user authenticates they will be issued a set of tokens, one session token and one admin token. If the admin token expires and a user tries an action that requires an active admin token, they will be prompted to re-authenticate and if successful will be issued a new set of tokens, the old session token will be removed.

## Other Security Considerations
I thought about preventing timing attacks on salt retrieval by adding a time gate and returning a fake salt, as this could be a vector for determining users, but realized that as long as I don't restrict account creation, doing so would be pointless as an attacker could determine if a user exists just by trying to create an account with the username they want to check. Now I could restrict account creation by using an environment variable, but it would be adding complexity that I ultimately don't think this project needs. If it is a path I want to go down in the future, it would not be difficult to implement, but right now, I want to avoid additional complexity if I can.

## Canonical Terms
| Name                                    | Definition                                                                   | Verification |
|:---------------------------------------:|:----------------------------------------------------------------------------:|:------------:|
|                     Deploy Server                    |                                       Can you deploy the server via docker compose.                                       |       Manual Test       |
| Creating a new account                  | Can you create a new account and receive positive feedback.                  | Manual Test  |
| Logging into said new account           | Can you login to the newly created account.                                  | Manual Test  |
| Adding three new entries to the account | Can you add entries to the new account.                                      | Manual Test  |
| Updating an entry                       | Can you update an entry on the new account.                                  | Manual Test  |
| Deleting an entry                       | Can you delete an entry on the new account.                                  | Manual Test  |
| Updating the account password           | Can you update the password on the new account and login.                    | Manual Test  |
| Updating the account username           | Can you update the username of the account and login.                        | Manual Test  |
| Deleting the account                    | Can you delete the account and no longer login.                              | Manual Test  |
| Encryption test                         | Verify by looking at the database and seeing that all entries are encrypted. | Manual Test  |
