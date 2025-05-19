# Threat Model

Should be secure against adversary who is not in possession of a user’s ATM card, even if the adversary knows the user’s PIN, and vice versa.

Attacker is in control of a router between ATM and bank
- Can inspect, modify, drop, and duplicate packets
- Can generate new packets

We also assume that the bank computer cannot be compromised, nor can the memory on the ATM be examined. The following is out of scope for possible attacks:
- Using code disassembly to recover secret keys
- Attacks that require restarting the bank
- Attacks that involve inspecting contents of the files created by init

# Basic Functionality

### Bank
- `create-user <user-name> <pin> <balance>`
- `deposit <user-name> <amt>`
- `balance <user-name>`

### ATM
- `begin-session <user-name>`
- `withdraw <amt>`
- `balance`
- `end-session`

### Side Notes:
- `user-name` can be at most 250 characters only consisting of `[a-zA-Z]`
- `pin` should be in the following format: `[0-9][0-9][0-9][0-9]`. Must be exactly 4 digits.
- `amt` can be at most what can be represented with `unsigned int`.

# Implementation

### *init.c*

Creates two files `<path>.bank` and `<path>.atm` that is to be used by the bank and ATM, respectively to securely communicate with each other.

The two files both contain a *shared key* and a *sequence number*. 
1) We will be using **AES-256 in CBC mode** to encrypt and decrypt packets that are being sent and received between the ATM and bank. The shared key will be a **randomized 256-bit AES key** (32 bytes) that is generated once when init.c is run.

2) The sequence number will be used to keep track of the ordering of packets and to ensure that adversaries cannot launch a replay attack using packets that were previously in transit. Each message will be prepended with a sequence number before encryption. When received, each party can verify that the sequence number of the packet is the expected sequence number. The sequence number will be initialized when init.c is run and will be a **random unsigned integer value**. Each packet sent will increment the sequence number by 1 for the following packet.

---

### *list.c*

Initializes the `List struct`(linked list) to store the user information.
The bank uses the list to store the names of each user in addition to the user specific hash values and their balances.
The ATM uses the list to store the names of users who attempted to `begin-session` and failed. The number of consecutive failed attempts are recorded by the user to deploy an exponential backoff delay to prevent brute force attacks.

---

### *helpers.c*

Contains helper functions for the ATM-Bank protocol that assist with the following
1) Encryption and MAC Generation
2) Decryption and Message Parsing
3) Hashing using *SHA256*
4) Removing Newline Characters *\n* from user inputs.

---

### ATM-Bank Protocol

**Overview**

For each command entered into the ATM, the ATM will send an encrypted packet to the Bank requesting the necessary information. 

The method of encryption will be **AES-256 in CBC mode**.
1) As CBC requires an IV (initialization vector), the packet will be prepended with a 
**16-byte IV** which will be *randomly generated* before each encryption. 
2) In addition, the packet will be appended with a **32-byte MAC** (message authentication code) of the packet to ensure the integrity of the IV and the packet. 

To further ensure the confidentiality of the packets, the messages are padded to a length of **288 bytes**. The encryption of a 288 byte message will result in a ciphertext of length 304 as CBC encrypts the length of the message in a 16-byte block at the end. With the IV and the MAC tag, the total ciphertext will always be 352 bytes (304 + 16 + 32).

The plaintext will be formatted as following: `SEQNO || MSG_LEN || MESSAGE || PADDING`

The ciphertext (including IV and MAc) will be formatted as following (with the bolded begin encrypted): `IV || ENC(KEY, PLAINTEXT) || MAC`

Both the bank and ATM will **drop** any packets that are incorrectly formatted. Any packets that are not of **length 352** and/or have incorrect **sequence number** will be considered as invalid packets. If a packet is needed to finish the ongoing command, the ATM/Bank will indefinitely hold until the correctly formatted packet is received.

**Commands**

**Note**: The packets will be mentioned by the message it contains. Even if not explicitly stated, all packets being sent are encrypted. 

1) `begin-session <user-name>`
The ATM will send the bank the message `begin-session <user-name>`.
Upon seeing the message, the bank will search for `<user-name>` from the list of registered users. If found, the bank will send back the hash value corresponding to `<user-name>`. Otherwise, it will send back the message `"No such user"`.
If the ATM receives the hash value, it will recalculate the hash using the salt stored in `<user-name>`’s card and the pin input. If they match, the ATM will prompt the user for the PIN and send the bank “Authorized” to fully establish the session. Otherwise, the ATM sends the bank `“Not authorized”` and does not authorize the user, since if the hash does not matter, either the input pin is wrong or the salt value in the card is incorrect meaning that the card was forged.
If the ATM receives `“No such user”` from the bank, the ATM will echo this message and print it.
The bank upon seeing “Authorized” will establish the session and remember `<user-name>` until the `“end-session”` message is seen. Otherwise, the bank will not establish the session and discard `<user-name>`
The ATM will print out either 1) `“Authorized”` if the session was established successfully, 2) `“Not authorized”` if the card verification or pin verification failed, or 3) `“No such user”` if it received `“No such user”` from the bank.

2) `withdraw <amt>`
The ATM will send the bank the message `“withdraw <amt>”`
Upon seeing the message, the bank will retrieve the balance of the session user. If the `<amt>` requested is greater than the session user’s balance, it will send back `“Not Authorized”`. Otherwise, it will send `“Authorized”` and deduct the requested amount from the session user’s balance.
The ATM will print out either 1) `“$<amt> dispensed”` if authorized by the bank or 2) `“Insufficient funds”` if not authorized.

3) `balance`
The ATM will send the bank the message `“balance”`
Upon seeing the message, the bank will retrieve the balance of the session user and send the balance to the ATM.
The ATM will print out `“$<amt>”` using the amount received from the bank.

4) `end-session`
The ATM will send the bank the message `“end-session”`
Upon seeing the message, the bank will send back the message `“Ending Session”` to acknowledge that it will be ending the session with the current user. The bank will then stop the session and forget the session user.
The ATM will receive the message `“Ending Session”` and also stop the session and forget the session user. Once the session has fully been stopped, the ATM will print out `“User logged out”`.

# Vulnerabilities

### 1) Replay Attacks
- **Threat**: Adversary has the ability to inspect and duplicate packets. This means that the adversary could capture a previously sent packet and resend the same packet(s) to the atm or bank and impersonate each other.
- **Solution**: To defend against such attacks, sequence numbers are included in each packet which the atm and bank checks with the expected sequence number. Each subsequent packet should have a sequence number incremented by 1 from the previous packet. To ensure that the adversary cannot simply count and forge a packet with the correct sequence number, the sequence number is initialized to a *random unsigned integer value*.
- **Solution Code**:
```
// Inclusion of SEQNO to ciphertext before sending
size_t to_send_len = 0;
unsigned char *to_send = encrypt_and_mac(bank->s_key, hash, msg_len, (bank->seqno)++, &to_send_len);
bank_send(bank, to_send, to_send_len);
```

```c
// Explicitly Checking the Received Sequence Number with the Expected Sequence Number.
// Drops packet if incorrect
unsigned char ciphertext[MAX_RECV_LEN + 1];
memcpy(ciphertext, command, MAX_RECV_LEN);
ciphertext[MAX_RECV_LEN] = '\0';

unsigned char seqno_buf[SEQNO_LEN + 1];
unsigned char *message = decrypt(bank->s_key, ciphertext, seqno_buf, NULL);
seqno_buf[SEQNO_LEN] = '\0';
if (bank->seqno != strtoul(seqno_buf, NULL, 10)) {
    return; // Invalid packet --> Drop
}
```

### 2) Integrity Attacks
- **Threat**: Adversary can inspect all the packets in transit and knows the method of encryption (Kerkoff's Principle). The adversary could modify the ciphertext in an undesired way that leads to unwanted side effects like withdrawing more money than allowed.
- **Solution**: To defend against the adversary modifying the packets in any undesired way, each ciphertext is appended by a MAC tag that verifies the integrity of the IV || Ciphertext. Upon receiving the ciphertext, the protocol recalculates the MAC for IV || Ciphertext and checks that the received MAC is identical to the recalculated MAC.

```c
// Encryption Algorithm for the Protocol
unsigned char *encrypt_and_mac(unsigned char *s_key, unsigned char *input, 
                                    size_t input_len, unsigned int seqno, size_t *output_len) {
    // Generation of 16-byte IV
    // Encrypting Input to Ciphertext
    ....

    unsigned char *mac = NULL;
    unsigned int mac_len = 0;
    mac = HMAC(EVP_sha256(), s_key, sizeof(s_key), iv_cipher, 16 + ciphertext_len, NULL, &mac_len);
    if (mac == NULL) return NULL; // MAC Failure

    // Appending MAC to end of Ciphertext
}
```

```c
// Decryption Algorithm for the Protocol
unsigned char *decrypt(unsigned char *s_key, unsigned char *ciphertext, unsigned char *seqno, size_t *message_len) {

    ....

    // Retrieve MAC from Ciphertext
    unsigned char mac[32];
    memcpy(mac, ciphertext + 320, 32);

    // Recalculate MAC from given IV and ciphertext
    unsigned int new_mac_len = 0;
    unsigned char *computed_mac = HMAC(EVP_sha256(), s_key, sizeof(s_key), iv_cipher, 16 + cipher_len, NULL, &new_mac_len);
    assert(computed_mac != NULL);

    // Ensure that the two MACs are the same
    if (CRYPTO_memcmp(mac, computed_mac, 32) != 0) {
        return NULL; // Integrity Failure => Drop Packet
    }
}
```

### 3) Confidentiality Attacks
- **Threat**: The adversary has the ability to eavesdrop on or capture any packets in transit. The adversary could gain certain knowledge about the message from the ciphertext
- **Solution**: To ensure that the adversary cannot gain any information about the plaintext from the ciphertext, all packets will be encrypted using AES256 in CBC mode which ensures confidentiality. The protocol also ensures that all packets being sent are a fixed size of 352 by padding the message with the necessary amount of random bytes. By ensuring that all packets in transit are the same length, it prevents adversaries from being able to decipher which command is being requested. Otherwise, shorter requests like “balance” or “end-session” may result in shorter ciphertexts compared to commands like `“begin-session <name>”` or `“withdraw <amt>”` since `<name>` could be up to 250 characters long and `<amt>` which is an unsigned int can be up to 10 digits.
- **Solution Code**:
```c
unsigned char *encrypt_and_mac(unsigned char *s_key, unsigned char *input, 
                                    size_t input_len, unsigned int seqno, size_t *output_len) {
    // Generate 16-byte IV
    // Format the plaintext buffer to include seqno, message_length, message

    // Generate padding for the message
    int max_message_len = 288;
    size_t rand_len = max_message_len - plaintext_len;
    unsigned char noise[rand_len];
    assert(RAND_bytes(noise, rand_len) == 1);

    // Append padding to end of the plaintext
    unsigned char to_encrypt[max_message_len];
    memcpy(to_encrypt, plaintext, plaintext_len);
    memcpy(to_encrypt + plaintext_len, noise, rand_len);

    // Encryption and MAC generation
    ...
}
```

### 4) Brute Force Attacks
- **Threat**: Given that the pin of each user is only 4 digits, there are only 10000 possible pins (each digit can be 0-9, therefore 10^4). An adversary can easily generate a script that tries all 10000 pins for a single user and record the correct user.
- **Solution**: To prevent the adversary from brute forcing the pin of any user, the protocol adopts an **exponential backoff** approach to incorrect pin attempts. The wait time will begin at 15 seconds for the first incorrect attempt and *doubles* each subsequent time the user incorrectly inputs their pin. For attempts after the 5th time, the ATM will lock for *10 minutes* for that user. The exponential backoff and lock user will occur independently for each user and the locks/waits will occur immediately before prompting the user for the pin.
- **Solution Code**:
```c
void atm_process_command(ATM *atm, char *command) {
    ...
    if (strcmp(instruction, "begin-session") == 0) {
        // Message Exchanges and PIN Input to initialize session
        ...
        if (i == 4 && CRYPTO_memcmp(received_hash, hash, recv_hash_len) == 0) { // PIN and Hashes Match
            // Establishing Connection
            ...
        } else { // PIN Failure or Card Forgery
            // Append user to atm->attempts list
            // Keep Track of # of Failed Attempts
            // Inform Bank that session will not be established
            ...
            if (user->val > 5) {
                    sleep(10 * 60); // 10 Minute Sleep if incorrect more than 5 times in a row
                } else {
                    unsigned int temp = 1;
                    for (int i = 0; i < user->val - 1; i++) { // Double the Time for Each Failed Attempt
                        temp *= 2;
                    }
                    sleep(temp * 15);
                }
        }
    }
    ... 
}
```

### 5) Card Forgery Attacks
- **Threat**: The adversary has the capability to forge the card of any user. 
- **Solution**: To protect against adversaries trying to forge the card of a user, the card contains the **32-byte salt** that was *randomly generated* with the creation of the card. This salt is used to calculate the hash value for the specific user. When the user enters the pin to establish the session, the ATM will send a request to the bank and the bank will reply with the hash value that was computed for that user. ATM will recalculate the hash using the salt and pin from user input. If the recalculated hash does not match the initial hash value, we can assume that either the pin was wrong or the card was forged. Even if the pin was correct, by not authorizing the user if the hashes don’t match, we can safely defend against scenarios where the adversary is attempting to forge a given user’s card.
- **Solution Code**:
```c
void atm_process_command(ATM *atm, char *command) {
    ...
    if (strcmp(instruction, "begin-session") == 0) {
        // Message Exchanges and PIN Input to initialize session
        // Receive Hash from the Bank
        ...
        unsigned char *hash = hash_input(plaintext, input_len); // Recalculate Hash of PIN || Name || Salt
        if (i == 4 && CRYPTO_memcmp(received_hash, hash, recv_hash_len) == 0) { // PIN and Hashes Match
            // Establishing Connection
            ...
        } else { // PIN Failure or Card Forgery
            // Keep Track of # of Failed Attempts by User
            // Inform Bank that session will not be established
            // Exponential Backoff for each failed attempt
            ... 
        }
    }
    ... 
}
```

### 6) Buffer Overflow Attacks
- **Threat**: A malicious user could attempt to input more characters than the expected amount causing a buffer overflow which could result in unwanted side effects.
- **Solution**: To prevent any buffer overflows from occuring due to user input, all buffers were explicitly terminated with null terminators. Furthermore, almost every buffer was made to hold exactly the expected bytes + 1 to account for null terminators as well. Any buffers where size is arbitrarily big due to user input discrepancies were initialized with null terminators at each index to ensure that the received string will be null terminated and not overflow. These buffers also hold 1 extra character than the number of bytes it reads, ensuring that the string is null terminated even if the buffer is completely filled up. The ATM and bank is coded to send and receive exactly 352 bytes which is the size of all packets from the protocol. Upon receiving, the number of bytes received also is double checked to ensure the received number of bytes was exactly 352. If the number of bytes is not the expected amount, the protocol drops the packet and waits for the correctly formatted packet.

### 7) Integer Overflow Attacks
- **Threat**: A malicious user could attempt to input an amount that exceeds the capacity of an `unsigned int`. This could cause integer overflow, possibly resulting in unwanted side effects such as the user being able withdraw more money than allowed.
- **Solution**: To ensure that an integer overflow does not occur and result in unwanted side effects, the `amt` string is stored in an `unsigned long` and checked against the `UINT_MAX` value. If the amount exceeds`UINT_MAX`, the ATM and the bank does not accept it as a valid amount. For commands like deposit, we check if the amount plus the current balance does not exceed `UINT_MAX`.

```
// Checking if amt input does not exceed UINT_MAX
if (strtoul(amt, NULL, 10) > UINT_MAX) { // Invalid Inputs
    printf("Usage: withdraw <amt>\n");
    return;
}
```

```
// Checking if depositing amt would not cause integer overflow
unsigned int curr_balance = user -> val;
if (curr_balance > UINT_MAX - (unsigned int) val) {
    printf("Too rich for this program\n");
} else {
    user->val = curr_balance + (unsigned int) val;
    printf("$%u added to %s's account\n", (unsigned int) val, name);
}
```

### 8) Availiability Attacks
- **Threat**: An adversary can inspect and modify packets in transit. Furthermore, the adversary could forge new packets. These unwanted changes to the packet may lead to the ATM or Bank crashing which denies users from accessing the Bank/ATM.
- **Solution**: The protocol checks the validity of the each packet by inspecting the length and sequence number of the packet. The Bank and ATM does not expect any packets that are not of length 352 and/or does not contain the correct sequence number. Deciphering ill-formatted packets or fully rejecting the packets that may result in unexpected behavior such as the programs crashing. Instead, the protocol simply drops any packets that does not align with the expectations and waits indefinitely for the well-formatted or expected packet to arrive.