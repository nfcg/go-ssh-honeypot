### Go SSH Honeypot

This is a simple SSH honeypot written in Go. It listens for incoming SSH connections, logs authentication attempts (both password and public key), and stores the data in a SQLite database. The server does not allow any successful logins and simply logs the connection details.

#### Features

  * **SSH Honeypot**: Masquerades as a real SSH server, OpenSSH 9.6p1.
  * **Credential Logging**: Captures usernames and passwords from password-based authentication attempts.
  * **Public Key Logging**: Captures public key fingerprints from public key authentication attempts.
  * **Database Storage**: All session data, including connection errors and authentication attempts, are stored in a SQLite database.
  * **Configurable**: The listen IP, port, database location, and log file can be configured via command-line flags.
  * **Concurrency**: Uses goroutines to handle multiple connections simultaneously.

#### Requirements

  * Go 1.16 or higher
  * `github.com/mattn/go-sqlite3`
  * `golang.org/x/crypto/ssh`

#### Installation

1.  **Clone the repository**:

    ```sh
    git clone https://github.com/nfcg/go-ssh-honeypot.git
    cd go-ssh-honeypot
    ```

2.  **Install dependencies**:

    ```sh
    go mod tidy
    ```

3.  **Build the application**:

    ```sh
    go build go-ssh-honeypot.go
    ```

#### Usage

Run the honeypot with the following command-line flags:

```sh
./go-ssh-honeypot [flags]
```

**Flags**:

  * `-l, --listen-ip`: Server listen IP address (default: `0.0.0.0`)
  * `-p, --listen-port`: Server listen port (default: `22`)
  * `-d, --database-loc`: SQLite database file location (default: `honeypot.db`)
  * `--log`: Path to log file (if empty, logs will be sent to `stdout`)

**Example**:
To run the honeypot on port 2222 and save data to `honeypot.db`:

```sh
./go-ssh-honeypot -p 2222 -d honeypot.db
```

To run on a privileged port (e.g., 22), you may need to use `sudo`:

```sh
sudo ./go-ssh-honeypot -p 22 -d honeypot.db
```

#### Database Schema

The honeypot stores all session information in a SQLite database file named `honeypot.db` by default. The database has a single table `ssh_sessions` with the following schema:

```sql
CREATE TABLE IF NOT EXISTS ssh_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    remote_addr TEXT NOT NULL,
    port INTEGER NOT NULL,
    client_version TEXT,
    supported_algorithms TEXT,
    public_key_fingerprint TEXT,
    username TEXT,
    password TEXT,
    auth_method TEXT,
    connection_error TEXT,
    auth_attempted BOOLEAN DEFAULT FALSE
);
```


#### Contributing

Contributions are welcome\! If you have suggestions for improvements or new features, please open an issue or submit a pull request.

