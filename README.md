# Quantum-Safe Password Generator

A secure password generator built with Go that creates cryptographically strong passwords resistant to quantum computing attacks. The application includes a simple web interface for generating and managing passwords.

## Features

- Generate strong, unique passwords with a minimum length of 12 characters
- Optional passphrase input for additional entropy
- Check if passwords have been leaked using the HaveIBeenPwned API (with option to disable)
- Automatically save generated passwords to text files
- Handles duplicate website/purpose names by adding timestamps to filenames
- Simple and intuitive web interface
- Quantum-resistant password generation techniques

## Requirements

- Go 1.16 or higher

## Installation

1. Clone this repository:
   ```
   git clone https://github.com/pillaiharish/Quantum-Safe-Password-Generator.git
   cd Quantum-Safe-Password-Generator
   ```

2. Install dependencies:
   ```
   go mod tidy
   ```

3. Build the application:
   ```
   go build -o password-generator ./cmd/server
   ```

## Usage

1. Run the application:
   ```
   ./password-generator
   ```

2. Open your web browser and navigate to:
   ```
   http://localhost:8080
   ```

3. Use the web interface to:
   - Enter a website/purpose for the password
   - Specify the desired password length (12-255 characters)
   - Optionally add a passphrase for additional entropy
   - Optionally disable the HaveIBeenPwned leak check
   - Generate and copy your secure password

4. Generated passwords are saved in the `passwords` directory with the website name as the filename.
   - If you generate multiple passwords for the same website/purpose, each file will be uniquely named by adding a timestamp (Unix epoch) to avoid overwriting previous passwords.
   - For example: `google.txt`, `google_1709123456.txt`, etc.

## Security Features

- Uses cryptographically secure random number generation
- Implements multiple sources of entropy for password generation
- Ensures password complexity with a mix of uppercase, lowercase, numbers, and special characters
- Checks passwords against known data breaches via HaveIBeenPwned API
- Option to disable leak checking for privacy or offline use
- Designed with quantum computing resistance in mind

## HaveIBeenPwned Integration

The application uses the HaveIBeenPwned API to check if generated passwords have been exposed in data breaches. This is done securely using the k-anonymity model:

1. The password is hashed using SHA-1
2. Only the first 5 characters of the hash are sent to the API
3. The API returns all matching hashes
4. The application checks locally if the full hash is in the returned list

This ensures that your actual password is never sent over the network. You can disable this check by selecting the "Disable HaveIBeenPwned check" option in the interface.

## Development

To run the application in development mode:

```
go run ./cmd/server/main.go
```

## License

MIT

## Disclaimer

This tool is provided for educational and personal use. While it implements strong security practices, no password system can guarantee absolute security. Always use additional security measures like two-factor authentication when available. 