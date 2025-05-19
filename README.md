# safedotenv

Securely store .env files using AES encryption on Github repositories for convenience.

Sometimes, you should not store tokens on Github, but you have private repositories, personal work, and you want a easy way to store tokens while keeping them somewhat secure.

To get started, create your .env and put your tokens.

Then, run
```
./safedotenv --encrypt
```

This will create a .env-encrypted. You should not track tokens, but if it's not critical, you can afford to track the encrypted version.
