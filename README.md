# password-strength-checker


## Project structure

password-strength-checker/
├── README.md
├── password_checker.py
├── test_password_checker.py
├── .gitignore
└── data/
    └── common_passwords.txt

## What I learned

*(Draft. Edit it so it is true to your experience.)*

- Modern guidance favors length and blocklists over complexity rules, and why:
  people respond to composition rules in predictable ways (`Password1!`).
- Splitting code into small pure functions made it easy to test without mocking
  the keyboard or the file system.
- Security tools have to avoid leaking the secret they check: no echo, no
  command-line argument, no logging, no quoting it back.
- Heuristics have blind spots, so I tested edge cases (empty input, 5,000
  characters, Unicode) and documented the limits.
