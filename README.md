# FileUploadFuzzer
Simple file upload fuzzer for FireFox-exported curl statements, including web shell verification.

Placeholders in file `post_curl.txt`:
- `TARGET`: target URL
- `HEADER`: placeholder to fuzz different content types
- `EXTENSION`: placeholder to fuzz different file extensions
- `SCRIPT`: placeholder for code placed in file
