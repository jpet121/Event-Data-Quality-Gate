# Linux setup

Use a local Ubuntu 24.04 x86-64 filesystem. Use the profile included with the binary. Install the binary at the path in the profile. Run validation and verification as an ordinary user.

```bash
sudo install -d -m 0755 /opt/sesv/bin
sudo install -m 0755 target/release/sesv /opt/sesv/bin/sesv
sudo install -m 0644 qualification/apparmor.sesv-m1 /etc/apparmor.d/sesv-m1
sudo apparmor_parser -r /etc/apparmor.d/sesv-m1
sudo aa-status
```

Keep the run directory and its parent private. If a run stops before the outcome appears, run `/opt/sesv/bin/sesv verify --run DIRECTORY` on that directory. Use a fresh directory for a new attempt. When you change builds, use the policy for that build. The verifier can check a completed run from the previous build.
