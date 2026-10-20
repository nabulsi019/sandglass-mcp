# sandbox/

Files baked into the sandbox image (see `Dockerfile`).

- `decoy_home/` becomes `/home/sandglass`, the `$HOME` of the user the server
  runs as. It holds the files a credential-stealing server would look for
  first: `.aws/credentials`, `.ssh/id_rsa` and `.env`. **Every value is
  `FAKE_...`**: nothing here is, or looks like, a real secret
  (`tests/test_decoy_home.py` checks this). Rebuild the image after changing it.
