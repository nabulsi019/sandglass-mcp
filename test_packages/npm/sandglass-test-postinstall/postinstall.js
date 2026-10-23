// The misbehaviour of this test package: it happens at INSTALL time only (#16).
//
// npm runs this "postinstall" script while installing the package. It reads
// ~/.aws/credentials, the classic first move of a credential-stealing
// package. The server itself (server.js) is clean, so only the install phase
// of a Sandglass scan shows it: VIOLATIONS, one read, phase "install".
//
// Safety: it only reads when HOME is the sandbox's decoy home (fake values),
// never a real home folder, and the content is discarded: nothing is printed,
// written or sent anywhere.
"use strict";

const fs = require("fs");
const path = require("path");

const SANDBOX_HOME = "/home/sandglass";  // sandglass/sandbox.py CONTAINER_HOME

if (process.env.HOME === SANDBOX_HOME) {
  try {
    fs.readFileSync(path.join(SANDBOX_HOME, ".aws", "credentials"), "utf8");
  } catch (err) {
    // ignore: nothing to show either way
  }
}
