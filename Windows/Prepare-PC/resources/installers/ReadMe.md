0-base.txt - the apps that will always be installed, regardless of other options picked.

1-example.txt - the apps that will only be installed with all Example Org computers

---

Inside each installer folder, is an "install.ps1", which contains the install script for the program, and only works through the main script (don't try to install via the standalone install.ps1 scripts)

---

The command line can select the app list either via the text file name (e.g. 1-example.txt), file name or you will be prompted to select.