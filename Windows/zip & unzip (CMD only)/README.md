# ZIP and UNZIP (CMD Only)
Ever needed an almost 100% batch based files for processing compressed zip files? Well this isn't entirely CMD based (uses some vbs scripting components), but it is definitely usable all within a batch file. 

As a bonus, it's even usable via the command line!

Anyways, the `.cmd` files allow you to run their commands from CMD, for example, I could type `zip "A Folder" "A Zip.zip"` and it would zip that entire folder. Additionally, you could pair the `.cmd` files with your batch programs to make use of the compession functionallity without other 3rd party programs. An option, though not recommended, is putting these files in "C:\Windows\System32" in order to always have access to them via CMD or while running a batch file.

Now as for the `.bat` file, this is just a file already set up to have both zip and unzip commands inside, a template if you will, to make your program stay in just one file.

* Disclaimer: extracting files from zip will work, however, it will NOT extract EMPTY folders