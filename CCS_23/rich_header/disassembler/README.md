# Windows PE Disassembler
IDAPython script to decompile Windows PE executables and to build the dataset of Windows Rich header

# Setup

Install IDA Pro with Python3 plugin support and add it's installation directory to your `PATH`. For example, add this to the end of your `~/.bashrc`:

```
export PATH="/opt/idapro-7.4/:$PATH"
```

Install python pip packages:
```
$ pip install -r requirements.txt
```

Clone [richprint](https://github.com/dishather/richprint)

Make a 