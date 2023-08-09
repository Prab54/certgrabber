# Certgrabber
This project searches for PFX certificates on the web then attempts to download and crack them, checking if they are valid too.
The project consists of one python script **certgrabber** and one C file **testpfxpass_linux**.
## [certgrabber.py](certgrabber.py)
The following python script uses the [GrayHatWarfare API](https://buckets.grayhatwarfare.com/api/v2/files) to search for pfx files within public buckets from the likes of AWS, Azure, Google Cloud Platform etc, and then downloads a maximum of 1000 pfx files. The script then uses threading to run the testpfxpass_linux.c file with the paramater common_roots.txt to crack each pfx file. It then checks whether or not the certificates are valid.
## [testpfxpass_linux.c](testpfxpass_linux.c)
With a parameter containing a word dictionary, this c file tries to crack each pfx file using the given word dictionary, through a brute force method.
## [common_roots.txt](common_roots.txt)
Is a simple 4725 word dictionary used to crack pfx passwords. This file can be replaced with more complex word dictionaries.
## How to Crack
To start, create a txt file called api_key.txt contating the users api key from [GrayHatWarfare](https://buckets.grayhatwarfare.com), then run the [certgrabber.py](certgrabber.py) script, providing the number of pfx files to download as a paramater.

