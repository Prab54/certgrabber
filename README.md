# Certgrabber
This project searches for PFX certificates on the web then attempts to download and crack them, checking if they are valid too.
Validity consists of a pfx file that is:
- In date
- Has Private Key
- Has Certificate
  
The project consists of one python script [certgrabber](certgrabber.py) and one C file [testpfxpass](testpfxpass.c).
## How to Crack
1. Clone Repository
1. Compile [testpfxpass.c](testpfxpass.c):
```
$ gcc testpfxpass.c -o verifypfx -lcrypto -std=c99
```
3. Install Requirements:
```
$ pip install -r requirements.txt
```
4. Create a txt file called **api_key.txt** contating only the users api key from [GrayHatWarfare](https://buckets.grayhatwarfare.com) 
5. Run the [certgrabber.py](certgrabber.py) script:
```
$ python certgrabber.py
```
6. Visit [localhost:5000](http://localhost:5000)
7. Fill in form to meet your requirements

### [certgrabber.py](certgrabber.py)
The following python script uses the [GrayHatWarfare API](https://buckets.grayhatwarfare.com/api/v2/files) to search for pfx files within public buckets from the likes of AWS, Azure, Google Cloud Platform etc, and then downloads a maximum of 1000 pfx files. The script then uses threading to run the testpfxpass file with the paramater common_roots.txt to crack each pfx file. It then checks whether or not the certificates are valid.
### [testpfxpass.c](testpfxpass.c)
With a parameter containing a word dictionary, this c file tries to crack each pfx file using the given word dictionary, through a brute force method.
### [common_roots.txt](common_roots.txt)
Is a simple 4725 word dictionary used to crack pfx passwords. This file can be replaced with more complex word dictionaries.

