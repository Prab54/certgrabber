import hashlib
import os
import shutil
import requests
import json
import threading
import subprocess
from datetime import datetime
from tqdm import tqdm
import time
from flask import Flask, render_template, request, flash, redirect, url_for, jsonify, session

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization.pkcs12 import load_key_and_certificates

with open("commonPasswords.json", 'r') as json_file:
        commonPasswords = json.load(json_file)
	
with open('cracked_files.json', 'r') as json_file:
	file_pwd_pairs = json.load(json_file)

app = Flask(__name__, template_folder='templates', static_folder='static')

@app.route('/')
def index():
	return render_template('index.html')

@app.route('/run', methods=['GET', 'POST'])
def run():
	if request.method == 'POST':
		apikey = request.form.get('apikey')
		limit = request.form.get('limit')
		crack = request.form.get('crack')
		dict = request.form.get('dict')
		search_term = request.form.get('searchterm')

		number_of_unique_files = 0
		number_of_successful_cracks = 0
		number_of_good_results = 0
		global number_of_invalid
		global number_of_out_of_date
		global number_of_no_private_key
		global number_of_no_cert
		global number_of_self_signed
		global multiple_issues_count


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

		isExist = os.path.exists('password_cracked_certs/')
		if not isExist:
			os.makedirs('password_cracked_certs/')
			print("Directory password_cracked_certs/ created")

		try:
			with open("api_key.txt", "r") as f:
				api_key = f.readline().strip()  # read the first line and strip any leading/trailing whitespaces
			if not api_key:  # If the API key is empty
				flash("API key is empty in the file")
		except Exception as e:
			print(e)  # This will print the error message for debugging purposes
			if not apikey:  # If the apikey from the form is None or empty
				flash("No API key supplied, and no api_key.txt file!", 'danger')
				return redirect('/')
			else:
				api_key = apikey

		search_terms_dict = {
			"extensions" : "pfx",
			"keywords" : f"{search_term}"
		}

		current_passwords = {}
		current_passwords.clear()
		test = certApiSearch(limit)
		search = test.grayhatwarfare(api_key, search_terms_dict)
		print("Search record limit = " + str(search['query']['limit']))
		print("Results found = " + str(search['meta']['results']))

		catalogue= test.catalogue_search_for_download(search)

		progress_bar = tqdm(total=len(catalogue), desc="Downloading PFX files", position=0, leave=True)

		# Maintain a set to keep track of hashes
		all_hashes = set()
		# Add any files that already exist
		for (paths, names, files) in os.walk(directory):
			for file in files:
				all_hashes.add(file)

		for item in catalogue:
			filename = item['filename']
			url = item['url']
			temp_filename = directory + filename
			download_result = download_file(temp_filename, url)
			progress_bar.update(1)
			if download_result:
				file_hash = hash_file(temp_filename)
				if file_hash in all_hashes:
					# This is a duplicate file, so remove it
					os.remove(temp_filename)
					#print(f"Removed duplicate file: {temp_filename}")
				else:
					all_hashes.add(file_hash)
					# Rename the file to its hash
					new_filename = directory + file_hash
					os.rename(temp_filename, new_filename)
					#print(f"Renamed {temp_filename} to {new_filename}")

		progress_bar.close()
		number_of_unique_files = number_of_unique_files + len(all_hashes)
		print("nou =", number_of_unique_files)

		time.sleep(2)
		### 
		### CRACKING STAGE 
		###

		verifypfx_path = "./verifypfx"

		if dict == '1':
			dictionary = "./common_roots.txt"
			dict_length = '4727'
		elif dict == '2': 
			dictionary = "./rockyouSlim.txt"
			dict_length = '30000'
		else:
			dictionary = "./common_roots.txt"
			dict_length = '4727'

		if crack != None:
			print("\nMoving on to cracking. . .\n")
			progress_bar_crack = tqdm(total=len(all_hashes), desc="Cracking PFX files (creating threads)", position=0, leave=True)

			files_list = os.listdir('password_cracked_certs/')
			# Filter out directories, keeping only files
			files_list = [file for file in files_list if os.path.isfile(os.path.join('password_cracked_certs/', file))]
			list_file = [name[:-4]   for name in files_list]

			# Start 2 threads
			threads = []
			for hash_name in all_hashes:
				if hash_name not in list_file:
					thread = threading.Thread(target=run_verifypfx_on_file, args=(directory+hash_name, verifypfx_path, dictionary, dict_length))
					threads.append(thread)
					thread.start()
					progress_bar_crack.update(0.1)
				else:
					cracked_hashes.append(('dls/' + hash_name, file_pwd_pairs[hash_name]))
					progress_bar_crack.update(1)
			with open('cracked_files.json', 'w') as json_file:
				json.dump(file_pwd_pairs, json_file, indent=4)
				

			progress_bar_crack.set_description("Cracking PFX files (all threads created, cracking...)")

			# Wait for all threads to finish
			for thread in threads:
				thread.join()
				progress_bar_crack.update(0.9)

			progress_bar_crack.close()

			print(f"\n\nAll tasks completed!\n\nCracked Hashes ({len(cracked_hashes)}):\n\tName\tPassword")
			for item in cracked_hashes:
				print('\n', item[0], '\t', item[1])
			print('\n\n')
			number_of_successful_cracks = number_of_successful_cracks + len(cracked_hashes)
			
			### 
			### Verification stage
			###
			
			# Read names of all files and directories inside 'password_cracked_certs/' into a list
			
			for item in cracked_hashes:
				if cracked_hashes[0] == item:
					verified_hashes.clear()
					number_of_invalid = 0
					number_of_out_of_date = 0
					number_of_no_private_key = 0
					number_of_no_cert = 0
					number_of_self_signed = 0
					multiple_issues_count = 0

				file_hash = item[0]
				if item[1] == 'PKCS12 has no password.':
					pfx_password="No Password"
				else:
					pfx_password = item[1]

				if pfx_password not in commonPasswords:
					commonPasswords[pfx_password] = 1
				else:
					if file_hash[4:] not in list_file:
						commonPasswords[pfx_password] +=1
				if file_hash[4:] not in list_file:
					if pfx_password not in current_passwords:
						current_passwords[pfx_password] = 1
					else:
						current_passwords[pfx_password] +=1

				if check_pfx_contents(file_hash, pfx_password):
					print(f'{file_hash} is GOOD!\n')
					verified_hashes.append((file_hash, item[1]))
					shutil.copy(file_hash, 'cracked_certs/'+file_hash[4:]+'.pfx')
				else:
					print(f'{file_hash} is BAD!\n')
				shutil.copy(file_hash, 'password_cracked_certs/'+file_hash[4:]+'.pfx')

			with open("commonPasswords.json", 'w') as json_file:
				json.dump(commonPasswords, json_file, indent=4)

			number_of_good_results = len(verified_hashes)
			print(f"\n\nVerified Hashes ({len(verified_hashes)}):\n\tName\t\t\t\t\t\tPassword")
			for item in verified_hashes:
				print('\n', item[0], '\t', item[1])

			curr_pass_len = len(current_passwords)
			print(f"\n{len(cracked_hashes)} ====>>> {len(verified_hashes)}\n")

	return render_template('results.html', number_of_successful_cracks=number_of_successful_cracks, 
			number_of_unique_files=number_of_unique_files, 
			number_of_good_results=number_of_good_results,
			number_of_invalid=number_of_invalid,
			number_of_out_of_date=number_of_out_of_date,
			number_of_no_private_key=number_of_no_private_key,
			number_of_no_cert=number_of_no_cert,
			number_of_self_signed=number_of_self_signed,
			multiple_issues_count=multiple_issues_count,
			limit=limit,
			commonPasswords=commonPasswords,
			current_passwords=current_passwords,
			curr_pass_len=curr_pass_len,
			cracked_hashes=cracked_hashes
			)





cracked_hashes = []
verified_hashes = []

# WEB INTERFACE TRACKING VARS
number_of_unique_files = 0
number_of_successful_cracks = 0
number_of_invalid = 0
number_of_out_of_date = 0
number_of_no_private_key = 0
number_of_no_cert = 0
number_of_self_signed = 0
number_of_good_results = 0
multiple_issues_count = 0

def run_verifypfx_on_file(filepath, verifypfx_path, common_roots_file, dict_length):
	#print(f"Attempting to crack {filepath}.")
	result = subprocess.run([verifypfx_path, filepath, common_roots_file, dict_length], stdout=subprocess.PIPE, text=True)
	#print(f"File {filepath} processed.")
	if result.stdout.strip():
		if (filepath, result.stdout.strip()) not in cracked_hashes:
			password = result.stdout.strip()
			cracked_hashes.append((filepath, password))
			file_pwd_pairs[filepath] = password



def download_file(filename, url):
	"""Download an URL to a file"""
	try:
		with open(filename, 'wb') as fout:
			response = requests.get(url, stream=True)
			response.raise_for_status()
			for block in response.iter_content(1024):
				fout.write(block)
		return True

	except requests.RequestException as e:
		print(f"Error downloading {url}. Error: {e}")
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
	def __init__(self, limit):
		self.var = "1"
		self.limit = limit

	def grayhatwarfare(self, api_key='', search_terms_dict={}):
		self.BASE_URL = "https://buckets.grayhatwarfare.com/api/v2/files"
		self.api_key = api_key
		self.search_terms_dict = search_terms_dict
		self.search_defaults = {
		  "limit" : str(self.limit),
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
		catalogue = []
	
		for x in search_json['files']:
			catalogue.append({'filename': x['filename'], 'url': x['url']})
		
		print("Number of files = " + str(len(catalogue)))
		return catalogue



# Check cert in date
def is_certificate_indate(cert):
	current_time = datetime.utcnow()
	return cert.not_valid_before <= current_time <= cert.not_valid_after

# Check the PFX file has both a private key and at least one certificate
def check_pfx_contents(pfx_path, pfx_password):
	global number_of_invalid
	global number_of_out_of_date
	global number_of_no_private_key
	global number_of_no_cert
	global number_of_self_signed
	global multiple_issues_count
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
		print("\n\t\tREADING FALIURE")
		number_of_invalid = number_of_invalid + 1
		return False

	# Initialize the variable to track issues
	multiple_issues = []
	multiple_issues.clear()
	returnVal = True

	# Check for private key
	if not private_key:
		multiple_issues.append("no_private_key")
		returnVal = False
		# Check for main certificate
	if not certificate:
		multiple_issues.append("no_cert")
		returnVal = False
	
	# Check if it is in date
	if not is_certificate_indate(certificate):
		multiple_issues.append("out_of_date")
		returnVal = False
	
	# Check if it is self-signed (no additional certs)
	if certificate.issuer == certificate.subject:
		multiple_issues.append("self_signed")
		returnVal = False

	if len(multiple_issues) > 1:
		multiple_issues_count += 1
	else:
		if "no_private_key" in multiple_issues:
			number_of_no_private_key += 1
		elif "no_cert" in multiple_issues:
			number_of_no_cert += 1
		elif "out_of_date" in multiple_issues:
			number_of_out_of_date += 1
		elif "self_signed" in multiple_issues:
			number_of_self_signed += 1


	if returnVal == False:
		return False

	with open(f"cracked_certs/{pfx_path[4:9]}_report.txt", 'w') as f:
		f.write(f"Name: {pfx_path[4:]}.pfx\nPassword: {pfx_password}\n\nPrivate Key:\n{private_key}\n\nCertificate(s):\n{certificate}\n{additional_certificates}\n\nDates:\n{certificate.not_valid_before} to {certificate.not_valid_after}")
	
	return returnVal

  
		


app.secret_key = "supersecretkey"



if __name__ == "__main__":
	app.config['SESSION_TYPE'] = 'filesystem'
	app.run(host='0.0.0.0', threaded=True, debug=True) # DEBUG

