import hashlib
import os
import requests
import json
import threading
import subprocess
import time
from tqdm import tqdm

global_cracks = []

def subprocess_thread(verifypfx_path, filepath, common_roots_file):
	result = subprocess.run([verifypfx_path, filepath, common_roots_file], stdout=subprocess.PIPE, text=True)
	if result.stdout.strip():
		global_cracks.append((filepath, result.stdout.strip()))
	return result

def run_verifypfx_on_file(filepath, verifypfx_path, common_roots_file):
	start_time = time.time()
	
	# Start the subprocess in a separate thread
	thread = threading.Thread(target=subprocess_thread, args=(verifypfx_path, filepath, common_roots_file))
	thread.start()

	# Create the progress bar
	pbar = tqdm(total=1, desc=f"Cracking {filepath} [Elapsed Time: 0s]")
	
	# While the subprocess thread is alive, update the progress bar's description
	while thread.is_alive():
		elapsed_time = int(time.time() - start_time)
		pbar.set_description(f"Cracking {filepath} [Elapsed Time: {elapsed_time}s]")
		time.sleep(1)

	pbar.update(1)
	pbar.close()
	thread.join()  # Ensure the subprocess thread completes






def download_file(filename, url):
	try:
		with open(filename, 'wb') as fout:
			response = requests.get(url, stream=True)
			total_size = int(response.headers.get('content-length', 0))
			pbar = tqdm(total=total_size, unit='B', unit_scale=True, desc=f"Downloading {filename}")
			
			for block in response.iter_content(4096):
				fout.write(block)
				pbar.update(len(block))
			
			pbar.close()
			
			# Verify if the file was completely downloaded
			if total_size != 0 and pbar.n != total_size:
				print("ERROR, something went wrong with the download.")
				os.remove(filename)
				return False

			return True

	except Exception as e:
		print(f"Error: {e}")
		if os.path.exists(filename):
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
		  "limit" : "50",
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
	hashes = set()
	# Add any files that already exist
	for (paths, names, files) in os.walk(directory):
		for file in files:
			hashes.add(file)

	for filename, url in catalogue.items():
		temp_filename = directory + filename
		download_result = download_file(temp_filename, url)
		
		if download_result:
			file_hash = hash_file(temp_filename)
			
			if file_hash in hashes:
				# This is a duplicate file, so remove it
				os.remove(temp_filename)
				print(f"Removed duplicate file: {temp_filename}")
			else:
				hashes.add(file_hash)
				# Rename the file to its hash
				new_filename = directory + file_hash
				os.rename(temp_filename, new_filename)
				print(f"Renamed {temp_filename} to {new_filename}")
	### 
	### CRACKING STAGE 
	###
	verifypfx_path = "./verifypfx.exe"
	common_roots_file = "./common_roots.txt"

	for hash_name in hashes:
		run_verifypfx_on_file(directory+hash_name, verifypfx_path, common_roots_file)



	# # Start 2 threads
	# threads = []
	# for hash_name in hashes:
	#	 thread = threading.Thread(target=run_verifypfx_on_file, args=(directory+hash_name, verifypfx_path, common_roots_file))
	#	 threads.append(thread)
	#	 thread.start()

	# # Wait for all threads to finish
	# for thread in threads:
	#	 thread.join()

	print("All tasks completed.\n\n")
	for item in global_cracks:
		print('\n', item[0], '\t', item[1])


### MAIN ### 
if __name__ == '__main__':
	main()
