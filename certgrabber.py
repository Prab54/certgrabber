import requests
import json
import os
import random
import pprint

def download_file(filename, url):
  """
  Download an URL to a file
  """
  print("Downloading " + url + "\nSaving to" + filename)
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
    return False


def download_if_not_exists(filename, url):
  """
  Download a URL to a file if the file
  does not exist already.
  Returns
  -------
  True if the file was downloaded,
  False if it already existed
  """
  if not os.path.exists(filename):
    downloaded = download_file(filename, url)
    return {"Duplicated": False, "Downloaded" : downloaded}
  return {"Duplicated": True, "Downloaded" : False}


class certApiSearch:
  def __init__(self):
    var= "1"

  def grayhatwarfare(self,api_key='',search_terms_dict={}):
    self.BASE_URL = "https://buckets.grayhatwarfare.com/api/v2/files"
    self.api_key = api_key
    self.search_terms_dict = search_terms_dict
    self.search_defaults = {
      "limit" : "3",
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
    #print(self.get_query)
    # Remove trailing &
    self.get_query = self.get_query[:-1]
    search = requests.get(self.get_query,headers = {'Authorization' : f'Bearer {api_key}'}) 
    # Load response as json object
    search_json = json.loads(search.text)
    #print(json.dumps(search_json, indent = 1))
    return search_json

  def catalogue_search_for_download(self, search_json):
    self.search_json = search_json
    catalogue = {}
    for x in search_json['files']:
      #print(x['filename'])
      if catalogue.get(x['filename']) is None:
        new_entry = {
          x['filename'] : x['url']
        }
        catalogue.update(new_entry)
        #print("Item added")
    print("Number of unique name certs = " + str(len(catalogue)))
      #print(catalogue)
      #print(json.dumps(x, indent = 1))
#    print(json.dumps(search_json['files'][1], indent = 1))
    return catalogue


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
search = test.grayhatwarfare(api_key,search_terms_dict)
print("Search record limit = " + str(search['query']['limit']))
print("Results found = " + str(search['meta']['results']))

catalogue = test.catalogue_search_for_download(search)

for filename, url in catalogue.items():
  print("Should I download: " + url)
  download_result = download_if_not_exists(directory + filename,url) 
  print(download_result)
#print(random_file)
#print(url)


#print(catalogue)
