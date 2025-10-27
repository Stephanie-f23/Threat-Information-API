import json
import urllib.parse
import urllib.request

#Loads JSON File
def load_json_from_url(url):
    try:
        with urllib.request.urlopen(url) as response:
            data = json.load(response)
        return data
    except Exception as e:
        print("Error loading JSON from URL:", e)
        return None

#Exports URL info to JSON file
def save_json_to_file(data, filename):
    try:
        with open(filename, 'w') as file:
            json.dump(data, file, indent=4)
        print("JSON data saved to", filename)
    except Exception as e:
        print("Error saving JSON to file:", e)

def extract_vulnerability_details(data):
    results = []
    vulnerabilities = data.get("vulnerabilities", [])
    
    for vulnerability in vulnerabilities:
        cve = vulnerability.get("cve", {})
        sourceIdentifier = cve.get("sourceIdentifier", "N/A")
        id = cve.get("id", "N/A")
        published = cve.get("published", "N/A")
        lastModified = cve.get("lastModified", "N/A")
        vulnStatus = cve.get("vulnStatus", "N/A")
        descriptions = cve.get("descriptions", [])
        
        urls = [ref.get("url", "N/A") for ref in cve.get("references", [])]
        cvssMetrics = cve.get("metrics", {}).get("cvssMetricV2", [])
        
        accessVectors = []
        exploitabilityScores = []
        impactScores = []
        baseScores = []

        for metric in cvssMetrics:
            cvssData = metric.get("cvssData", {})
            accessVectors.append(cvssData.get("accessVector", "N/A"))
            exploitabilityScores.append(cvssData.get("exploitabilityScore", "N/A"))
            impactScores.append(cvssData.get("impactScore", "N/A"))
            baseScores.append(cvssData.get("baseScore", "N/A"))
        
        for desc in descriptions:
            lang = desc.get("lang", "N/A")
            value = desc.get("value", "N/A")
            
            results.append({
                "sourceIdentifier": sourceIdentifier,
                "id": id,
                "published": published,
                "lastModified": lastModified,
                "vulnStatus": vulnStatus,
                "description": {"lang": lang, "value": value},
                "urls": urls,
                "accessVectors": accessVectors,
                "exploitabilityScores": exploitabilityScores,
                "impactScores": impactScores,
                "baseScores": baseScores
            })
    return results

def main(keyword, page_number=1, results_per_page=10):
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0" #Base URL
    filename = "data.json"
    keyword_encoded = urllib.parse.quote(keyword)  # Properly encoding the keyword for URL usage
    
    startIndex = (page_number - 1) * results_per_page 
    
    #Loading the infomation from specified url to JSON
    json_data = load_json_from_url(f"{url}?keywordSearch={keyword_encoded}&startIndex={startIndex}&resultsPerPage={results_per_page}")
    if json_data:
        save_json_to_file(json_data, filename)
        
        vulnerability_details = extract_vulnerability_details(json_data)

        #Displaying the details of the Cyber Security Infomrmation
        for detail in vulnerability_details:
            print("Source of Info:", detail["sourceIdentifier"])
            print("CVE ID:", detail["id"])
            print("Date info published:", detail["published"])
            print("Last known data entry:", detail["lastModified"])
            print("Vulnerability Status:", detail["vulnStatus"])
            print("Security Details:", detail["description"]["value"])
            print("URL References:", ', '.join(detail["urls"]) if detail["urls"] else "No URLs available")
            print("Access Vector:", detail["accessVectors"][0] if detail["accessVectors"] else "No Access Vector available")
            print("Impact Score:", detail["impactScores"][0] if detail["impactScores"] else "No Impact Score available")
            print("Base Score:", detail["baseScores"][0] if detail["baseScores"] else "No Base Score available")
            print("Exploitability Score:", detail["exploitabilityScores"][0] if detail["exploitabilityScores"] else "No Exploitability Score available")
            print("")
            print("")
            print("")

if __name__ == "__main__":
    keyword = input("Please enter keyword: ")
    page_number = int(input("Enter page number: "))
    main(keyword, page_number)
