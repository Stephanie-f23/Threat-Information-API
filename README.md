# Threat-Information-API

## Description

This Python script is designed to fetch JSON data from URLs, extract details about cybersecurity vulnerabilities , and save these details to a file. This scipt is specifically tailored to interact with the CVE API that provides CVE information, and includes functionality for encoding search keywords for URLs, handling JSON data, and extracting comprehensive vulnerability details from the JSON structure.

## Installation

No additional installation is required for standard libraries.

## Requirements

Python 3
urllib and json libraries

## Usage

To run the script, execute the following command in the terminal:

python cve_details_extractor.py

When prompted, enter a keyword to search for specific CVE details.

## Function Descriptions

load_json_from_url(url): Loads JSON data from a specified API URL.
save_json_to_file(data, filename): Saves JSON data to a specified file "Data.JSON".
extract_vulnerability_details(data): Extracts and returns vulnerability details from JSON data.
main(keyword, page_number): Main function that orchestrates the loading, saving, and extraction of CVE details.
