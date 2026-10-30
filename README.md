# Digital Forensics Log Analyzer

## About the Project

For this project, I created a Streamlit application that allows users to analyze login activity and identify potentially suspicious behavior. I wanted to make something cybersecurity specific, and this caught my eye. 

The goal is to make authentication logs easier to understand by using interactive charts, filters, and simple investigation features.

## Dataset

I used a sample CSV file called `authentication_logs.csv` that contains simulated login activity. This can be replaced by company logs.

The dataset includes:
- Timestamp of each login attempt
- Username
- IP address
- Login status (Success or Failed)

## Features

- Upload a CSV file containing login records
- Filter logins by username and status
- View interactive Plotly charts
- Identify IP addresses with repeated failed attempts
- Detect successful logins after multiple failures
- Download investigation findings as a CSV

## Tools Used

- Python
- Streamlit
- Pandas
- Plotly

## How to Run

1. Download or clone the GitHub repository.
2. Open the project folder in VS Code.
3. Install the required libraries using `pip install -r requirements.txt`.
4. Run the app using `streamlit run app.py`.
5. Open the local URL provided by Streamlit.

## How to Use

Use the sidebar to upload a CSV file or filter the existing data. The Overview tab shows general login statistics, while the Log Explorer displays individual records.

The Investigation tab allows users to adjust the number of failed attempts needed to flag an IP address and review the findings.

## AGILE Process

I divided the project into two sprints. The first focused on building the basic application, and the second focused on adding investigation features and improving the interface.

More details are included in `agile_process.md`.