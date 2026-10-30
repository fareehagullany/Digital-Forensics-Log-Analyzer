# AGILE Development Process

## Project: Digital Forensics Log Analyzer

### Project Goal

My goal was to build an interactive application that makes it easier to analyze authentication logs and recognize unusual login patterns.

I used an AGILE approach by splitting the project into two sprints so that I could build, test, and improve the application in smaller steps to ensure smooth delivery. 

### User Stories

- As a user, I want to upload a CSV file so I can analyze different login records.
- As a user, I want to filter login activity so I can focus on specific accounts or results.
- As a cybersecurity analyst, I want to see failed login attempts so I can recognize unusual patterns.
- As a user, I want to download the investigation results so I can review them later.

### Sprint 1: Building the Application

**Goal:** Get the basic Streamlit application working.

Tasks:
- Set up the Python environment
- Create the authentication log dataset
- Load CSV data using Pandas
- Add interactive filters
- Create Plotly charts
(A lot of this was refered from previous classwork)

During this sprint, I ran into an issue where the CSV file wasn't loading correctly. After checking the file, I realized the dataset needed to be added and saved properly. Once I fixed that, the application displayed the data correctly. 

### Sprint 2: Investigation Features and Design

**Goal:** Make the application more useful for investigating login activity.

Tasks:
- Add detection for repeated failed logins
- Identify successful logins after multiple failed attempts
- Add an adjustable threshold slider
- Allow users to download investigation results
- Improve the layout and apply a dark theme

I focused on keeping the application simple while making sure the interactive features were useful and easy to understand. 

### Testing

These are the main features I tested or planned to verify before submission:

| Feature | Expected Result |
|---|---|
| CSV loading | Displays authentication data |
| Dropdown filters | Updates the displayed results |
| Plotly charts | Displays the correct login statistics |
| Threshold slider | Updates flagged IP addresses |
| Investigation results | Identifies repeated failed attempts |
| Download button | Exports findings as CSV |

### Reflection

One thing I learned from this project was how important it is to test features as I build them instead of waiting until the end.

I also became more comfortable using Streamlit and Pandas to work with datasets. Dividing the project into smaller steps helped me stay organized and made it easier to figure out what was causing errors.

This project gave me a better understanding of how interactive data visualization can be used in cybersecurity investigations.