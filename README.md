# SecLog Analyzer

#### Video Demo: https://youtu.be/6JV-QvBUzhA

#### Description:

SecLog Analyzer is a Python program that I made to analyze simple security log files. I chose this project because I am interested in cybersecurity, and I wanted to use what I learned from CS50P to build something related to cybersecurity.

The idea is simple. A computer system can produce many login events, and looking through every log line manually can take time. My program reads the log file and looks at the login events. It counts the total number of events, the number of failed logins, and the number of successful logins. It also checks which IP addresses have many failed login attempts.

The log format I used for this project is:

    2026-10-01 10:21:03 LOGIN_FAILED 192.168.1.20

The first part is the date, the second is the time, the third is the event, and the last part is the IP address.

For detecting suspicious activity, I decided to use a simple rule. If the same IP address has 3 or more failed login attempts, the program reports it as suspicious and says that it could be possible brute-force activity. I know that three failed attempts alone does not prove that someone is attacking a system. I used this rule because I wanted to start with something simple that I understand and that I can improve later.

## How It Works

The program first asks the user for the name of a log file. It loads the lines from the file and then processes each line separately.

The `parse_log()` function splits each line into its different parts and stores the information in a dictionary. If a line does not have the expected format, the program skips it and gives a warning instead of stopping the whole program.

The `analyze_events()` function counts the total events, failed login attempts, and successful login attempts.

The `detect_suspicious_activity()` function counts failed login attempts for each IP address. It uses a threshold of 3 by default. IP addresses that reach the threshold are added to the suspicious activity results.

Finally, `generate_report()` takes the results and creates a report that is easier for a person to read.

## Files

- `project.py` - The main Python program. It contains the main function and the functions used for loading, parsing, analyzing, detecting, and reporting.
- `test_project.py` - Contains the pytest tests for the functions in `project.py`.
- `sample_logs.txt` - A small sample log file that I used to test the program.
- `requirements.txt` - Contains pytest, which is used for testing the project.

## Testing

I used pytest to test the important functions in the program. The tests check whether log lines are parsed correctly, invalid log lines raise an error, event statistics are calculated correctly, suspicious IP addresses are detected, the threshold works correctly, and the report contains the expected information.

I also tested the function that loads log files. At the end of testing, the project had 7 tests and all 7 passed.

## Design Decisions

I decided to use dictionaries for individual log events because the information has different fields such as date, time, event, and IP address. This makes it easier to access a specific value later.

I also used a dictionary to count failed attempts for each IP address. For example, if an IP appears several times with `LOGIN_FAILED`, its counter is increased each time.

I kept the project fairly simple because this is my first cybersecurity-related Python project. I did not want to add features that I could not properly explain. My plan is to improve it later by adding more types of suspicious activity and supporting more realistic log formats.

One thing I learned from this project is that cybersecurity tools do not always need to start as very complicated systems. Even a simple program that reads logs, finds patterns, and reports something unusual can be a starting point for security analysis.

## Future Improvements

There are several things I would like to add in the future. For example, I could add more detection rules, allow the user to change the failed-login threshold, add severity levels, support other types of security logs, and export the results to a file.

I could also eventually explore using machine learning to detect unusual behavior. However, I would first like to make the normal rule-based version stronger before adding machine learning.