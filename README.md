The GitHub Repository Scanner is a Python-based tool designed to analyze GitHub repositories for potentially malicious code patterns. It leverages static code analysis techniques to identify security vulnerabilities in various programming languages, including Python, JavaScript, PHP, Ruby, and more. The tool generates a comprehensive PDF report detailing the findings, including any detected malicious patterns, threat levels, and recommendations for improving code security.

Features
Malicious Code Detection: Scans repository files for known malicious patterns and practices.
Static Analysis Integration: Utilizes Bandit for Python code analysis and ESLint for JavaScript code analysis to provide detailed security insights.
PDF Report Generation: Creates a well-structured PDF report summarizing the scan results, including:
Repository details
Types of malicious code found
Threat level assessment
Static analysis results
Recommendations for secure coding practices
User -Friendly GUI: Provides a graphical user interface (GUI) for easy interaction and input of GitHub repository URLs.
Requirements
Python 3.x
Required Python packages:
tkinter (for GUI)
requests (for API calls)
reportlab (for PDF generation)
bandit (for Python static analysis)
eslint (for JavaScript static analysis)
