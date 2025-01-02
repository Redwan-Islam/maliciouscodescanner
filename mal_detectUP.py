import tkinter as tk
from tkinter import messagebox, scrolledtext
from tkinter import ttk
from datetime import datetime
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
import requests
import os
import re
import logging
import subprocess
import cProfile
import pstats
import io

# Set up logging
logging.basicConfig(filename='error_log.txt', level=logging.ERROR)

def contains_malicious_patterns(file_content):
    """Check for malicious patterns in the file content."""
    malicious_patterns = [
        r"exec\(", r"eval\(", r"os\.system\(", r"os\.popen\(", r"os\.remove\(", r"os\.rename\(", 
        r"os\.listdir\(", r"open\(", r"with open\(", r"import subprocess", r"import os", 
        r"import sys", r"import shutil", r"import base64", r"import requests", 
        r"import urllib", r"import json", r"import re", r"import threading", 
        r"import time", r"import random", r"import hashlib", r"import pickle", 
        r"import ctypes", r"import win32api", r"import win32com", r"import winreg", 
        r"import paramiko", r"import cryptography", r"import flask", r"import django", 
        r"import pymysql", r"import psycopg2", r"import sqlite3", r"import smtplib", 
        r"import email", r"import ftplib", r"import telnetlib", r"__import__\(", 
        r"globals\(", r"locals\(", r"setattr\(", r"getattr\(", r"delattr\(", r"dir\(", 
        r"call\(", r"Popen\(", r"run\(", r"send\(", r"recv\(", r"connect\(", r"bind\(", 
        r"listen\(", r"accept\(", r"sendto\(", r"recvfrom\(", r"execfile\(", r"evalfile\("
    ]
    
    for pattern in malicious_patterns:
        if re.search(pattern, file_content):
            return True
    return False


def wrap_text(text, max_length=50):
    """Wrap text to fit within a specified maximum length."""
    words = text.split()
    wrapped_lines = []
    current_line = ""

    for word in words:
        if len(current_line) + len(word) + 1 > max_length:
            wrapped_lines.append(current_line)
            current_line = word
        else:
            current_line += " " + word if current_line else word

    if current_line:
        wrapped_lines.append(current_line)

    return "\n".join(wrapped_lines)


def create_pdf_report(url, repo_owner, scan_time, malicious_types, file_details, threat_level, programming_languages, functionality_description, analysis_results):
    """Create a PDF report of the scan results."""
    pdf_filename = "Generic_report.pdf"
    
    # Check if the file already exists and create a new name if necessary
    counter = 1
    while os.path.exists(pdf_filename):
        pdf_filename = f"Generic_report_{counter}.pdf"
        counter += 1

    doc = SimpleDocTemplate(pdf_filename, pagesize=letter, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(name='TitleStyle', fontSize=18, textColor=colors.blue, spaceAfter=6)
    body_style = ParagraphStyle(name='BodyStyle', fontSize=12, textColor=colors.black, spaceAfter=6)

    content = []

    content.append(Paragraph("Generic Report for GitHub Repository Scan", title_style))
    content.append(Spacer(1, 12))  # Space after title

    # Create a table for the report summary
    data = [
        ["Field", "Details"],
        ["Repository Owner", wrap_text(repo_owner)],
        ["Repository Link", wrap_text(url)],
        ["Scan Time", wrap_text(scan_time)],
        ["Types of Malicious Code Found", wrap_text(", ".join(malicious_types) if malicious_types else "None")],
        ["File Details", wrap_text("\n".join(file_details) if file_details else "None")],
        ["Threat Level", wrap_text(threat_level)],
        ["Static Analysis Results", wrap_text(analysis_results)],
        ["How to Prevent This", wrap_text("1. Code Review: Regularly review code for suspicious patterns and practices.\n"
                                           "2. Static Analysis Tools: Use tools that can analyze code for potential vulnerabilities.\n"
                                           "3. Limit Permissions: Ensure that the code runs with the least privileges necessary.\n"
                                           "4. Educate Developers: Train developers on secure coding practices and common vulnerabilities.")],
        ["Abstract of the Code Repository", wrap_text(f"The repository contains various scripts and modules primarily written in {programming_languages}.\n"
                                                      f"The code is designed to {functionality_description}. However, it includes patterns that may lead to security vulnerabilities.")],
    ]

    # Create the table with specified column widths
    table = Table(data, colWidths=[150, 300])  # Adjust widths as necessary
    table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.blue),  # Header background color
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),  # Header text color
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),  # Align text to the left
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),  # Header font
        ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),  # Body font
        ('SIZE ', (0, 0), (-1, 0), 12),  # Header font size
        ('SIZE', (0, 1), (-1, -1), 10),  # Body font size
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),  # Padding for header
        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),  # Body background color
        ('GRID', (0, 0), (-1, -1), 1, colors.black),  # Grid lines
    ]))

    content.append(table)
    content.append(Spacer(1, 12))  # Space after table

    # Add credit statement
    credit_statement = Paragraph("Report and coding done by ~~", body_style)
    content.append(Spacer(1, 12))  # Space before credit
    content.append(credit_statement)

    doc.build(content)
    
    # Alert message for PDF creation
    return pdf_filename, "PDF report created successfully!"


def scan_repository(url):
    """Scan the specified GitHub repository for malicious code."""
    pr = cProfile.Profile()
    pr.enable()  # Start profiling

    if not url.startswith("https://github.com/"):
        return "Invalid GitHub URL. Please enter a valid repository link.", None

    repo_name = url.split("github.com/")[-1]
    repo_owner = repo_name.split("/")[0]
    api_url = f"https://api.github.com/repos/{repo_name}/git/trees/main?recursive=1"
    languages_url = f"https://api.github.com/repos/{repo_name}/languages"

    try:
        response = requests.get(api_url)
        response.raise_for_status()
        contents = response.json().get('tree', [])

        # Fetch programming languages used in the repository
        languages_response = requests.get(languages_url)
        languages_response.raise_for_status()
        programming_languages = ", ".join(languages_response.json().keys())

        malicious_types = []
        file_details = []
        threat_level = "Low"  # Default threat level
        analysis_results = "Check Error Log File "

        for item in contents:
            if item['type'] == 'blob' and item['path'].endswith(('.py', '.js', '.php', '.rb', '.sh', '.txt', '.html')):
                file_content = requests.get(item['url']).text
                file_name = item['path']
                line_number = 0

                # Check for malicious patterns
                for line in file_content.splitlines():
                    line_number += 1
                    if contains_malicious_patterns(line):
                        if file_name not in malicious_types:
                            malicious_types.append(file_name)
                            file_details.append(f"{file_name} (Line {line_number})")
                            threat_level = "High"  # Update threat level if malicious code is found

        # Run Bandit for Python files
        if any(file.endswith('.py') for file in file_details):
            bandit_results = subprocess.run(['bandit', '-r', repo_name], capture_output=True, text=True)
            analysis_results += f"\nBandit Results:\n{bandit_results.stdout}"

        # Run ESLint for JavaScript files
        if any(file.endswith('.js') for file in file_details):
            eslint_results = subprocess.run(['eslint', repo_name], capture_output=True, text=True)
            analysis_results += f"\nESLint Results:\n{eslint_results.stdout}"

        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        functionality_description = "perform various data processing tasks"  # Example description
        pdf_filename, pdf_alert = create_pdf_report(url, repo_owner, scan_time, malicious_types, "\n".join(file_details), threat_level, programming_languages, functionality_description, analysis_results)

        # Alert messages
        if malicious_types:
            return "Alert: Malicious code found!", pdf_alert
        else:
            return "Alert: No malicious code found.", pdf_alert
        
    except requests.exceptions.HTTPError as http_err:
        logging.error(f"HTTP error occurred: {http_err}")
        return f"HTTP error occurred: {http_err}", None
    except Exception as e:
        logging.error(f"An error occurred: {e}")
        return f"An error occurred: {e}", None
    finally:
        pr.disable()  # Stop profiling
        s = io.StringIO()
        sortby = pstats.SortKey.CUMULATIVE
        ps = pstats.Stats(pr, stream=s).sort_stats(sortby)
        ps.print_stats()
        logging.info(s.getvalue())  # Log profiling results


def scan_repository_gui():
    """Handle the GUI interaction for scanning a repository."""
    url = url_entry.get()
    if not url:
        messagebox.showwarning("Input Error", "Please enter a GitHub repository URL.")
        return
    
    # Call the scan_repository function
    alert, pdf_alert = scan_repository(url)
    messagebox.showinfo("Scan Result", alert)
    if pdf_alert:
        messagebox.showinfo("PDF Report", pdf_alert)


# Create the main window
root = tk.Tk()
root.title("GitHub Repository Scanner")
root.geometry("600x400")
root.configure(bg="#f0f0f0")

# Create a stylish frame
frame = ttk.Frame(root, padding="20")
frame.pack(fill=tk.BOTH, expand=True)

# Title label
title_label = ttk.Label(frame, text="GitHub Repository Scanner", font=("Helvetica", 16, "bold"), foreground="#007ACC")
title_label.pack(pady=(0, 10))

# URL entry
url_label = ttk.Label(frame, text="Enter GitHub Repository URL:", font=("Helvetica", 12))
url_label.pack(anchor=tk.W, pady=(0, 10))  # Added space after label
url_entry = ttk.Entry(frame, width=50, font=("Helvetica", 12))
url_entry.pack(pady=(0, 10))

# Scan button with color
scan_button = ttk.Button(frame, text="Scan Repository", command=scan_repository_gui)
scan_button.pack(pady=(0, 20))
scan_button.configure(style="TButton")  # Apply style to button

# Create a style for the button
style = ttk.Style()
style.configure("TButton", background="blue", foreground="black", font=("Helvetica", 12, "bold"))
style.map("TButton", background=[("active", "#005FA3")])  # Change color on hover

# Footer
footer_label = ttk.Label(frame, text="", font=("Helvetica", 10), foreground="#888888")
footer_label.pack(side=tk.BOTTOM, pady=(10, 0))

# Start the GUI event loop
root.mainloop()