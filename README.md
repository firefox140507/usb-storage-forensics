USB STORAGE FORENSICS AND FILE INTEGRITY ANALYZER

Files:
- usb_forensics_analyzer.py : runnable Python desktop application
- USB_Forensics_Project_Report.docx : editable report draft

Run on Windows:
1. Install Python 3 from https://www.python.org/downloads/windows/
2. During installation, enable "Add python.exe to PATH".
3. Open Command Prompt in this folder.
4. Run: python usb_forensics_analyzer.py

No third-party Python packages are required; the application uses Python standard-library modules.

Recommended quick test:
1. Create a folder named test_evidence.
2. Put a few files in it.
3. Copy one file and rename the copy to create a duplicate-content test.
4. Run the app and scan test_evidence.
5. Click Show Duplicates and Export CSV Report.
6. Click Verify Current Files; then modify one file and verify again to see CHANGED.

For formal forensic work, use an appropriate write blocker and a verified evidence image/copy. This application is educational and is not a write blocker or a complete forensic acquisition tool.
