# Android Malware Analysis Tool

## Description

This is a simple web-based tool built with Flask that allows users to upload APK files for malware analysis. The tool retrieves information about the analysis results and presents essential data to the user in a clear and concise format.

## Features

- Upload APK files for analysis.
- Retrieve and display analysis results.
- Present essential information to users:
  - Number of malicious detections.
  - Number of undetected scans.
  - Details of scan engines reporting malware (if any).

## Prerequisites

Before running the application, ensure you have the following:

- Python 3.x installed.
- Required Python packages (Flask, requests) installed. You can install them using `pip install flask requests`.

## Installation

1. Clone the repository to your local machine:

   ```bash
   git clone https://github.com/rakesharutla/android-apk-analysis.git
    ```

1. Navigate to the project directory:

    ```
    cd virustotal-malware-analysis
    ```

2. Create a virtual environment (optional but recommended):

    ```
    python -m venv venv
    ```

3. Activate the virtual environment:

- On Windows:
    ```
    venv\Scripts\activate
    ```
- On macOS and Linux:

    ```
    source venv/bin/activate
    ```

4. Install project dependencies:

    ```
    pip install -r requirements.txt
    ```

## Configuration

Before running the application, configure your VirusTotal API key:

1. Open app.py in your text editor.


## Usage

1. Start the Flask application:

    ```python app.py
    ```

2. Access the application in your web browser at http://localhost:5000.

3. Upload an APK file for analysis.

View the analysis results displayed in the user-friendly format.

## Contributing

Contributions are welcome! Feel free to open issues or submit pull requests to help improve this project.

## License
This project is licensed under the MIT License - see the LICENSE file for details.

*Note:* This tool is intended for educational and informational purposes. Be aware of the legal and ethical considerations when using it.
