#! \main\Scripts\python.exe

# type: ignore
from flask import Flask, render_template, request, jsonify, session, Response
import os
import requests
import json
import time
import config
import markdown
from flask_session import Session
import re
import subprocess
from datetime import datetime
from src import deepFake, prevention
import ast
from src.redis_client import RedisClient


UPLOAD_FOLDER = config.UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app = Flask(__name__)
app.config['SESSION_TYPE'] = 'redis'
app.config['SESSION_REDIS'] = config.REDIS_CLIENT
app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = config.SECRET_KEY

redis_client = RedisClient()
Session(app)
ALLOWED_IMAGE_EXTENSIONS = {'.png', '.jpeg', '.jpg'}
RESTRICTED_FILE_EXTENSIONS = {'.exe', '.msi', '.bat', '.jar', '.py'}

def show_alert(message, status_code=400):
    """Return a JSON response with an alert message."""
    return jsonify({"alert": message}), status_code


def validate_file_extension(filename, allowed_extensions):
    """Check if the file extension is allowed."""
    return os.path.splitext(filename)[1].lower() in allowed_extensions


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/upload', methods=['POST'])
def upload_files():
    try:
        if 'files' not in request.files:
            return show_alert("No file provided.")
        file = request.files['files']
        if file.filename == '':
            return show_alert("No file selected.")

        if validate_file_extension(file.filename, RESTRICTED_FILE_EXTENSIONS):
            return show_alert("Executable files are not allowed.")

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        return jsonify({"uploaded_file": file_path, "filename": file.filename})
    except Exception as e:
        return show_alert(f"Error uploading file: {str(e)}", 500)


@app.route('/analyze', methods=['POST'])
def analyze_data():
    try:
        data = request.json
        feature = data.get('feature')
        input_data = data.get('inputData')
        subcategories = data.get('subcategories')
        user_id = request.remote_addr
        if not feature or not input_data:
            return show_alert("Missing feature or input data.")
        session['cache_info'] = {
            'feature': feature,
            'inputData': input_data,
        }
        cache_key = f"analysis:{user_id}:{feature}:{input_data}"
        cached_result = redis_client.get_cached_result(cache_key)
        cached_result = json.dumps(ast.literal_eval(cached_result), indent = 2) if cached_result else None
        if cached_result:
            print(cached_result)
            print(type(json.loads(cached_result)))
            session['analysis_result'] = json.loads(cached_result)
            return jsonify({"redirect": "/report"})

        info = {
            'detection_time': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC'),
            'feature': feature
        }
        if feature == 'File Analysis':
            info["subcategories"] = subcategories
            if not os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], input_data)):
                return show_alert("Uploaded file not found.")

            if validate_file_extension(input_data, RESTRICTED_FILE_EXTENSIONS):
                return show_alert("Executable files are not allowed.")

            file_path = os.path.join(app.config['UPLOAD_FOLDER'], input_data)

            if subcategories == 'Deep Fake':
                if not validate_file_extension(input_data, ALLOWED_IMAGE_EXTENSIONS):
                    return show_alert("Only image files (.png, .jpeg, .jpg) are allowed for deepfake analysis.")
                result = deepFake.deepfake_analysis(file_path)
                print(result)
                if result['Label'].lower() == "fake":
                    result['severity'] = "medium" 
                else:
                    result['severity'] = "LOW"
                result['prevention_required'] = "No"
            elif subcategories == 'Malware':
                result = getSummary(get_malware(file_path))
                result = json.loads(result)
            else:
                return show_alert("Invalid subcategory for File Analysis.")

        elif feature == 'URL Check':
            result = getSummary(check_phishing_url(input_data))
            result = json.loads(result)

        elif feature == 'Text Analysis':
            info["subcategories"] = subcategories
            if subcategories == 'Sentiment Analysis':
                result = run_agent(input_data, 'sentiment')
                result = json.loads(result)
                if str(result['is_fake']).lower() == "true":
                    result['severity'] = "medium" 
                else:
                    result['severity'] = "LOW"
                
                result['prevention_required'] = "No"

            elif subcategories == 'Fake News Detection':
                result = run_agent(input_data, 'fake_news')
                result = json.loads(result)
                
                result['prevention_required'] = "No"
                result['severity'] = "medium" 

            else:
                return show_alert("Invalid subcategory for Text Analysis.")
            
            if result.status != "success":
                return show_alert(f"Error, {result.error_message}")
            
        elif feature == 'Breach Analysis':
            result = getSummary(check_email(input_data))
            result = json.loads(result)

        else:
            return show_alert("Unknown feature selected.")

        analysis_result = info | result
        session['analysis_result'] = analysis_result
        print(str(analysis_result))
        redis_client.cache_result(cache_key, str(analysis_result))
        return jsonify({"redirect": "/report"})

    except Exception as e:
        return show_alert(f"Analysis failed: {str(e)}", 500)


def getSummary(RESULT):
    """Run text to summariz using Docker."""
    try:
        command = [
            "docker", "run", "--rm",
            "-e", f"RESULT={RESULT}",
            "summary"
        ]

        result = subprocess.run(command, capture_output=True, text=True)

        return result.stdout
    except subprocess.SubprocessError as e:
            return {"alert": f"Text analysis failed: {str(e)}"}


def check_email(email):
    """Check email for breaches and return analysis."""
    try:
        breach_list, analysis = check_email_breaches(email)
        if not breach_list:
            return {"message": "No breaches found. You are safe."}
        return {"breaches": breach_list, "analysis": analysis}
    except Exception as e:
        return [], {"alert": "Server is down. Please try again after a few minutes."}


def check_email_breaches(email):
    """Query breach API for email."""
    try:
        response = requests.get(f"{config.XPOSED_API_URL}/check-email/{email}", timeout=config.TIMEOUT)
        if response.status_code == 200:
            response.raise_for_status()
            data = response.json()
            breaches = data.get('breaches', [])
            if not breaches:
                return [], None
            breach_list = breaches[0]
            analysis = get_breach_analysis(email)
            return breach_list, analysis
        else:
            return [], {"alert": "Server is down. Please try again after a few minutes."}
    except requests.RequestException as e:
        return {"alert": "Server is down. Please try again after a few minutes."}


def get_breach_analysis(email):
    """Fetch breach analytics for email."""
    try:
        response = requests.get(f"{config.XPOSED_API_URL}/breach-analytics?email={email}", timeout=config.TIMEOUT)
        response.raise_for_status()
        return response.json()
    except requests.RequestException:
        return {"alert": "Server is down. Please try again after a few minutes."}


def upload_file_to_virustotal(file_path, api_key, base_url):
    """Upload file to VirusTotal for scanning."""
    try:
        url = f"{base_url}/files"
        headers = {"x-apikey": api_key}
        with open(file_path, "rb") as file:
            files = {"file": (os.path.basename(file_path), file)}
            response = requests.post(url, headers=headers, files=files, timeout=config.TIMEOUT)
        response.raise_for_status()
        return response.json()["data"]["id"]
    except (requests.RequestException, IOError) as e:
        raise Exception(f"Error uploading file to VirusTotal: {str(e)}")


def get_analysis_report(file_id, api_key, base_url):
    """Retrieve VirusTotal analysis report."""
    try:
        url = f"{base_url}/analyses/{file_id}"
        headers = {"x-apikey": api_key}
        while True:
            response = requests.get(url, headers=headers, timeout=config.TIMEOUT)
            response.raise_for_status()
            report = response.json()
            if report["data"]["attributes"]["status"] == "completed":
                return report
            time.sleep(10)
    except requests.RequestException as e:
        raise Exception(f"Error fetching analysis report: {str(e)}")


def get_malware(file_path):
    """Analyze file for malware using VirusTotal."""
    try:
        file_id = upload_file_to_virustotal(file_path, config.VIRUSTOTAL_API, config.VIRUSTOTAL_URL)
        if not file_id:
            return {"alert": "Failed to upload file for malware analysis."}
        report = get_analysis_report(file_id, config.VIRUSTOTAL_API, config.VIRUSTOTAL_URL)
        return report
    except Exception as e:
        return {"alert": str(e)}


def submit_url_for_scan(target_url, scan_type="full"):
    """Submit URL for phishing scan."""
    try:
        url = f"{config.BLOSTER_URL}/scan"
        headers = {"Content-Type": "application/json"}
        payload = {
            "apiKey": config.BLOSTER_API_KEY,
            "urlInfo": {"url": target_url},
            "scanType": scan_type
        }
        response = requests.post(url, headers=headers, json=payload, timeout=config.TIMEOUT)
        response.raise_for_status()
        return response.json().get("jobID")
    except requests.RequestException as e:
        raise Exception(f"Failed to submit URL scan: {str(e)}")


def get_scan_status(job_id, insights=True, max_attempts=20, delay=5):
    """Check status of URL scan."""
    try:
        url = f"{config.BLOSTER_URL}/scan/status"
        headers = {"Content-Type": "application/json"}
        payload = {
            "apiKey": config.BLOSTER_API_KEY,
            "jobID": job_id,
            "insights": insights
        }
        for _ in range(max_attempts):
            response = requests.post(url, headers=headers, json=payload, timeout=config.TIMEOUT)
            response.raise_for_status()
            result = response.json()
            if result.get("status") == "DONE":
                return result
            time.sleep(delay)
        raise TimeoutError("Scan did not complete in time.")
    except (requests.RequestException, TimeoutError) as e:
        raise Exception(f"Error fetching scan status: {str(e)}")


def check_phishing_url(target_url):
    """Check if URL is phishing."""
    try:
        job_id = submit_url_for_scan(target_url)
        result = get_scan_status(job_id)
        url_data = result.get("urlData", {})
        return {
            "url": target_url,
            "phishing": url_data.get("phishing", False),
            "threatIndicators": url_data.get("threatIndicators", []),
            "raw": result
        }
    except Exception as e:
        return {"alert": str(e)}


def run_agent(TEXT_INPUT, SELECT):
    """Run text analysis using Docker agent."""
    try:
        command = [
            "docker", "run", "--rm",
            "-e", f"TEXT_INPUT={TEXT_INPUT}",
            "-e", f"SELECT={SELECT}",
            "module-cyber"
        ]
        result = subprocess.run(command, capture_output=True, text=True)
        return result.stdout
    except subprocess.SubprocessError as e:
        return {"alert": f"Text analysis failed: {str(e)}"}


@app.route('/get_prevention_steps')
def get_prevention_steps():
    # get_prevention_steps = session.get('prevention_steps', [])
    if redis_client.get_cached_result('prevention_steps'):
        get_prevention_steps = redis_client.get_cached_result('prevention_steps')
        get_prevention_steps = json.loads(get_prevention_steps)
    return jsonify({"preventionSteps": get_prevention_steps})


@app.route('/chatbot', methods=['POST'])
def chat():
    try:
        data = request.json
        input_text = data.get('inputText')
        reference_text = data.get('preventionSteps', "")
        # report_details = data.get('reportDetails')
        user_id = request.remote_addr
        if not input_text:
            return show_alert("No input text provided.")
        output = chatbot(input_text, reference_text)
        messages = [
            {"sender": "user", "message": user_message},
            {"sender": "assistant", "message": assistant_message}
        ]
        for msg in messages:
            redis_client.store_message(user_id, json.dumps(msg))
        session['chatbot_output'] = output
        return jsonify({"response": markdown.markdown(output)})
    except Exception as e:
        return show_alert(f"Chatbot error: {str(e)}", 500)


@app.route('/get_conversation_history', methods=['GET'])
def get_conversation_history():
    try:
        user_id = request.remote_addr
        conversation_history = redis_client.get_message(user_id)
        if conversation_history is None:
            return jsonify({"conversation": []})
        return jsonify({"conversation": [json.loads(conv) for conv in conversation_history]})
    except Exception as e:
        print(e)
        return show_alert(f"Error fetching conversation history: {str(e)}", 500)

        
def chatbot(input_text, reference_text=""):
    """Interact with chatbot service."""
    try:
        response = requests.post(
            "http://localhost:5000/chat",
            json={"input_text": input_text, "reference_text": reference_text},
            timeout=config.TIMEOUT
        )
        response.raise_for_status()
        return markdown.markdown(re.sub(r'<think>.*?</think>', '', response.json().get("response"), flags=re.DOTALL).strip())
        # return response.json().get("response")
    except requests.RequestException as e:
        raise Exception(f"Chatbot request failed: {str(e)}")


@app.route('/report')
def report():
    return render_template('report_and_mitigation_assistance.html')


@app.route('/get_analysis_result')
def get_analysis_result():
    analysis_result = session.get('analysis_result', {})
    return jsonify(analysis_result)


@app.route('/process_prevention', methods=['POST'])
def process_prevention():
    data = request.json
    cache = session.get('cache_info', [])
    input_text = data.get('reportDetails')
    output = redis_client.get_prevention(request.remote_addr, cache["feature"], cache["inputData"])
    if output:
        prevention_steps = output
    else:
        prevention_steps = prevention.findPrevention(input_text)
        redis_client.store_prevention(request.remote_addr, cache["feature"], cache["inputData"], prevention_steps)
    session['prevention_steps'] = prevention_steps
    prevention_steps = markdown.markdown(re.sub(r'<think>.*?</think>', '', prevention_steps, flags=re.DOTALL).strip())
    return jsonify({"preventionSteps": prevention_steps})


if __name__ == '__main__':
    app.run(debug=True)