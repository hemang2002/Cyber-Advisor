
const elements = {
    dropZone: document.getElementById('dropZone'),
    fileInput: document.getElementById('fileInputField'),
    analyzeBtn: document.getElementById('analyze-btn'),
    inputSection: document.getElementById('input-section'),
    textField: document.getElementById('textField'),
    charCount: document.getElementById('charCount'),
    breachField: document.getElementById('breachField'),
    breachCharCount: document.getElementById('breachCharCount'),
    removeFileBtn: document.getElementById('removeFileBtn'),
    uploadedFileName: document.getElementById('uploadedFileName'),
    uploadedFileInfo: document.getElementById('uploadedFileInfo'),
    loadingSpinner: document.getElementById('loading-spinner')
};

function switchTab(tab) {
    document.querySelectorAll('.input-section').forEach(section => section.classList.add('hidden'));
    document.getElementById(`${tab}Input`).classList.remove('hidden');
    document.querySelectorAll('#fileTab, #urlTab, #ipTab, #textTab, #breachTab').forEach(btn => {
        btn.classList.remove('bg-secondary', 'text-gray-900');
        btn.classList.add('bg-gray-800', 'text-gray-400');
    });
    document.getElementById(`${tab}Tab`).classList.remove('bg-gray-800', 'text-gray-400');
    document.getElementById(`${tab}Tab`).classList.add('bg-secondary', 'text-gray-900');
}

function setDefaultSelectOption(selectId, value) {
    const select = document.getElementById(selectId);
    if (select) select.value = value;
}

function showSection(sectionId) {
    document.querySelectorAll('main > section').forEach(section => {
        section.classList.add('hidden');
    });
    const targetSection = document.getElementById(sectionId);
    if (targetSection) {
        targetSection.classList.remove('hidden');
        document.querySelectorAll('.nav-link').forEach(link => {
            link.classList.remove('text-secondary');
            if (link.dataset.section === sectionId) {
                link.classList.add('text-secondary');
            }
        });
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }
}

function showInputSection() {
    elements.inputSection.classList.remove('hidden');
    elements.inputSection.scrollIntoView({ behavior: 'smooth' });
}

function selectService(service) {
    showInputSection();
    switch (service) {
        case 'malware':
            switchTab('file');
            setDefaultSelectOption('FileType', 'Malware');
            break;
        case 'deepFake':
            switchTab('file');
            setDefaultSelectOption('FileType', 'Deep Fake');
            break;
        case 'url':
            switchTab('url');
            break;
        // case 'ip':
        //     switchTab('ip');
        //     break;
        case 'sentiment':
            switchTab('text');
            setDefaultSelectOption('textAnalysisType', 'Sentiment Analysis');
            break;
        case 'fake-news':
            switchTab('text');
            setDefaultSelectOption('textAnalysisType', 'Fake News Detection');
            break;
        case 'breach':
            switchTab('breach');
            break;
    }
}

function updateCharCount() {
    elements.charCount.textContent = `${elements.textField.value.length}/1000 characters`;
}

function updateBreachCharCount() {
    elements.breachCharCount.textContent = `${elements.breachField.value.length}/50 characters`;
}

function isValidURL(url) {
    return /^(https?:\/\/)?([\w-]+\.)+[\w-]+(\/[\w- .\/?%&=]*)?$/.test(url);
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// function isValidIP(ip) {
//     const pattern = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
//     return pattern.test(ip);
// }

async function handleFiles(files) {
    if (!files.length) return;
    const formData = new FormData();
    formData.append('files', files[0]);
    try {
        const response = await fetch('/upload', {
            method: 'POST',
            body: formData });
        const result = await response.json();
        if (result.alert) {
            alert(result.alert);
            return;
        }
        elements.uploadedFileName.textContent = result.filename;
        elements.uploadedFileInfo.classList.remove('hidden');
    } catch (error) {
        alert('Failed to upload file.');
    }
}

document.addEventListener('DOMContentLoaded', () => {
    showSection('home');
    switchTab('file');
    document.querySelectorAll('.nav-link').forEach(link => {
        link.addEventListener('click', e => {
            e.preventDefault();
            showSection(link.dataset.section);
        });
    });

    // Add event listeners for Enter key press
    document.getElementById('urlField').addEventListener('keydown', handleEnterKey);
    // document.getElementById('ipField').addEventListener('keydown', handleEnterKey);
    document.getElementById('textField').addEventListener('keydown', handleEnterKey);
    document.getElementById('breachField').addEventListener('keydown', handleEnterKey);
});

elements.dropZone.addEventListener('dragover', e => {
    e.preventDefault();
    elements.dropZone.classList.add('drag-over');
});

elements.dropZone.addEventListener('dragleave', () => {
    elements.dropZone.classList.remove('drag-over');
});

elements.dropZone.addEventListener('drop', e => {
    e.preventDefault();
    elements.dropZone.classList.remove('drag-over');
    handleFiles(e.dataTransfer.files);
});

elements.dropZone.addEventListener('click', () => elements.fileInput.click());

elements.fileInput.addEventListener('change', e => handleFiles(e.target.files));

elements.removeFileBtn.addEventListener('click', () => {
    elements.fileInput.value = '';
    elements.uploadedFileInfo.classList.add('hidden');
    elements.uploadedFileName.textContent = '';
});

async function analyzebtnFun() {
    elements.loadingSpinner.classList.remove('hidden');
    elements.analyzeBtn.disabled = true;
    const activeTab = document.querySelector('.input-section:not(.hidden)').id;
    let feature, inputData, subcategories;

    try {
        switch (activeTab) {
            case 'fileInput':
                feature = 'File Analysis';
                inputData = elements.uploadedFileName.textContent;
                subcategories = document.getElementById('FileType').value;
                if (!inputData) throw new Error('Please upload a file.');
                break;
            case 'urlInput':
                feature = 'URL Check';
                inputData = document.getElementById('urlField').value;
                // subcategories = document.getElementById('phishingCheck').value;
                if (!isValidURL(inputData)) throw new Error('Please enter a valid URL.');
                break;
            // case 'ipInput':
            //     feature = 'IP Lookup';
            //     inputData = document.getElementById('ipField').value;
            //     subcategories = document.getElementById('ipField').value;
            //     if (!isValidIP(inputData)) throw new Error('Please enter a valid IP address.');
            //     break;
            case 'textInput':
                feature = 'Text Analysis';
                inputData = elements.textField.value;
                subcategories = document.getElementById('textAnalysisType').value;
                if (!inputData.trim()) throw new Error('Please enter text for analysis.');
                break;
            case 'breachInput':
                feature = 'Breach Analysis';
                inputData = elements.breachField.value;
                if (!inputData.trim()) throw new Error('Please enter an email address.');
                if (!isValidEmail(inputData)) throw new Error('Please enter a valid email address.');
                break;
            default:
                throw new Error('Please select an input type.');
        }
        const response = await fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ feature, inputData, subcategories })
        });
        const result = await response.json();
        if (result.alert) {
            alert(result.alert);
            return;
        }
        if (result.redirect) window.location.href = result.redirect;
    } catch (error) {
        alert(error.message);
    } finally {
        elements.loadingSpinner.classList.add('hidden');
        elements.analyzeBtn.disabled = false;
    }
}

function handleEnterKey(event) {
    if (event.key === 'Enter') {
        event.preventDefault();
        analyzebtnFun();
    }
}

elements.analyzeBtn.addEventListener('click', analyzebtnFun);