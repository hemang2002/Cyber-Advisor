function updateTime() {
    const now = new Date();
    document.getElementById('currentTime').textContent = now.toLocaleTimeString();
}
setInterval(updateTime, 1000);
updateTime();

function formatKeyAsLabel(key) {
    return key
        .replace(/([A-Z])/g, ' $1')
        .replace(/_/g, ' ')
        .split(' ')
        .map(word => word.charAt(0).toUpperCase() + word.slice(1).toLowerCase())
        .join(' ');
}

function createReportDetails(analysisResult) {
    const container = document.getElementById('reportDetails');
    container.innerHTML = '';
    const gridDiv = document.createElement('div');
    gridDiv.className = 'grid grid-cols-2 gap-4';

    const details = Object.keys(analysisResult)
        .filter(key => !['summary'].includes(key))
        .map(key => ({
            label: formatKeyAsLabel(key),
            value: analysisResult[key] ?? 'N/A'
        }));

    details.forEach(detail => {
        const div = document.createElement('div');
        div.innerHTML = `
            <h3 class="text-gray-400 mb-1">${detail.label}</h3>
            <p>${detail.value}</p>
        `;
        gridDiv.appendChild(div);
    });
    container.appendChild(gridDiv);

    if (analysisResult.summary) {
        const descDiv = document.createElement('div');
        descDiv.innerHTML = `
            <h3 class="text-gray-400 mb-2">Description</h3>
            <p class="text-gray-300">${analysisResult.summary}</p>
        `;
        container.appendChild(descDiv);
    }
}

function updateSeverityIndicator(severity) {
    const indicator = document.getElementById('severityIndicator');
    const border = indicator.querySelector('.animate-pulse');
    const text = indicator.querySelector('span');
    let color = '';
    switch (severity.toLowerCase()) {
        case 'high':
            color = 'red-500';
            break;
        case 'medium':
            color = 'yellow-500';
            break;
        case 'low':
            color = 'green-500';
            break;
        default:
            color = 'gray-500';
    }
    border.className = `absolute inset-0 rounded-full border-4 border-${color} animate-pulse`;
    text.className = `text-3xl font-bold text-${color}`;
    text.textContent = severity || 'N/A';
}

let analysisResult = {};
let preventionStepsText = "";

document.addEventListener('DOMContentLoaded', () => {
    fetch('/get_analysis_result')
        .then(response => response.json())
        .then(data => {
            if (data && Object.keys(data).length > 0) {
                analysisResult = data;
                createReportDetails(analysisResult);
                updateSeverityIndicator(analysisResult.severity || 'Low');
                if (analysisResult.prevention_required.toLowerCase() === 'yes') {
                    document.getElementById('preventionBtn').disabled = false;
                } else {
                    document.getElementById('preventionBtn').disabled = true;
                }
            } else {
                document.getElementById('reportDetails').innerHTML = '<p>No analysis data available.</p>';
            }
        })
        .catch(error => {
            console.error('Error fetching analysis result:', error);
            document.getElementById('reportDetails').innerHTML = '<p>Error loading analysis data.</p>';
        });
});

const preventionBtn = document.getElementById('preventionBtn');
const preventionSteps = document.getElementById('preventionSteps');
const preventionText = document.getElementById('preventionText');

preventionBtn.addEventListener('click', async () => {
    const spinner = document.createElement('div');
    spinner.className = 'spinner';
    preventionBtn.disabled = true;
    preventionBtn.innerHTML = '';
    preventionBtn.appendChild(spinner);
    try {
        const response = await fetch('/process_prevention', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ reportDetails: analysisResult.summary })
        });
        const result = await response.json();
        preventionText.innerHTML = marked.parse(result.preventionSteps);
        preventionStepsText = result.preventionSteps;
        preventionSteps.classList.remove('hidden');
    } catch (error) {
        console.error('Error processing prevention steps:', error);
        alert('An error occurred while processing prevention steps. Please try again later.');
    } finally {
        preventionBtn.disabled = analysisResult.prevention_required?.toLowerCase() !== 'yes';
        preventionBtn.innerHTML = `
            <i class="ri-shield-line mr-2"></i>
            View Prevention Steps
        `;
    }
});

const askAssistantBtn = document.getElementById('askAssistantBtn');
const chatContainer = document.getElementById('chatContainer');
const closeChat = document.getElementById('closeChat');
const messageInput = document.getElementById('messageInput');
const sendMessage = document.getElementById('sendMessage');
const chatMessages = document.getElementById('chatMessages');
const chatbotBtn = document.getElementById('chatbotBtn');

function addLoadingIndicator() {
    const loadingDiv = document.createElement('div');
    loadingDiv.id = 'loadingIndicator';
    loadingDiv.classList.add('message', 'assistant-message');
    loadingDiv.innerHTML = `
        <div class="flex items-center space-x-2">
            <span class="text-gray-300">Analyzing</span>
            <div class="flex space-x-1">
                <div class="w-2 h-2 bg-blue-500 rounded-full animate-bounce" style="animation-delay: 0s;"></div>
                <div class="w-2 h-2 bg-blue-500 rounded-full animate-bounce" style="animation-delay: 0.2s;"></div>
                <div class="w-2 h-2 bg-blue-500 rounded-full animate-bounce" style="animation-delay: 0.4s;"></div>
            </div>
        </div>
    `;
    chatMessages.appendChild(loadingDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
    return loadingDiv;
}

function removeLoadingIndicator() {
    const loadingDiv = document.getElementById('loadingIndicator');
    if (loadingDiv) {
        loadingDiv.remove();
    }
}

async function loadConversationHistory() {
    try {
        chatMessages.innerHTML = ''; // Clear existing messages
        const response = await fetch('/get_conversation_history', {
            method: 'GET',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        const result = await response.json();
        if (result.conversation && Array.isArray(result.conversation)) {
            result.conversation.forEach(({ sender, message }) => {
                if (message) { // Ensure message is not empty
                    addMessage(message, sender.toLowerCase());
                }
            });
        }
    } catch (error) {
        console.error('Error loading conversation history:', error);
        addMessage('Failed to load conversation history.', 'assistant');
    }
}

async function sendChatbotRequest(userMessage) {
    if (userMessage) {
        addMessage(userMessage, 'user');
        messageInput.value = '';
        const loadingIndicator = addLoadingIndicator();
        try {
            const response = await fetch('/chatbot', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    inputText: userMessage,
                    reportDetails: analysisResult.summary,
                    preventionSteps: preventionStepsText
                })
            });
            const result = await response.json();
            removeLoadingIndicator();
            if (result.alert) {
                addMessage(result.alert, 'assistant');
            } else {
                addMessage(result.response, 'assistant');
            }
        } catch (error) {
            console.error('Error communicating with chatbot:', error);
            removeLoadingIndicator();
            addMessage('Sorry, I encountered an error. Please try again later.', 'assistant');
        }
    }
}

function addMessage(text, type) {
    const messageDiv = document.createElement('div');
    messageDiv.classList.add('message', `${type}-message`);
    if (type === 'assistant') {
        messageDiv.innerHTML = marked.parse(text);
    } else {
        messageDiv.textContent = text;
    }
    chatMessages.appendChild(messageDiv);
    chatMessages.scrollTop = chatMessages.scrollHeight;
}

askAssistantBtn.addEventListener('click', () => {
    chatContainer.style.display = 'block';
    loadConversationHistory();
});

chatbotBtn.addEventListener('click', () => {
    chatContainer.style.display = 'block';
    loadConversationHistory();
});

closeChat.addEventListener('click', () => {
    chatContainer.style.display = 'none';
});

sendMessage.addEventListener('click', () => {
    const userMessage = messageInput.value.trim();
    sendChatbotRequest(userMessage);
});

messageInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') {
        const userMessage = messageInput.value.trim();
        sendChatbotRequest(userMessage);
    }
});