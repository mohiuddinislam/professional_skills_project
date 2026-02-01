/**
 * Progress Tracking Module
 * Handles Server-Sent Events (SSE) connection for real-time progress updates
 */

let currentEventSource = null;

/**
 * Connect to SSE endpoint for progress updates
 * @param {string} sessionId - Unique session identifier
 * @param {string} inputText - Original input text
 * @param {boolean} useCache - Whether caching was enabled
 */
function connectProgressStream(sessionId, inputText, useCache) {
    const submitBtn = document.getElementById('submitBtn');
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    const errorMsg = document.getElementById('errorMsg');
    const progressMessage = document.getElementById('progressMessage');
    
    // Close existing connection if any
    if (currentEventSource) {
        currentEventSource.close();
    }
    
    // Connect to SSE endpoint
    currentEventSource = new EventSource(`/progress/${sessionId}`);
    
    currentEventSource.onmessage = (event) => {
        try {
            const progressData = JSON.parse(event.data);
            
            console.log('Progress update:', progressData);
            
            // Update progress UI
            updateProgressUI(progressData);
            
            // Handle completion
            if (progressData.stage === 'complete') {
                currentEventSource.close();
                progressMessage.textContent = 'Assessment complete! Loading results...';
                
                // Fetch the actual result from result endpoint
                fetchCompletedResult(sessionId);
            }
            
            // Handle error
            if (progressData.stage === 'error') {
                currentEventSource.close();
                errorMsg.innerHTML = `<div class="error">❌ ${progressData.details}</div>`;
                loading.classList.remove('active');
                submitBtn.disabled = false;
            }
            
        } catch (error) {
            console.error('Error parsing progress data:', error);
        }
    };
    
    currentEventSource.onerror = (error) => {
        console.error('EventSource error:', error);
        currentEventSource.close();
        
        // Still try to fetch result in case it completed
        setTimeout(() => fetchCompletedResult(sessionId), 1000);
    };
}

/**
 * Update the progress UI based on received progress data
 * @param {Object} progressData - Progress data from server
 */
function updateProgressUI(progressData) {
    const stage = progressData.stage;
    const status = progressData.status;
    const details = progressData.details;
    
    const progressMessage = document.getElementById('progressMessage');
    
    // Update main progress message
    if (details) {
        progressMessage.textContent = details;
    }
    
    // Update stage-specific UI
    const stageElement = document.querySelector(`[data-stage="${stage}"]`);
    if (stageElement) {
        const statusElement = stageElement.querySelector('.progress-status');
        const iconElement = stageElement.querySelector('.progress-icon');
        
        // Update status text and styling
        statusElement.textContent = status;
        stageElement.className = `progress-stage ${status}`;
        
        // Update icon based on status
        if (status === 'completed') {
            iconElement.textContent = '✅';
        } else if (status === 'in_progress') {
            iconElement.textContent = '⏳';
        } else if (status === 'failed') {
            iconElement.textContent = '❌';
        }
    }
}

/**
 * Fetch the completed assessment result
 * @param {string} sessionId - Session identifier
 */
async function fetchCompletedResult(sessionId) {
    const submitBtn = document.getElementById('submitBtn');
    const loading = document.getElementById('loading');
    const results = document.getElementById('results');
    const errorMsg = document.getElementById('errorMsg');
    
    try {
        // Fetch from result endpoint
        const response = await fetch(`/result/${sessionId}`);
        
        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Failed to fetch results');
        }
        
        if (data.success && data.assessment) {
            displayAssessment(data.assessment);
            results.style.display = 'block';
        }
        
    } catch (error) {
        errorMsg.innerHTML = `<div class="error">❌ ${error.message}</div>`;
    } finally {
        loading.classList.remove('active');
        submitBtn.disabled = false;
    }
}
