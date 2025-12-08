/**
 * Notification system for SecureChat
 * Displays notifications and handles URL parameters for incoming messages
 */

/**
 * Show notification modal
 * @param {string} messageTxHash - Transaction hash of the message
 */
export function showNotificationModal(messageTxHash) {
    const modal = document.getElementById('notification-modal');
    const viewBtn = document.getElementById('view-message-btn');
    
    if (!modal) return;
    
    modal.classList.remove('hidden');
    
    // Set up view button to scroll to messages
    viewBtn.onclick = () => {
        hideNotificationModal();
        scrollToMessages();
        // Optionally highlight the specific message
        if (messageTxHash) {
            highlightMessage(messageTxHash);
        }
    };
}

/**
 * Hide notification modal
 */
export function hideNotificationModal() {
    const modal = document.getElementById('notification-modal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

/**
 * Scroll to messages section
 */
function scrollToMessages() {
    const messagesSection = document.getElementById('messages-container');
    if (messagesSection) {
        messagesSection.scrollIntoView({ behavior: 'smooth' });
    }
}

/**
 * Highlight a specific message by transaction hash
 * @param {string} txHash - Transaction hash
 */
function highlightMessage(txHash) {
    setTimeout(() => {
        const messageElement = document.querySelector(`[data-tx-hash="${txHash}"]`);
        if (messageElement) {
            messageElement.style.animation = 'highlight 2s ease';
            messageElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
    }, 500);
}

/**
 * Check URL parameters for incoming message notification
 * Looks for ?msg=<txHash> parameter
 */
export function checkUrlForMessage() {
    const urlParams = new URLSearchParams(window.location.search);
    const msgTxHash = urlParams.get('msg');
    
    if (msgTxHash) {
        // Show notification after a brief delay
        setTimeout(() => {
            showNotificationModal(msgTxHash);
        }, 1000);
        
        // Clean up URL (optional - removes the parameter)
        const cleanUrl = window.location.pathname;
        window.history.replaceState({}, document.title, cleanUrl);
    }
}

/**
 * Create a shareable notification link
 * @param {string} messageTxHash - Transaction hash of the message
 * @returns {string} Full URL with message parameter
 */
export function createNotificationLink(messageTxHash) {
    const baseUrl = window.location.origin + window.location.pathname;
    return `${baseUrl}?msg=${messageTxHash}`;
}

/**
 * Display a toast notification
 * @param {string} message - Notification message
 * @param {string} type - Type: 'success', 'error', 'info'
 * @param {number} duration - Duration in milliseconds
 */
export function showToast(message, type = 'info', duration = 3000) {
    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    
    // Add styles
    toast.style.cssText = `
        position: fixed;
        bottom: 20px;
        right: 20px;
        background: ${type === 'success' ? '#4caf50' : type === 'error' ? '#f44336' : '#2196f3'};
        color: white;
        padding: 16px 24px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        z-index: 10000;
        animation: slideInRight 0.3s ease;
        max-width: 400px;
    `;
    
    document.body.appendChild(toast);
    
    // Auto-remove after duration
    setTimeout(() => {
        toast.style.animation = 'slideOutRight 0.3s ease';
        setTimeout(() => {
            document.body.removeChild(toast);
        }, 300);
    }, duration);
}

/**
 * Create notification icon badge for UI
 * @param {number} count - Number of unread messages
 * @returns {string} HTML string for badge
 */
export function createNotificationBadge(count) {
    if (count === 0) return '';
    
    return `
        <span class="notification-badge" style="
            position: absolute;
            top: -8px;
            right: -8px;
            background: #f44336;
            color: white;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 12px;
            font-weight: bold;
        ">${count > 9 ? '9+' : count}</span>
    `;
}

/**
 * Add notification styles to document
 */
export function initNotificationStyles() {
    if (document.getElementById('notification-styles')) return;
    
    const style = document.createElement('style');
    style.id = 'notification-styles';
    style.textContent = `
        @keyframes highlight {
            0%, 100% { background-color: inherit; }
            50% { background-color: #fff3cd; }
        }
        
        @keyframes slideInRight {
            from {
                transform: translateX(400px);
                opacity: 0;
            }
            to {
                transform: translateX(0);
                opacity: 1;
            }
        }
        
        @keyframes slideOutRight {
            from {
                transform: translateX(0);
                opacity: 1;
            }
            to {
                transform: translateX(400px);
                opacity: 0;
            }
        }
    `;
    
    document.head.appendChild(style);
}

/**
 * Send browser notification (requires permission)
 * @param {string} title - Notification title
 * @param {string} body - Notification body
 * @param {string} icon - Icon URL or emoji
 */
export async function sendBrowserNotification(title, body, icon = '📬') {
    if (!('Notification' in window)) {
        console.log('This browser does not support notifications');
        return;
    }

    let permission = Notification.permission;

    if (permission === 'default') {
        permission = await Notification.requestPermission();
    }

    if (permission === 'granted') {
        new Notification(title, {
            body: body,
            icon: icon,
            badge: icon,
            tag: 'secrechat-message',
            requireInteraction: false
        });
    }
}

// Initialize notification system
initNotificationStyles();
